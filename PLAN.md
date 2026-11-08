# pkgvuln

Goal: turn version snapshots of the installed Nix packages into actionable
findings — which installed packages are affected by which advisories, what
changed since the last snapshot, and what was fixed by an update.

`pkgvuln snapshot` records the snapshots, and the rest of the package owns
advisory ingestion, matching and reporting in the **same** SQLite database.

    pkgvuln --help
    python3 -m unittest pkgvuln.test_pkgvuln     # no network needed

## Measured starting point

From the live system (1,274 closure paths → 1,095 unique derivations):

| class | count | matchable by |
|---|---|---|
| plain C/C++/CLI (`curl-8.22.0`) | 1,013 | NVD/CPE |
| perl (`perl5.40-*`) | 52 | nothing useful (no CPAN feed) |
| python (`python3.14-mako-1.4.1`) | 10 | OSV / PyPI |
| other | 20 | — |

## The finding that changed the plan

The original plan started with "borrow vulnix's NVD/CPE matching" (steps 5, 6).
That does not work on this machine, and the failure mode is dangerous:

* **479 of 1,095 `.drv` files have been garbage collected** (measured:
  602 present). vulnix parses `.drv` files, so it can only see 55% of the
  system, and it skips the rest **silently** — a skipped package is
  indistinguishable from a clean one.
* Verified: `vulnix --json --no-requisites <output path>` returns `[]` for
  packages with a collected derivation, exit code 0.
* Dropping `--no-requisites` "fixes" the empty output but changes the
  semantics: vulnix then scans the *build* closure of each deriver and reports
  build-time-only inputs (e.g. binutils for everything).

So NVD/CPE matching was moved to the front and implemented directly, using only
the name+version that the snapshot already recorded (no derivations
needed → 100% coverage). vulnix survives as an **opt-in diagnostic** source that
reports how much it could actually see.

## Constraints that shaped the design

- **Stdlib only.** The package runs under a bare Python; no `withPackages`.
  `urllib`, `gzip`, `json`, `sqlite3`, `tomllib` suffice.
- **Same DB, additive tables.** Existing snapshot databases keep working.
- **No `nixpkgs` OSV ecosystem** — verified `{"code":3,"message":"invalid
  ecosystem"}`. The Nix↔OSV namespace translation in `names.py` is mandatory.
- **`meta.identifiers` is nearly empty** (121 files in the pinned nixpkgs;
  `product` is just `toLower pname`). Not a usable CPE map.
- **Standard Python packaging**: `pkgvuln` is installable from `pyproject.toml`
  and the flake exposes it as a package.

## Steps

`- [x]` = done, with the accepting test noted.

### Phase 1 — end-to-end (done)

- [x] **1. Package skeleton.** `python3 -m pkgvuln --help`; `python3 -m
  unittest pkgvuln.test_pkgvuln`.
- [x] **2. Schema (`db.py`).** `advisories`, `affected`, `matches`,
  `osv_queries`, `feeds`, `vuln_meta`, all `IF NOT EXISTS`, plus a forward
  migration for `feeds.payload`. Test: snapshot tables coexist.
- [x] **3. Version semantics (`nixver.py`).** Port of Nix's
  `nextComponent`/`componentsLT` (`src/libstore/names.cc`), a dotted-numeric
  fast path with trailing-zero equality (`153.0` ≡ `153.0.0`), and
  `upstream_version()` which strips `-r3` revisions and output suffixes and
  rejects `unstable-*`. Test: 15 pairs checked against
  `nix eval builtins.compareVersions`.
- [x] **4. Namespace mapping (`names.py`).** `python3.X-*` → PyPI (PEP 503
  canonical), nothing else — deliberately conservative. Test: real names from
  the live snapshot; `python3-3.15.0_fish-completions` maps to nothing.
- [x] **5. NVD ingester (`sources/nvd.py`).** `nvdcve-2.0-{modified,YYYY}.json.gz`
  with ETag revalidation, CPE 2.3 parsing, `vulnerable: true` only, ranges and
  exact versions, CVSS v2/v3/v4. Verified: 2026 archive → 86,383 advisories /
  88,324 affected rows in 40 s.
- [x] **6. CPE matcher (`match.py`).** Product candidates (literal, then
  underscored) against `affected.product`, exact-version comparison with
  trailing-zero tolerance, then range evaluation. 1,095 packages in 0.37 s
  against 88k rows. Ignores vendor (accepts false positives, like vulnix);
  documented in the module.
- [x] **7. OSV (`sources/osv.py`).** `POST /v1/querybatch` (1000 per call,
  aligned results, `{}` for a miss), cached per `(ecosystem, package, version)`
  for 7 days, then `GET /v1/vulns/<id>` for summary/severity/aliases. Verified
  live: 4 matches on this snapshot; aliases make the KEV/EPSS joins work.
- [x] **8. Enrichment (`sources/kev.py`, `sources/epss.py`).** KEV and EPSS,
  joined by id *and* alias. A 304 re-applies the cached payload, because new
  advisories appear between feed updates (that is why `feeds.payload` exists).
- [x] **9. Report (`report.py`).** `initial` / `introduced` / `carried` /
  `fixed` classification, priority ordering (KEV > EPSS ≥ 0.1 > CVSS ≥ 7 >
  severity), duplicate identifiers collapsed to one bug by CVE alias, text and
  JSON output. Exit codes 0 / 2 / 3 (see 11b).
- [x] **10. Whitelist (TOML).** `~/.config/pkgvuln/whitelist.toml`, sections
  `["pkg-version"]`, `["pkg"]`, `["*"]`, keys `cve`, `until`, `issue_url`,
  `comment`. A `cve` list stops masking as soon as a new CVE appears; `until`
  expires the rule on the given date.
- [x] **11. CLI + units.** `sync | scan | report | run`; `run` = scan → sync →
  report (order matters: enrichment applies to advisories that already exist).
  `configuration.nix`: a weekly user service separate from the snapshot unit, so
  the network stage cannot fail the snapshot unit.

### Phase 2 — improve the matcher (next)

- [x] **12. Coverage reporting for vulnix** — `--vulnix` prints
  `covered 602/1095 derivations; 479 have no .drv left`.
- [x] **13. Curated product/vendor overrides** — `pkgvuln/overrides.toml`,
  loaded by `pkgvuln/overrides.py`, tried before the name heuristic. Two kinds
  of entry, both evidence-based from the stored CPE data:
  recall (`python3`→`python`, `nodejs`→`node.js`, `libtheora`→`theora`) and
  precision (vendor allow-lists: `git` excludes `jenkins`, `zlib` excludes
  `ruby-lang`, `orc` excludes `apache`, `snappy` excludes `knplabs`, …).
  Measured on this snapshot: 13 false positives removed, and the `nodejs` alias
  found a real one — Node 24 bundles brotli 1.2.0 and is inside the same
  CVE-2026-111497 range. Blanket rules were checked and rejected: stripping
  `lib` would map `libzip`→Info-ZIP `zip`, `libcamera`→Android's camera app,
  `libcbor`→a .NET library.
- [x] **13b. Whitelist non-findings** — a whitelist passed with `-w`, version-pinned
  so entries expire by themselves on upgrade. Covers the false positives that
  no vendor constraint can express: NVD range data that contradicts its own
  prose (perl 5.42.3 is the fixed version), date-as-version CPE bounds,
  Windows-only advisories, a mislabelled record (`game-music-emu`), a
  Debian-packaging CVE and a `dbus-1` version-string artefact.
- [x] **14. Vendor-aware matching.** Applied for packages with a curated
  vendor list; unconstrained packages still match on product alone (a wrong
  vendor is cheaper than a missed finding when we have no data to judge).
- [ ] **15. Patch-name suppression** (only possible for the 602 derivations
  whose `.drv` survives): one `nix derivation show` for all paths → `env.patches`
  → a `CVE-\d{4}-\d+` filename means "backported, do not report".
- [ ] **16. Recover derivations.** `nix-store --realise` the `.drv` paths of the
  snapshot before scanning, so vulnix/patch detection can see the whole system.
  Only worth it if 13–15 show the drv content is needed.

### Phase 3 — more ecosystems, only if they earn their keep

- [ ] **17. npm/crates.io/Go mapping** behind the same `names.py` interface,
  plus a user-supplied `--ecosystem-map`. Not default: bare `pname` → npm name
  guesses are false-positive factories.
- [ ] **18. OSV `GIT` mode** for `unstable-*` packages (map `src` rev → commit
  ranges). The only path to advisories for projects that never cut releases.
- [x] **19. Fold the snapshotter into the package.** `pkgvuln/snapshot.py`
  owns root discovery and schema, and `pkgvuln snapshot` is the command.

### Phase 4 — version drift

- [x] **20. Outdated detection (`outdated.py`).** `nix-env -qa --json` per pin,
  cached in `nixpkgs_pins`/`nixpkgs_attrs` (104 900 attributes, ~75 s, 26 MB on
  this machine), compared against `pkgs.<pname>` with `nixver.compare` after
  `nixver.strip_variants()` removes derivation-variant markers. Two refinements
  were needed before the numbers meant anything, both measured on the live
  database:

  * `strip_variants` took "newer than the pin" from 46 rows to 6
    (`9.12_fish-completions`, `5.42.3-env`, `1.2.4-zstd` are the same release);
  * `same_version_attr` took "outdated" from 5 rows to 0. All five were version
    lines nixpkgs keeps on purpose (`boost189`, `db4`, `lua5_4_compat`,
    `webrtc-audio-processing_1`) or the `makeDBusConf` name split. An
    exact-version sibling means "you are on that line", not "you never
    upgraded": `openssl_1_1` next to `openssl` is the explicit statement.

  Layer 2 (`--verify-store-paths`) then only answers "was this path built by
  this pin at all": a hit sets `in_pin`, a miss is real drift (a package from
  an older `nix profile`, another flake input, or an attribute that was removed
  or renamed). What remains on this machine is one deliberate `ahead` row:
  `boot.kernelPackages = pkgs.linuxPackages_latest` (7.3.1) is newer than the
  default `pkgs.linux` (6.18.60), and the `-modules` derivation lives in nested
  `linuxKernel` attributes that layer 1 does not look at.

  Two things were learned the hard way and are encoded in the module:
  `nix-env`'s filter is matched against the **pname**, not the attribute path
  (one expression selects every version line of a package), and the filter is a
  *command line argument*, so a `^(a|b|...)$` for 1000 names dies with `E2BIG`
  (hence `BATCH = 200`). `re.escape` cannot build the filter either: it escapes
  `-` as `\-`, which nix rejects with "Invalid escape in regular expression"
  after a full evaluation.

  Runs as the last section of `pkgvuln run` (before the advisory report, which
  keeps the exit code), so the daily unit reports drift without a second unit
  or timer. `--no-outdated` skips it; a failed evaluation is a warning, never a
  failed scan. The unit passes `--nixpkgs ${pkgs.path}`, which adds the nixpkgs
  source (~490 MB) to the system closure, the same cost as
  `nixpkgs.flake.setNixPath`.

  The result is stored in `outdated_summary` (one row per snapshot) so
  `pkgvuln report --json` can carry it to the Noctalia widget: the widget runs
  `report` every minute and must stay a database read. The bar widget shows the
  advisory count normally and the outdated count when there are no findings,
  the tooltip names both, and the panel lists the outdated rows. A summary for
  an older snapshot is not reused, because the installed versions have changed
  since.

## Layout

    PLAN.md                  this file
    README.md                usage
    flake.nix  pyproject.toml
    pkgvuln/
      __init__.py  __main__.py  cli.py
      snapshot.py  installed versions -> snapshots/packages tables
      db.py        schema, connection, advisory/match writers
      fetch.py     urllib wrapper: retries, ETag, gzip
      nixver.py    Nix version comparison, upstream_version(), in_range(),
                   strip_variants() for derivation-variant markers
      names.py     pname -> (ecosystem, package, version)
      match.py     CPE/product matching against `affected`
      outdated.py  installed versions vs the nixpkgs pin (two layers)
      report.py    delta classification, whitelist, text/JSON
      overrides.py overrides.toml  curated pname -> NVD vendor/product facts
      sources/
        nvd.py     NVD JSON 2.0 feeds -> advisories + affected
        osv.py     OSV querybatch + vuln details
        vulnix.py  optional ingest of `vulnix --json` (partial coverage)
        kev.py     CISA KEV catalogue
        epss.py    FIRST EPSS scores
        feeds.py   ETag + cached-payload fetch helper
      test_pkgvuln.py

## Usage

    # once, then daily
    pkgvuln snapshot                                   # record installed versions
    pkgvuln run --nvd                                  # sync + scan + report + drift

    # useful individual commands
    pkgvuln sync --nvd --archives 2026                 # one NVD archive only
    pkgvuln scan --no-osv                              # NVD/CPE only
    pkgvuln report --json | jq '.current'
    pkgvuln report -s                                  # list whitelisted too
    pkgvuln scan --offline                             # cached OSV answers only

    # version drift: what has a newer version in nixpkgs?
    pkgvuln outdated                                   # flake in $PWD, or --nixpkgs PATH
    pkgvuln outdated --verify-store-paths              # drop alternate version lines
    pkgvuln outdated --json | jq '.outdated'
    pkgvuln run --no-outdated                          # scan only, no drift section

`NVD` sync downloads ~25–45 MB per archive (~200 MB gz for the default 6-year
window) and keeps only product/version/range data, so the database grows by
roughly 1 GB. Expect ~40 s per archive on first run and 304s afterwards.

## Known limitations

- **Vendor is ignored** in CPE matching → false positives for ambiguous product
  names. Step 14.
- **Build-vs-runtime closure**: matching uses the recorded runtime closure,
  which is what is actually installed; build-time inputs are correctly excluded.
- **`unstable-*` packages are unmatchable** by CPE or OSV release ranges. They
  are counted, not guessed at. Step 18.
- **NVD's enrichment backlog** means many recent CVEs have no CPE data and
  cannot match — nothing a client-side matcher can fix.
- **Only the first product candidate with a hit is used** (vulnix's rule), so a
  package matching two NVD products is under-reported.
- **`pname` is not an attribute path** (`gtk+3` is `pkgs.gtk3`, `gssdp` is
  `gssdp_1_6`, `db4` has pname `db`), so `outdated` cannot map 453 of 1108 rows
  by name; those are closure entries that are not packages (`X-Restart-Triggers-*`,
  `unit-*`, `etc-*`) or names with several or no top-level attributes. The
  store-path check resolves the ones that matter (the candidates).
- **Never trust "0 matches" without checking that `affected` is populated**:
  an empty advisory table reports zero findings. `match.scan` says so explicitly,
  and `run` syncs NVD *before* scanning for exactly this reason.
- The DB is written by a *user* service, so `nix-store --gc --print-live`-style
  root discovery is unavailable; roots come from `/run/current-system` and the
  user profiles.
## Phase 3 - Surface the findings (Noctalia widget)

The report is only useful if it is visible without remembering to run a command.

- [x] **20. `pkgvuln-report` wrapper.** `pkgvuln report --json` with the unit's
      whitelist, exit code normalised to 0 (0/2/3 all mean "a report exists").
      One command keeps the widget and the unit from disagreeing.
- [x] **21. Noctalia plugin** (`noctalia-plugins/pkgvuln/`): `plugin.toml`
      (`plugin_api = 24`), a `[[widget]]` entry and a `[[panel]]` entry. Luau,
      because that is the only scripting Noctalia 5.x accepts; the plugin is
      installed through hjem into `~/.local/share/noctalia/plugins/pkgvuln`,
      which Noctalia discovers as its built-in "local" source.
- [x] **22. Bar widget** = one glyph + the package count, red when an advisory is
      in CISA KEV, plus a tooltip listing the worst six packages. Click opens
      the panel.
- [x] **23. Panel** = worst-first list of packages, advisory id / CVSS / KEV per
      row, `Rescan` (`pkgvuln scan`) and `Reload` buttons, click-to-copy the CVE.

Not planned, on purpose:

- **No polling of NVD from the widget.** It reads the database the weekly unit
  writes; a widget that syncs NVD on open would turn a 0.3 s query into a
  200 MB download and duplicate the unit's job.
