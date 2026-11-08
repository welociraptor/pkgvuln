"""Compare the installed snapshot against the versions the nixpkgs pin builds.

Two layers, because the cheap one is not trustworthy on its own.

**Layer 1** evaluates nixpkgs once per pin (``nix-env -qa --json``: 104 900
attributes, ~75 s and 26 MB on this machine) and compares every installed
package with ``pkgs.<pname>``. Measured against the live database, that resolves
~620 of 1108 rows and produces five "newer version available" candidates - all
five false. The reason is that a *pname is not an attribute path* and a version
is not enough to tell an old package from another version line:

* ``boost 1.89.0`` is ``pkgs.boost189`` (still in the pin, and 1.89 is what the
  closure asks for), while ``pkgs.boost`` is 1.91 and nothing installs it;
* ``db 4.8.30`` is ``pkgs.db4`` and ``db 5.3.28`` is ``pkgs.db`` - both are
  installed, so neither is out of date;
* ``dbus 1`` is the output of ``pkgs.makeDBusConf``; the name parser reads the
  "1" as a version;
* ``lua 5.4.9`` is ``pkgs.lua5_4_compat`` and 5.5.1 is installed too.

**Layer 2** (``--verify-store-paths``) settles it by store path instead of by
name: the same attributes are evaluated with ``--out-path``, and the snapshot's
``store_path`` is looked up in the result. A hit proves the installed path is
exactly what this pin builds, whatever it is called, so the candidate is
dropped. Only a miss is real: a package from an older pin (``nix profile``), an
output from another flake input, or an attribute that has since been renamed or
removed.

What the report calls ``ahead`` is the mirror image - installed newer than the
pin's default attribute. Usually that is a variant marker in the version
(``9.12_fish-completions``, ``1.2.4-zstd``, ``5.42.3-env``; see
:func:`pkgvuln.nixver.strip_variants`), occasionally a deliberate alternate
line the profile picked up.

Exit codes follow :mod:`pkgvuln.report`: 0 by default because "an upgrade
exists" is not a failure, 2 with ``--fail-on-outdated`` when something is
outdated. 1 stays reserved for crashes.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from . import db, nixver

SOURCE = "nixpkgs"

CURRENT = "current"
OUTDATED = "outdated"
AHEAD = "ahead"
UNMAPPED = "unmapped"

# nix-env takes its filter as a command line argument, and the kernel's limit
# per argument is ~128 KB: 1062 names in one expression is 17 KB but hits E2BIG
# long before that, so the residue is evaluated in small batches.
BATCH = 200

# How one package's name was mapped onto an attribute.
HOW_DEFAULT = "default"  # pkgs.<name> exists, i.e. what asking for it gives you
HOW_PNAME = "pname"  # exactly one top-level attribute has that pname
HOW_AMBIGUOUS = "ambiguous"  # several attributes share the pname
HOW_ABSENT = "absent"  # no top-level attribute has it

_LOG = logging.getLogger(__name__)


class EvaluationError(Exception):
    """nix-env could not be run or did not produce a usable attribute set."""


# --------------------------------------------------------------------------
# Finding nix and nixpkgs
# --------------------------------------------------------------------------


def find_executable(name: str) -> str:
    """Locate a nix binary even when PATH is minimal (systemd units)."""
    found = shutil.which(name)
    if found:
        return found
    for candidate in (
        f"/run/current-system/sw/bin/{name}",
        f"/nix/var/nix/profiles/default/bin/{name}",
    ):
        if os.access(candidate, os.X_OK):
            return candidate
    raise EvaluationError(f"cannot find '{name}' on this system")


def _run(command: list[str], timeout: float | None) -> str:
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout
        )
    except OSError as error:
        raise EvaluationError(f"failed to run {command[0]}: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise EvaluationError(
            f"{' '.join(command[:4])} timed out after {timeout}s"
        ) from error
    if completed.returncode != 0:
        # The feed of "evaluation warning: 'x' was renamed" lines is huge and
        # never useful; the tail is where the actual error is.
        detail = "\n".join(completed.stderr.strip().splitlines()[-5:])
        raise EvaluationError(
            f"{' '.join(command[:4])} failed ({completed.returncode}): {detail}"
        )
    return completed.stdout


def flake_nixpkgs(directory: Path = Path(".")) -> Path:
    """The nixpkgs source a flake pins, without touching the network."""
    nix = find_executable("nix")
    output = _run(
        [
            nix,
            "eval",
            "--raw",
            "--impure",
            "--expr",
            f'(builtins.getFlake "{directory.resolve()}").inputs.nixpkgs.outPath',
        ],
        timeout=120,
    )
    return Path(output.strip())


def current_system() -> str:
    return _run(
        [
            find_executable("nix"),
            "eval",
            "--raw",
            "--impure",
            "--expr",
            "builtins.currentSystem",
        ],
        timeout=120,
    ).strip()


def resolve_pin(explicit: str | Path | None) -> Path:
    """--nixpkgs, else $PKGVULN_NIXPKGS, else the flake in the current directory."""
    if explicit:
        return Path(explicit)
    from_environment = os.environ.get("PKGVULN_NIXPKGS")
    if from_environment:
        return Path(from_environment)
    if Path("flake.lock").exists():
        return flake_nixpkgs()
    raise EvaluationError(
        "cannot find nixpkgs: pass --nixpkgs PATH (or set PKGVULN_NIXPKGS,"
        " or run from a directory containing flake.lock)"
    )


# --------------------------------------------------------------------------
# Evaluation
# --------------------------------------------------------------------------


# Only these need escaping to appear literally in a POSIX ERE. re.escape is not
# usable here: it escapes ``-`` as ``\-``, which nix's regex flavour rejects
# outright ("Invalid escape in regular expression"), and that failure costs a
# full evaluation before it is reported.
_FILTER_SPECIAL = frozenset(".+*?()[]{}|^$\\")


def _escape(name: str) -> str:
    return "".join("\\" + char if char in _FILTER_SPECIAL else char for char in name)


def filter_regex(names) -> str:
    """The ``nix-env -qa`` filter that selects these pnames.

    nix-env matches the filter against the *pname*, not the attribute path, so
    one expression selects every alternative version line of a package - which
    is exactly what layer 2 needs.
    """
    return "^(" + "|".join(_escape(name) for name in sorted(names)) + ")$"


def evaluate(
    pin: Path,
    names=None,
    with_outputs: bool = False,
    timeout: float | None = 3600,
) -> dict[str, dict]:
    """``nix-env -qa --json``: attrPath -> {pname, version, outputs?}."""
    command = [find_executable("nix-env"), "-f", str(pin), "-qa", "--json"]
    if with_outputs:
        command.append("--out-path")
    if names is not None:
        names = sorted(set(names))
        if not names:
            return {}
        command.append(filter_regex(names))
    payload = _run(command, timeout=timeout)
    try:
        data = json.loads(payload)
    except ValueError as error:
        raise EvaluationError(f"nix-env produced invalid JSON: {error}") from error
    if not isinstance(data, dict):
        raise EvaluationError("nix-env did not produce an attribute map")
    return data


def batches(names, size: int = BATCH) -> list[list[str]]:
    ordered = sorted(set(names))
    return [ordered[start : start + size] for start in range(0, len(ordered), size)]


# --------------------------------------------------------------------------
# Cache
# --------------------------------------------------------------------------


def cached_attrs(connection, pin: Path | str, system: str) -> dict[str, dict] | None:
    """The cached attribute set, or None when this pin has not been evaluated."""
    row = connection.execute(
        "SELECT attrs FROM nixpkgs_pins WHERE pin = ? AND system = ?",
        (str(pin), system),
    ).fetchone()
    if row is None or not row["attrs"]:
        return None
    attrs: dict[str, dict] = {}
    for stored in connection.execute(
        "SELECT attr, pname, version FROM nixpkgs_attrs WHERE pin = ? AND system = ?",
        (str(pin), system),
    ):
        attrs[stored["attr"]] = {
            "pname": stored["pname"],
            "version": stored["version"],
        }
    return attrs


def store_attrs(connection, pin: Path | str, system: str, attrs: dict[str, dict]) -> None:
    connection.executemany(
        "INSERT INTO nixpkgs_attrs (pin, system, attr, pname, version)"
        " VALUES (?, ?, ?, ?, ?)"
        " ON CONFLICT (pin, system, attr) DO UPDATE SET"
        " pname = excluded.pname, version = excluded.version",
        [
            (
                str(pin),
                system,
                attr,
                meta.get("pname") or attr.rsplit(".", 1)[-1],
                meta.get("version"),
            )
            for attr, meta in attrs.items()
        ],
    )
    connection.execute(
        "INSERT INTO nixpkgs_pins (pin, system, attrs) VALUES (?, ?, ?)"
        " ON CONFLICT (pin, system) DO UPDATE SET"
        " attrs = excluded.attrs,"
        " evaluated = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        (str(pin), system, len(attrs)),
    )
    connection.commit()


def load_attrs(
    connection, pin: Path | str, system: str, refresh: bool = False
) -> dict[str, dict]:
    """Cached attributes for this pin, evaluating nixpkgs only when needed."""
    if not refresh:
        cached = cached_attrs(connection, pin, system)
        if cached:
            return cached
    _LOG.info("evaluating %s (this takes a minute)", pin)
    attrs = evaluate(pin)
    store_attrs(connection, pin, system, attrs)
    return attrs


def cached_output_pnames(connection, pin: Path | str, system: str) -> set[str]:
    return {
        row["pname"]
        for row in connection.execute(
            "SELECT pname FROM nixpkgs_outputs WHERE pin = ? AND system = ?",
            (str(pin), system),
        )
    }


def store_outputs(
    connection, pin: Path | str, system: str, pnames, evaluated: dict[str, dict]
) -> None:
    """Remember one evaluation under every pname it was filtered on."""
    payload = {
        attr: meta.get("outputs") or {}
        for attr, meta in evaluated.items()
    }
    if not payload:
        return
    serialised = json.dumps(payload)
    connection.executemany(
        "INSERT INTO nixpkgs_outputs (pin, system, pname, attrs) VALUES (?, ?, ?, ?)"
        " ON CONFLICT (pin, system, pname) DO UPDATE SET attrs = excluded.attrs",
        [(str(pin), system, name, serialised) for name in sorted(set(pnames))],
    )
    connection.commit()


def stored_outputs(connection, pin: Path | str, system: str) -> dict[str, dict]:
    """store path -> {attr, output} for everything evaluated with --out-path."""
    paths: dict[str, dict] = {}
    for row in connection.execute(
        "SELECT attrs FROM nixpkgs_outputs WHERE pin = ? AND system = ?",
        (str(pin), system),
    ):
        for attr, outputs in json.loads(row["attrs"]).items():
            for output, path in (outputs or {}).items():
                if path:
                    paths.setdefault(path, {"attr": attr, "output": output})
    return paths


def verify_store_paths(connection, pin: Path | str, system: str, pnames) -> dict[str, dict]:
    """Resolve store paths for these pnames, evaluating only what is not cached."""
    known = cached_output_pnames(connection, pin, system)
    missing = [name for name in sorted(set(pnames)) if name not in known]
    for batch in batches(missing):
        _LOG.info("evaluating store paths for %d pnames", len(batch))
        store_outputs(
            connection, pin, system, batch, evaluate(pin, batch, with_outputs=True)
        )
    return stored_outputs(connection, pin, system)


# --------------------------------------------------------------------------
# Comparison (pure)
# --------------------------------------------------------------------------


def top_level(attrs: dict[str, dict]) -> dict[str, dict]:
    """``pkgs.<name>`` only: the attributes that are not behind another set."""
    return {
        attr: meta
        for attr, meta in attrs.items()
        if "." not in attr and meta.get("version")
    }


def index_by_pname(top: dict[str, dict]) -> dict[str, list[str]]:
    index: dict[str, list[str]] = {}
    for attr, meta in top.items():
        index.setdefault(meta.get("pname") or attr, []).append(attr)
    return {pname: sorted(attrs) for pname, attrs in index.items()}


def resolve_attr(
    name: str, top: dict[str, dict], index: dict[str, list[str]]
) -> tuple[str | None, str]:
    """The attribute a package name corresponds to, plus how it was found.

    ``pkgs.<name>`` wins because it is what nixpkgs gives you when you ask for
    that name; ``_latest``/``_4_1``/``boost189`` siblings are alternatives, not
    upgrades. A pname that is not an attribute path is resolved only when it is
    unambiguous (``gtk+3`` -> ``gtk3``).
    """
    if name in top:
        return name, HOW_DEFAULT
    candidates = index.get(name) or []
    if len(candidates) == 1:
        return candidates[0], HOW_PNAME
    return None, (HOW_AMBIGUOUS if candidates else HOW_ABSENT)


def classify(version: str | None, reference: str | None) -> str:
    """current / outdated / ahead for one installed version against the pin."""
    if not version or not reference:
        return UNMAPPED
    left = nixver.strip_variants(version)
    right = nixver.strip_variants(reference)
    if not left or not right:
        return UNMAPPED
    order = nixver.compare(left, right)
    if order == 0:
        return CURRENT
    return OUTDATED if order < 0 else AHEAD


# An `unstable-` component means "snapshot of a moving branch", and nixpkgs puts
# it in the middle of the version as often as at the start
# (``14.4.2-unstable-2021-05-09``). It compares as a string, so the direction of a
# version difference involving one is a guess, not a fact.
_UNSTABLE = re.compile(r"(?:^|[-_.])unstable(?:$|[-_.])")


# A version with no separator at all ("1", "7") is often not a version but the
# tail of a name: `dbus-1` is the derivation `dbus-1` (version "1") in one pin and
# `dbus-1.16.2` in the next. Reporting `1 -> 1.16.2` as a certain upgrade would be
# wrong, so this pattern is downgraded to "unsure".
_ONE_COMPONENT = re.compile(r"^\d+$")


def looks_truncated(installed: str | None, reference: str | None) -> bool:
    """Whether the installed version is a leading component of the reference."""
    if not installed or not reference or not _ONE_COMPONENT.match(installed):
        return False
    return reference.split(".")[0] == installed and "." in reference


def confident(version: str | None, reference: str | None) -> bool:
    """Whether both versions are real releases, so the comparison can be trusted.

    ``unstable-2021-05-09`` and date-stamped builds sort by whatever the date
    happens to be; the report says ``unsure`` rather than implying certainty.
    """
    return all(
        nixver.upstream_version(value) is not None
        and not _UNSTABLE.search(value)
        and not looks_truncated(value, other)
        for value, other in ((version, reference), (reference, version))
    )


def compare_packages(packages, attrs: dict[str, dict]) -> list[dict]:
    """Layer 1: one row per installed package."""
    top = top_level(attrs)
    index = index_by_pname(top)
    rows: list[dict] = []
    for package in packages:
        name = package["name"]
        version = package["version"]
        attr, how = resolve_attr(name, top, index)
        reference = top[attr]["version"] if attr else None
        status = classify(version, reference)
        row = {
            "name": name,
            "version": version,
            "store_path": package["store_path"],
            "attr": attr,
            "how": how,
            "nixpkgs_version": reference,
            "status": status,
        }
        if status in (OUTDATED, AHEAD):
            row["confidence"] = "certain" if confident(version, reference) else "unsure"
        rows.append(row)
    return rows


def apply_verification(rows: list[dict], paths: dict[str, dict]) -> None:
    """Layer 2: a store path the pin builds cannot be out of date."""
    for row in rows:
        resolved = paths.get(row["store_path"])
        row["in_pin"] = resolved is not None
        if resolved is None:
            continue
        # The pin builds this exact path: the attribute is now known for certain,
        # whatever the name looked like.
        row["attr"] = resolved["attr"]
        row["verified_output"] = resolved["output"]
        if row["status"] in (OUTDATED, AHEAD):
            row["status"] = CURRENT
            row["note"] = "identical to the pin"


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


def build(
    connection,
    snapshot_id: int,
    pin: Path | str,
    system: str | None = None,
    refresh: bool = False,
    verify: bool = False,
) -> dict:
    snapshot = connection.execute(
        "SELECT id, taken_at FROM snapshots WHERE id = ?", (snapshot_id,)
    ).fetchone()
    if snapshot is None:
        raise SystemExit(f"error: snapshot #{snapshot_id} not found")

    system = system or current_system()
    attrs = load_attrs(connection, pin, system, refresh=refresh)
    packages = db.snapshot_packages(connection, snapshot_id)
    if not packages:
        raise SystemExit(f"error: snapshot #{snapshot_id} has no packages")

    rows = compare_packages(packages, attrs)

    paths: dict[str, dict] = {}
    if verify:
        # Only the candidates need disambiguating: everything else is either
        # already equal to the pin or unmappable, and one evaluation answers for
        # every alternate version line of the same pname.
        candidates = {row["name"] for row in rows if row["status"] in (OUTDATED, AHEAD)}
        if candidates:
            paths = verify_store_paths(connection, pin, system, candidates)
        apply_verification(rows, paths)
    counts = {status: 0 for status in (CURRENT, OUTDATED, AHEAD, UNMAPPED)}
    for row in rows:
        counts[row["status"]] += 1

    def interesting(status):
        return sorted(
            (row for row in rows if row["status"] == status),
            key=lambda row: (row["name"], row["version"] or ""),
        )

    return {
        "snapshot": {"id": snapshot["id"], "taken_at": snapshot["taken_at"]},
        "nixpkgs": {
            "pin": str(pin),
            "system": system,
            "attrs": len(attrs),
            "verified": bool(verify),
            "resolved_candidates": sum(
                1 for row in rows if row.get("note") == "identical to the pin"
            ),
        },
        "packages": len(rows),
        "counts": counts,
        "outdated": interesting(OUTDATED),
        "ahead": interesting(AHEAD),
    }


def format_text(report: dict, limit: int = 20) -> str:
    snapshot = report["snapshot"]
    nixpkgs = report["nixpkgs"]
    counts = report["counts"]
    lines = [
        f"Snapshot #{snapshot['id']} ({snapshot['taken_at']}) vs {nixpkgs['pin']}"
        f" [{nixpkgs['system']}, {nixpkgs['attrs']} attributes]",
        f" {report['packages']} packages: {counts[CURRENT]} current,"
        f" {counts[OUTDATED]} possibly outdated, {counts[AHEAD]} newer than the pin,"
        f" {counts[UNMAPPED]} unmapped",
    ]

    if counts[OUTDATED]:
        lines.append("")
        lines.append(f"{counts[OUTDATED]} package(s) with a newer version in nixpkgs:")
        for row in report["outdated"][:limit]:
            lines.append("   " + _describe(row, "->"))
        if len(report["outdated"]) > limit:
            lines.append(f"   ... and {len(report['outdated']) - limit} more")
        if not nixpkgs["verified"]:
            lines.append(
                "   unverified: a candidate can be another version line of the same"
                " package; rerun with --verify-store-paths"
            )

    if counts[AHEAD]:
        lines.append("")
        lines.append(f"{counts[AHEAD]} package(s) newer than the pin:")
        for row in report["ahead"][:limit]:
            lines.append("   " + _describe(row, ">"))
        if len(report["ahead"]) > limit:
            lines.append(f"   ... and {len(report['ahead']) - limit} more")

    if nixpkgs["verified"]:
        lines.append("")
        resolved = nixpkgs["resolved_candidates"]
        lines.append(
            f" store-path check: {resolved} candidate(s) are exactly what the pin"
            " builds under another attribute"
            + (f", {counts[OUTDATED] + counts[AHEAD]} remain" if counts[OUTDATED] or counts[AHEAD] else ", nothing remains")
        )

    if not counts[OUTDATED] and not counts[AHEAD]:
        lines.append(" nothing to upgrade")
    return "\n".join(lines)


def _describe(row: dict, arrow: str) -> str:
    """One candidate line: what it is, what the pin has, and how sure we are."""
    title = f"{row['name']}-{row['version']}" if row["version"] else row["name"]
    line = f"{title} {arrow} {row['nixpkgs_version']}  [{row['attr']}"
    if row.get("confidence"):
        line += f", {row['confidence']}"
    line += "]"
    if row.get("in_pin") is False:
        line += "  not built by this pin"
    if row.get("note") and row["note"] != "identical to the pin":
        line += f"  [{row['note']}]"
    return line


def format_json(report: dict) -> str:
    return json.dumps(report, indent=1, sort_keys=False)