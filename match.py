"""Match recorded package versions against the ``affected`` table (CPE data).

No derivation files are involved, which is the whole point: on this system 479
of 1095 ``.drv`` files have been garbage collected, so anything that parses
derivations sees less than half the machine. Name and version from the snapshot
table are enough.

Known limitations, inherited from the way NVD models software:

* The vendor field is ignored. Matching on product alone reports
  ``CVE-2021-44228`` for anything named ``log4j``, which is what vulnix does
  too - false positives are accepted in exchange for not losing findings.
* Only the first product candidate with any hit is used, so a package that maps
  onto two different NVD products is under-reported.
* NVD's own enrichment backlog means recently published CVEs often have no
  CPE data at all and cannot match anything here.

Product candidates are tried in order of decreasing confidence, straight from
``Derive.product_candidates()`` in vulnix, which is the de-facto convention for
this problem.
"""

from __future__ import annotations

import logging

from . import db, nixver

SOURCE = "nvd"


def product_candidates(pname: str) -> list[str]:
    """Candidate NVD product names, most literal first.

    ``affected.product`` is stored lowercased at ingest time, so case variants
    would be redundant lookups; only the hyphen/underscore difference is real
    (NVD has both ``libpng`` and ``libpng16``, and ``gnu_libc``-style names).
    """
    underscore = pname.replace("-", "_").lower()
    literal = pname.lower()
    return [literal] if literal == underscore else [literal, underscore]


def _row_matches(row, release: str) -> bool:
    exact = row["version_exact"]
    if exact:
        return nixver.compare_release(release, exact) == 0
    if not any(
        row[key] for key in ("start_incl", "start_excl", "end_incl", "end_excl")
    ):
        # A CPE with no version and no range says nothing about this release.
        return False
    return nixver.in_range(
        release,
        row["start_incl"],
        row["start_excl"],
        row["end_incl"],
        row["end_excl"],
    )


def candidates_for(connection, release: str, pname: str):
    """Yield (product, advisory_id) pairs for one package."""
    statement = (
        "SELECT advisory_id, version_exact, start_incl, start_excl,"
        " end_incl, end_excl FROM affected WHERE product = ?"
    )
    for product in product_candidates(pname):
        hits = [
            row["advisory_id"]
            for row in connection.execute(statement, (product.lower(),))
            if _row_matches(row, release)
        ]
        if hits:
            yield product, sorted(set(hits))
            return


def scan(connection, snapshot_id: int, packages: list) -> int:
    """Record matches for every package whose name/version hits the CPE data."""
    log = logging.getLogger(__name__)
    affected = connection.execute("SELECT COUNT(*) AS n FROM affected").fetchone()["n"]
    if affected == 0:
        # Reporting "0 matches" here would look exactly like a clean system.
        print(
            "nvd: no advisory data - run 'pkgvuln sync --nvd' first."
            " 0 matches is NOT the same as clean."
        )
        return 0
    connection.execute(
        "DELETE FROM matches WHERE snapshot_id = ? AND source = ?",
        (snapshot_id, SOURCE),
    )

    recorded = 0
    unmatched_reason = {"no_version": 0, "no_product": 0}
    for package in packages:
        release = nixver.upstream_version(package["version"])
        if release is None:
            unmatched_reason["no_version"] += 1
            continue
        found = False
        for product, advisory_ids in candidates_for(connection, release, package["name"]):
            found = True
            for advisory_id in advisory_ids:
                db.record_match(
                    connection,
                    snapshot_id,
                    package["store_path"],
                    package["name"],
                    package["version"],
                    advisory_id,
                    SOURCE,
                )
                recorded += 1
            break  # first product candidate with hits wins, like vulnix
        if not found:
            unmatched_reason["no_product"] += 1

    log.info(
        "NVD/CPE: %d matches; %d packages without a matchable version,"
        " %d with no NVD product",
        recorded,
        unmatched_reason["no_version"],
        unmatched_reason["no_product"],
    )
    return recorded