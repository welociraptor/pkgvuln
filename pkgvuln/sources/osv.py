"""OSV.dev lookups for language-ecosystem packages.

Two things differ from the NVD/CPE world and make this the easy half:

* The server does the range matching - ``querybatch`` returns only the
  advisories that affect *that exact version*, so no version comparison code is
  needed on our side.
* Package identity is namespaced (``PyPI`` + ``requests``), so no heuristic
  product-name guessing - but also no ``nixpkgs`` ecosystem, so the translation
  in :mod:`pkgvuln.names` is what makes this work at all.

Results are cached per (ecosystem, package, version) so a weekly run only pays
for coordinates it has never seen. There is also a bulk export
(``https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip``)
if the API ever becomes a problem.
"""

from __future__ import annotations

import logging

from .. import db, fetch, names

API_BATCH = "https://api.osv.dev/v1/querybatch"
API_VULN = "https://api.osv.dev/v1/vulns/"
BATCH_SIZE = 1000
SOURCE = "osv"
REFRESH_DAYS = 7


def _cached(connection, ecosystem: str, package: str, version: str, refresh_days: int):
    row = connection.execute(
        "SELECT advisory_ids FROM osv_queries"
        " WHERE ecosystem = ? AND package = ? AND version = ?"
        " AND checked_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)",
        (ecosystem, package, version, f"-{refresh_days} days"),
    ).fetchone()
    if row is None:
        return None
    return [i for i in row["advisory_ids"].split(",") if i]


def _store(connection, ecosystem: str, package: str, version: str, ids: list[str]) -> None:
    connection.execute(
        "INSERT INTO osv_queries (ecosystem, package, version, advisory_ids)"
        " VALUES (?, ?, ?, ?)"
        " ON CONFLICT (ecosystem, package, version) DO UPDATE SET"
        " advisory_ids = excluded.advisory_ids,"
        " checked_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        (ecosystem, package, version, ",".join(ids)),
    )


def lookup(
    connection, coordinates, *, offline: bool = False, refresh_days: int = REFRESH_DAYS
) -> dict[tuple[str, str, str], list[str]]:
    """Map each coordinate to the advisory ids affecting that version."""
    results: dict[tuple[str, str, str], list[str]] = {}
    pending: list[tuple[str, str, str]] = []

    for coordinate in dict.fromkeys(coordinates):
        if not names.ecosystem_supported(coordinate[0]):
            continue
        cached = _cached(connection, *coordinate, refresh_days)
        if cached is None:
            pending.append(coordinate)
        else:
            results[coordinate] = cached

    if offline:
        if pending:
            logging.getLogger(__name__).warning(
                "offline: %d coordinates have no cached OSV answer", len(pending)
            )
        return results

    for start in range(0, len(pending), BATCH_SIZE):
        chunk = pending[start : start + BATCH_SIZE]
        payload = {
            "queries": [
                {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
                for ecosystem, package, version in chunk
            ]
        }
        response = fetch.post_json(API_BATCH, payload)
        rows = response.get("results") or []
        for coordinate, row in zip(chunk, rows):
            ids = [vuln["id"] for vuln in (row.get("vulns") or [])]
            results[coordinate] = ids
            _store(connection, *coordinate, ids)
        if len(rows) != len(chunk):
            logging.getLogger(__name__).warning(
                "OSV returned %d results for %d queries", len(rows), len(chunk)
            )
    return results


def _severity(vuln: dict) -> str | None:
    """Coarse label. OSV severity scores are CVSS *vectors*, not numbers."""
    specific = vuln.get("database_specific") or {}
    label = specific.get("severity")
    return label.upper() if isinstance(label, str) else None


def fetch_details(connection, advisory_ids) -> None:
    """Populate summaries, severity and CVE aliases for known advisories.

    Alias handling matters: OSV ids are mostly GHSA ids while KEV and EPSS are
    keyed by CVE, so without aliases those joins would miss everything.
    """
    log = logging.getLogger(__name__)
    known = {
        row["id"]: row
        for row in connection.execute(
            "SELECT id, summary, description FROM advisories"
        )
    }
    for advisory_id in dict.fromkeys(advisory_ids):
        row = known.get(advisory_id)
        if row is not None and (row["summary"] or row["description"]):
            continue
        try:
            vuln = fetch.get_json(API_VULN + advisory_id)
        except fetch.FetchError as error:
            log.warning("cannot fetch OSV details for %s: %s", advisory_id, error)
            continue
        db.record_advisory(
            connection,
            {
                "id": vuln.get("id", advisory_id),
                "source": SOURCE,
                "modified": vuln.get("modified"),
                "severity": _severity(vuln),
                "summary": vuln.get("summary"),
                "description": vuln.get("details"),
                "aliases": vuln.get("aliases") or [],
            },
        )


def scan(connection, snapshot_id: int, packages: list, *, offline: bool = False) -> int:
    """Look up every mappable package and record the matches."""
    by_coordinate: dict[tuple[str, str, str], list] = {}
    for package in packages:
        coordinate = names.osv_coordinates(package["name"], package["version"])
        if coordinate is None:
            continue
        by_coordinate.setdefault(coordinate, []).append(package)

    if not by_coordinate:
        return 0

    found = lookup(connection, by_coordinate, offline=offline)

    # Details first, placeholders afterwards: a placeholder row would make
    # fetch_details() think it already knows the advisory.
    referenced = [
        advisory_id
        for advisory_ids in found.values()
        for advisory_id in advisory_ids
    ]
    if not offline:
        fetch_details(connection, referenced)

    recorded = 0
    for coordinate, advisory_ids in found.items():
        for advisory_id in advisory_ids:
            db.record_advisory(
                connection, {"id": advisory_id, "source": SOURCE}
            )
            for package in by_coordinate[coordinate]:
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
    return recorded