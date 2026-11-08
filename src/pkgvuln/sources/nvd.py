"""NVD JSON 2.0 feeds: the only source for plain C/C++ packages.

This is the phase-2 source that the plan expected to need later; it is here
first because ``sources/vulnix.py`` cannot see 44% of this system's
derivations (their ``.drv`` files were garbage collected - measured: 602 of
1095 present). Matching here needs nothing but the name and version that
``pkgvuln snapshot`` already recorded, so coverage is 100%.

Feeds are ~25-45 MB gzipped per year and ~1.5 GB of JSON in total. They are
parsed one archive at a time and only the parts needed for matching are kept
(vendor/product/version ranges), not the raw records.
"""

from __future__ import annotations

import datetime
import json
import logging

from . import feeds

MIRROR = "https://nvd.nist.gov/feeds/json/cve/2.0/"
SOURCE = "nvd"
YEARS = 5
CHUNK = 500


def archives(years: int = YEARS, with_modified: bool = True) -> list[str]:
    """The archive names vulnix uses: recent years plus the modified feed."""
    current = datetime.date.today().year
    names = ["modified"] if with_modified else []
    names.extend(str(year) for year in range(current - years, current + 1))
    return names


def feed_url(name: str) -> str:
    return f"{MIRROR}nvdcve-2.0-{name}.json.gz"


def parse_cpe(criteria: str) -> dict | None:
    """Extract vendor/product/version from a CPE 2.3 application URI."""
    if not criteria or not criteria.startswith("cpe:2.3:"):
        return None
    parts = criteria.replace("\\:", "-").split(":", 7)
    if len(parts) < 8:
        return None
    _, _version, part, vendor, product, version, update, _rest = parts
    if part != "a":
        return None
    if product in ("", "*", "-"):
        return None
    exact = None
    if version not in ("", "*", "-"):
        exact = version
        if update not in ("", "*", "-"):
            exact = f"{version}-{update}"
    return {"vendor": vendor, "product": product.lower(), "version_exact": exact}


def _metric(cve: dict, key: str) -> float | None:
    for entry in (cve.get("metrics") or {}).get(key) or []:
        score = (entry.get("cvssData") or {}).get("baseScore")
        if score is not None:
            return float(score)
    return None


def _description(cve: dict) -> str | None:
    for entry in cve.get("descriptions") or []:
        if entry.get("lang", "en") == "en":
            return entry.get("value")
    return None


def parse_cve(item: dict) -> tuple[dict, list[dict]]:
    """Parse one NVD item into an advisory row and its affected rows."""
    cve = item["cve"]
    advisory = {
        "id": cve["id"],
        "modified": cve.get("lastModified"),
        "cvss_v4": _metric(cve, "cvssMetricV40"),
        "cvss_v3": _metric(cve, "cvssMetricV31") or _metric(cve, "cvssMetricV30"),
        "cvss_v2": _metric(cve, "cvssMetricV2"),
        "summary": cve.get("cisaVulnerabilityName"),
        "description": _description(cve),
    }
    affected = []
    for configuration in cve.get("configurations") or []:
        for node in configuration.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") is not True:
                    continue
                parsed = parse_cpe(match.get("criteria") or "")
                if parsed is None:
                    continue
                parsed.update(
                    {
                        "advisory_id": cve["id"],
                        "start_incl": match.get("versionStartIncluding"),
                        "start_excl": match.get("versionStartExcluding"),
                        "end_incl": match.get("versionEndIncluding"),
                        "end_excl": match.get("versionEndExcluding"),
                        "cpe": match.get("criteria"),
                    }
                )
                affected.append(parsed)
    return advisory, affected


_ADVISORY_SQL = """
INSERT INTO advisories (id, source, sources, modified, cvss_v4, cvss_v3,
                        cvss_v2, summary, description)
VALUES (?, 'nvd', 'nvd', ?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
    modified    = COALESCE(excluded.modified, advisories.modified),
    cvss_v4     = COALESCE(excluded.cvss_v4, advisories.cvss_v4),
    cvss_v3     = COALESCE(excluded.cvss_v3, advisories.cvss_v3),
    cvss_v2     = COALESCE(excluded.cvss_v2, advisories.cvss_v2),
    summary     = COALESCE(advisories.summary, excluded.summary),
    description = COALESCE(advisories.description, excluded.description),
    sources     = CASE WHEN instr(advisories.sources, 'nvd') > 0
                       THEN advisories.sources
                       ELSE advisories.sources || ',nvd' END
"""

_AFFECTED_SQL = """
INSERT INTO affected (advisory_id, vendor, product, version_exact,
                      start_incl, start_excl, end_incl, end_excl, cpe)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def store(connection, advisories: list[tuple], affected: list[tuple]) -> None:
    connection.executemany(_ADVISORY_SQL, advisories)
    for start in range(0, len(advisories), CHUNK):
        ids = [row[0] for row in advisories[start : start + CHUNK]]
        marks = ",".join("?" * len(ids))
        connection.execute(f"DELETE FROM affected WHERE advisory_id IN ({marks})", ids)
    connection.executemany(_AFFECTED_SQL, affected)


def sync(connection, names: list[str]) -> dict:
    """Download and store the given NVD archives. Returns per-feed counts."""
    log = logging.getLogger(__name__)
    counts: dict[str, int] = {}
    for name in names:
        url = feed_url(name)
        body = feeds.fetch_cached(connection, url, gz=True, keep_payload=False)
        if body is None:
            counts[name] = -1
            continue
        raw = json.loads(body.decode("utf-8"))
        del body
        advisories: list[tuple] = []
        affected: list[tuple] = []
        for item in raw.get("vulnerabilities") or []:
            try:
                advisory, matches = parse_cve(item)
            except (KeyError, TypeError):
                continue
            advisories.append(
                (
                    advisory["id"],
                    advisory["modified"],
                    advisory["cvss_v4"],
                    advisory["cvss_v3"],
                    advisory["cvss_v2"],
                    advisory["summary"],
                    advisory["description"],
                )
            )
            for match in matches:
                affected.append(
                    (
                        match["advisory_id"],
                        match["vendor"],
                        match["product"],
                        match["version_exact"],
                        match["start_incl"],
                        match["start_excl"],
                        match["end_incl"],
                        match["end_excl"],
                        match["cpe"],
                    )
                )
        store(connection, advisories, affected)
        connection.commit()
        del raw
        counts[name] = len(advisories)
        log.info("NVD %s: %d advisories, %d affected rows", name, len(advisories), len(affected))
    return counts
