"""CISA Known Exploited Vulnerabilities catalogue.

The single highest-value signal per byte: it turns "you have 400 CVEs" into
"six of them are being exploited right now". Keyed by CVE id, so it joins
against OSV's GHSA ids only through the alias list.
"""

from __future__ import annotations

import json
import logging

from . import feeds

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
SOURCE = "kev"


def sync(connection) -> int:
    """Mark advisories that appear in the KEV catalogue. Returns rows changed."""
    log = logging.getLogger(__name__)
    body = feeds.fetch_cached(connection, URL)
    if body is None:
        return 0

    catalogue = json.loads(body.decode("utf-8"))
    exploited = {
        entry["cveID"]: entry.get("dateAdded")
        for entry in catalogue.get("vulnerabilities") or []
        if entry.get("cveID")
    }

    changed = 0
    for row in connection.execute("SELECT id, aliases, kev FROM advisories"):
        keys = {row["id"]}
        keys.update(alias for alias in (row["aliases"] or "").split(",") if alias)
        hit = next((key for key in keys if key in exploited), None)
        if hit is None:
            continue
        connection.execute(
            "UPDATE advisories SET kev = 1, kev_added = ? WHERE id = ?",
            (exploited[hit], row["id"]),
        )
        changed += 1
    log.info("KEV: %d advisories marked exploited", changed)
    return changed
