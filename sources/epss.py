"""EPSS exploit-prediction scores (FIRST).

Used only for prioritisation: the daily CSV is a single gzipped table of
``cve,epss,percentile``, and rows that are not in ``advisories`` are simply
ignored - we only need scores for findings we already have.
"""

from __future__ import annotations

import logging

from . import feeds

URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
SOURCE = "epss"


def parse(text: str) -> dict[str, tuple[float, float]]:
    """Parse the EPSS CSV into {cve: (score, percentile)}."""
    scores: dict[str, tuple[float, float]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(",")
        if len(fields) < 3 or not fields[0].startswith("CVE-"):
            continue
        try:
            scores[fields[0]] = (float(fields[1]), float(fields[2]))
        except ValueError:
            continue
    return scores


def sync(connection) -> int:
    log = logging.getLogger(__name__)
    body = feeds.fetch_cached(connection, URL, gz=True)
    if body is None:
        return 0

    scores = parse(body.decode("utf-8"))
    changed = 0
    for row in connection.execute("SELECT id, aliases FROM advisories"):
        keys = {row["id"]}
        keys.update(alias for alias in (row["aliases"] or "").split(",") if alias)
        for key in keys:
            if key in scores:
                score, percentile = scores[key]
                connection.execute(
                    "UPDATE advisories SET epss = ?, epss_percentile = ? WHERE id = ?",
                    (score, percentile, row["id"]),
                )
                changed += 1
                break
    log.info("EPSS: scores recorded for %d advisories", changed)
    return changed
