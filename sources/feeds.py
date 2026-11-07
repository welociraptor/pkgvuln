"""Feed download helper with ETag revalidation and a local copy.

A ``304 Not Modified`` must not mean "nothing to do": enrichment feeds (KEV,
EPSS) are applied to whatever advisories exist *now*, and new advisories are
added between runs. So the last payload is kept in the ``feeds`` table and
re-applied whenever the server says the feed has not changed.
"""

from __future__ import annotations

import gzip
import logging

from .. import fetch

log = logging.getLogger(__name__)


def fetch_cached(
    connection, url: str, *, gz: bool = False, keep_payload: bool = True
) -> bytes | None:
    """Return the feed body, revalidating with an ETag. None if unavailable.

    ``keep_payload=False`` is for large feeds whose parsed data is already
    persisted in the database (NVD): there is nothing to re-apply after a 304,
    so keeping a second copy would just double the storage.
    """
    row = connection.execute(
        "SELECT etag, payload FROM feeds WHERE url = ?", (url,)
    ).fetchone()
    etag = row["etag"] if row else None

    body, new_etag = fetch.get(url, etag=etag, gz=gz)
    if body is None:
        if row is not None and row["payload"]:
            log.info("%s unchanged, re-applying cached copy", url)
            return gzip.decompress(row["payload"])
        log.info("%s unchanged and nothing cached", url)
        return None

    if not keep_payload:
        connection.execute(
            "INSERT INTO feeds (url, etag) VALUES (?, ?)"
            " ON CONFLICT (url) DO UPDATE SET etag = excluded.etag,"
            " fetched_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
            (url, new_etag),
        )
        log.info("fetched %s (%d bytes)", url, len(body))
        return body

    connection.execute(
        "INSERT INTO feeds (url, etag, payload) VALUES (?, ?, ?)"
        " ON CONFLICT (url) DO UPDATE SET etag = excluded.etag,"
        " payload = excluded.payload,"
        " fetched_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')",
        (url, new_etag, gzip.compress(body)),
    )
    log.info("fetched %s (%d bytes)", url, len(body))
    return body
