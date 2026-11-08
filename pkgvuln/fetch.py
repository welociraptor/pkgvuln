"""Minimal HTTP fetching: retries, ETag revalidation, gzip.

Named ``fetch`` rather than ``http`` on purpose: a module called ``http``
inside a package on ``sys.path`` shadows the stdlib one and breaks
``urllib.request`` in confusing ways.

Stdlib only, so the tool runs under a bare Python with no site-packages.
"""

from __future__ import annotations

import gzip
import json
import logging
import time
import urllib.error
import urllib.request

_log = logging.getLogger(__name__)

USER_AGENT = "pkgvuln/0.1 (+nixos)"
TIMEOUT = 60
RETRIES = 3
BACKOFF = 2.0


class FetchError(RuntimeError):
    pass


def _request(url: str, data: bytes | None, headers: dict[str, str]) -> urllib.request.Request:
    base_headers = {"User-Agent": USER_AGENT}
    base_headers.update(headers)
    return urllib.request.Request(url, data=data, headers=base_headers)


def get(
    url: str, *, etag: str | None = None, gz: bool = False
) -> tuple[bytes | None, str | None]:
    """Fetch ``url``, returning (body, new_etag).

    ``body`` is None when the server answers 304 Not Modified, which is the
    normal case for unchanged NVD/KEV/EPSS feeds. ``gz=True`` decompresses a
    gzip payload (only pass it when you know the body is gzip; plain HTTP
    errors would otherwise be fed to the decompressor).
    """
    headers = {}
    if etag:
        headers["If-None-Match"] = etag
    last_error: Exception | None = None
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(_request(url, None, headers), timeout=TIMEOUT) as response:
                body = response.read()
                new_etag = response.headers.get("ETag")
                if gz:
                    body = gzip.decompress(body)
                return body, new_etag
        except urllib.error.HTTPError as error:
            if error.code == 304:
                return None, etag
            if 400 <= error.code < 500 and error.code not in (408, 429):
                raise FetchError(f"{url}: HTTP {error.code} {error.reason}") from error
            last_error = error
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
        if attempt + 1 < RETRIES:
            delay = BACKOFF ** (attempt + 1)
            _log.warning("fetch failed (%s), retrying in %.0fs", last_error, delay)
            time.sleep(delay)
    raise FetchError(f"{url}: {last_error}")


def post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    last_error: Exception | None = None
    for attempt in range(RETRIES):
        try:
            with urllib.request.urlopen(_request(url, data, headers), timeout=TIMEOUT) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            if 400 <= error.code < 500 and error.code not in (408, 429):
                detail = error.read().decode("utf-8", "replace")[:200]
                raise FetchError(f"{url}: HTTP {error.code} {detail}") from error
            last_error = error
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
        if attempt + 1 < RETRIES:
            time.sleep(BACKOFF ** (attempt + 1))
    raise FetchError(f"{url}: {last_error}")


def get_json(url: str) -> dict:
    body, _ = get(url)
    if body is None:
        raise FetchError(f"{url}: unexpected 304 without a cached body")
    return json.loads(body.decode("utf-8"))