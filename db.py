"""SQLite schema and connection helpers.

The database file is shared with ``track-packages.py``: that script owns the
``snapshots`` and ``packages`` tables and this module only ever reads them.
Everything it writes lives in its own tables, created with ``IF NOT EXISTS``.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS vuln_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS advisories (
    id              TEXT PRIMARY KEY,   -- CVE-2024-1234, GHSA-xxxx-yyyy-zzzz, ...
    source          TEXT NOT NULL,      -- source that first told us about it
    sources         TEXT NOT NULL DEFAULT '',  -- comma separated, all sources
    first_seen      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    modified        TEXT,
    severity        TEXT,               -- coarse label when there is no CVSS
    cvss_v4         REAL,
    cvss_v3         REAL,
    cvss_v2         REAL,
    summary         TEXT,
    description     TEXT,
    aliases         TEXT NOT NULL DEFAULT '',  -- comma separated ids
    kev             INTEGER NOT NULL DEFAULT 0,
    kev_added       TEXT,
    epss            REAL,
    epss_percentile REAL
);

CREATE TABLE IF NOT EXISTS affected (
    id            INTEGER PRIMARY KEY,
    advisory_id   TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    vendor        TEXT,
    product       TEXT,
    ecosystem     TEXT,
    package       TEXT,
    version_exact TEXT,
    start_incl    TEXT,
    start_excl    TEXT,
    end_incl      TEXT,
    end_excl      TEXT,
    cpe           TEXT
);

CREATE INDEX IF NOT EXISTS affected_product_idx ON affected (product);
CREATE INDEX IF NOT EXISTS affected_package_idx ON affected (ecosystem, package);

CREATE TABLE IF NOT EXISTS matches (
    snapshot_id INTEGER NOT NULL,
    store_path  TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT,
    advisory_id TEXT NOT NULL,
    source      TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, store_path, advisory_id)
);

CREATE INDEX IF NOT EXISTS matches_advisory_idx ON matches (advisory_id);

CREATE TABLE IF NOT EXISTS osv_queries (
    ecosystem    TEXT NOT NULL,
    package      TEXT NOT NULL,
    version      TEXT NOT NULL,
    checked_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    advisory_ids TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ecosystem, package, version)
);

CREATE TABLE IF NOT EXISTS feeds (
    url        TEXT PRIMARY KEY,
    etag       TEXT,
    sha256     TEXT,
    payload    BLOB,   -- gzipped copy of the feed, so a 304 can still be applied
    fetched_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
"""


def default_db_path() -> Path:
    """Same location track-packages.py uses, so both share one file."""
    data_home = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.environ.get("HOME", str(Path.home())), ".local", "share"
    )
    return Path(data_home) / "package-versions" / "packages.db"


def _ensure_column(connection, table: str, column: str, definition: str) -> None:
    """Tiny forward migration: the schema is additive only."""
    columns = {
        row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
    }
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def connect(db_path: Path) -> sqlite3.Connection:
    """Open the database and make sure our tables exist."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(SCHEMA)
    _ensure_column(connection, "feeds", "payload", "BLOB")
    connection.execute(
        "INSERT INTO vuln_meta (key, value) VALUES ('schema_version', ?)"
        " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )
    connection.commit()
    return connection


def latest_snapshot(connection: sqlite3.Connection) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT id, taken_at FROM snapshots ORDER BY id DESC LIMIT 1"
    ).fetchone()


def previous_snapshot(
    connection: sqlite3.Connection, snapshot_id: int
) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT id, taken_at FROM snapshots WHERE id < ? ORDER BY id DESC LIMIT 1",
        (snapshot_id,),
    ).fetchone()


def snapshot_packages(
    connection: sqlite3.Connection, snapshot_id: int
) -> list[sqlite3.Row]:
    return list(
        connection.execute(
            "SELECT name, version, derivation, store_path FROM packages"
            " WHERE snapshot_id = ? ORDER BY name",
            (snapshot_id,),
        )
    )


def record_advisory(connection: sqlite3.Connection, advisory: dict) -> None:
    """Insert or merge one advisory.

    Sources overlap heavily (GHSA records carry CVE aliases, NVD and OSV
    describe the same bug), so a second sighting must not clobber richer data
    with NULLs. Per-field: keep what we have, fill what we lack.
    """
    advisory_id = advisory["id"]
    source = advisory.get("source") or "unknown"
    row = connection.execute(
        "SELECT * FROM advisories WHERE id = ?", (advisory_id,)
    ).fetchone()

    if row is None:
        connection.execute(
            "INSERT INTO advisories (id, source, sources, modified, severity,"
            " cvss_v4, cvss_v3, cvss_v2, summary, description, aliases)"
            " VALUES (:id, :source, :sources, :modified, :severity, :cvss_v4,"
            " :cvss_v3, :cvss_v2, :summary, :description, :aliases)",
            {
                "id": advisory_id,
                "source": source,
                "sources": source,
                "modified": advisory.get("modified"),
                "severity": advisory.get("severity"),
                "cvss_v4": advisory.get("cvss_v4"),
                "cvss_v3": advisory.get("cvss_v3"),
                "cvss_v2": advisory.get("cvss_v2"),
                "summary": advisory.get("summary"),
                "description": advisory.get("description"),
                "aliases": ",".join(advisory.get("aliases") or []),
            },
        )
        return

    existing_sources = [s for s in (row["sources"] or "").split(",") if s]
    if source not in existing_sources:
        existing_sources.append(source)

    existing_aliases = [a for a in (row["aliases"] or "").split(",") if a]
    for alias in advisory.get("aliases") or []:
        if alias not in existing_aliases:
            existing_aliases.append(alias)

    merged = {
        "id": advisory_id,
        "sources": ",".join(existing_sources),
        "modified": advisory.get("modified") or row["modified"],
        "severity": advisory.get("severity") or row["severity"],
        "cvss_v4": advisory.get("cvss_v4") or row["cvss_v4"],
        "cvss_v3": advisory.get("cvss_v3") or row["cvss_v3"],
        "cvss_v2": advisory.get("cvss_v2") or row["cvss_v2"],
        "summary": advisory.get("summary") or row["summary"],
        "description": advisory.get("description") or row["description"],
        "aliases": ",".join(existing_aliases),
    }
    connection.execute(
        "UPDATE advisories SET sources = :sources, modified = :modified,"
        " severity = :severity, cvss_v4 = :cvss_v4, cvss_v3 = :cvss_v3,"
        " cvss_v2 = :cvss_v2, summary = :summary, description = :description,"
        " aliases = :aliases WHERE id = :id",
        merged,
    )


def record_match(
    connection: sqlite3.Connection,
    snapshot_id: int,
    store_path: str,
    name: str,
    version: str | None,
    advisory_id: str,
    source: str,
) -> None:
    connection.execute(
        "INSERT INTO matches"
        " (snapshot_id, store_path, name, version, advisory_id, source)"
        " VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT (snapshot_id, store_path, advisory_id) DO NOTHING",
        (snapshot_id, store_path, name, version, advisory_id, source),
    )


def advisory_ids(connection: sqlite3.Connection) -> dict[str, set[str]]:
    """Map alias/id -> set of advisories, for KEV and EPSS joins."""
    mapping: dict[str, set[str]] = {}
    for row in connection.execute("SELECT id, aliases FROM advisories"):
        mapping.setdefault(row["id"], set()).add(row["id"])
        for alias in (row["aliases"] or "").split(","):
            if alias:
                mapping.setdefault(alias, set()).add(row["id"])
    return mapping