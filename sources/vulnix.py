"""Ingest findings from ``vulnix --json`` - optional, partial coverage.

vulnix parses ``.drv`` files, so it can only see derivations whose derivation
file still exists. On this system that is 602 of 1095 (44% were garbage
collected), and vulnix skips the rest *silently*, which looks exactly like "not
vulnerable". That is why this source is opt-in and why it reports its coverage,
and why the default matcher is :mod:`pkgvuln.match`, which needs no derivations.

``--no-requisites`` is used so the derivations examined are exactly the ones the
snapshot recorded, instead of the build closure of each deriver (which would
pull in build-time-only inputs and report e.g. binutils for everything).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess

from .. import db

_log = logging.getLogger(__name__)

SOURCE = "vulnix"
# vulnix returns 0 (clean), 1 (only whitelisted findings) and 2 (active
# advisories). None of those are errors for us.
_OK_EXIT_CODES = (0, 1, 2)
_MAX_ARG_BYTES = 100_000


class VulnixError(RuntimeError):
    pass


def find_executable() -> str:
    executable = shutil.which("vulnix")
    if executable:
        return executable
    for candidate in (
        "/run/current-system/sw/bin/vulnix",
        "/nix/var/nix/profiles/default/bin/vulnix",
    ):
        if os.access(candidate, os.X_OK):
            return candidate
    raise VulnixError(
        "cannot find 'vulnix'; install pkgs.vulnix or pass --vulnix-json"
    )


def run_vulnix(store_paths: list[str], executable: str | None = None) -> list[dict]:
    """Run vulnix over the given store paths and return its JSON findings."""
    executable = executable or find_executable()
    environment = dict(os.environ)
    # vulnix refuses to run without a UTF-8 locale (it parses .drv files).
    environment.setdefault("LANG", "C.UTF-8")

    items: list[dict] = []
    for chunk in _chunks(store_paths):
        command = [executable, "--json", "--no-requisites", *chunk]
        _log.info("running vulnix over %d store paths", len(chunk))
        completed = subprocess.run(
            command, capture_output=True, text=True, env=environment
        )
        if completed.returncode not in _OK_EXIT_CODES:
            raise VulnixError(
                f"vulnix failed with exit code {completed.returncode}: "
                f"{completed.stderr.strip()[:500]}"
            )
        if completed.stderr.strip():
            _log.debug("vulnix stderr: %s", completed.stderr.strip()[:2000])
        items.extend(json.loads(completed.stdout or "[]"))
    return items


def _chunks(paths: list[str]) -> list[list[str]]:
    chunks: list[list[str]] = []
    current: list[str] = []
    size = 0
    for path in dict.fromkeys(paths):
        if current and size + len(path) > _MAX_ARG_BYTES:
            chunks.append(current)
            current, size = [], 0
        current.append(path)
        size += len(path) + 1
    if current:
        chunks.append(current)
    return chunks


def load_json(path: str) -> list[dict]:
    if path == "-":
        return json.load(os.sys.stdin)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _cvss(item: dict, cve: str) -> float | None:
    value = (item.get("cvssv3_basescore") or {}).get(cve)
    return float(value) if value else None


def ingest(
    connection,
    snapshot_id: int,
    packages: list,
    items: list[dict],
) -> int:
    """Record vulnix findings as matches. Returns the number of matches."""
    store_path_by_name = {}
    for package in packages:
        store_path_by_name[package["derivation"]] = package["store_path"]

    recorded = 0
    for item in items:
        vulnerable = item.get("affected_by") or []
        if not vulnerable:
            continue
        store_path = store_path_by_name.get(item.get("name"), item.get("derivation"))
        name = item.get("pname") or item.get("name")
        version = item.get("version")
        for advisory_id in vulnerable:
            db.record_advisory(
                connection,
                {
                    "id": advisory_id,
                    "source": SOURCE,
                    "cvss_v3": _cvss(item, advisory_id),
                    "description": (item.get("description") or {}).get(advisory_id),
                },
            )
            db.record_match(
                connection,
                snapshot_id,
                store_path,
                name,
                version,
                advisory_id,
                SOURCE,
            )
            recorded += 1
    return recorded


def derivers(store_paths: list[str]) -> dict[str, str]:
    """Map store path -> .drv path using the Nix database only."""
    executable = shutil.which("nix-store") or "/run/current-system/sw/bin/nix-store"
    mapping: dict[str, str] = {}
    for start in range(0, len(store_paths), 400):
        chunk = store_paths[start : start + 400]
        output = subprocess.run(
            [executable, "-q", "--deriver", *chunk], capture_output=True, text=True
        )
        if output.returncode != 0:
            raise VulnixError(f"nix-store --deriver failed: {output.stderr.strip()}")
        mapping.update(zip(chunk, output.stdout.splitlines()))
    return mapping


def surviving(store_paths: list[str]) -> list[str]:
    """Store paths whose derivation file still exists in the store."""
    mapping = derivers(store_paths)
    return [
        path
        for path in store_paths
        if mapping.get(path, "").endswith(".drv") and os.path.exists(mapping[path])
    ]


def scan(connection, snapshot_id: int, packages: list, json_path=None) -> dict:
    """Fetch (or load) vulnix findings and store them as matches."""
    if json_path:
        items = load_json(json_path)
        scan_paths = [package["store_path"] for package in packages]
    else:
        scan_paths = surviving([package["store_path"] for package in packages])
        missing = len(packages) - len(scan_paths)
        if missing:
            _log.warning(
                "%d of %d derivations have no .drv left and cannot be scanned by"
                " vulnix; their status is unknown, not clean",
                missing,
                len(packages),
            )
        items = run_vulnix(scan_paths) if scan_paths else []
    return {
        "matches": ingest(connection, snapshot_id, packages, items),
        "packages": len(packages),
        "with_drv": len(scan_paths),
        "without_drv": len(packages) - len(scan_paths),
    }