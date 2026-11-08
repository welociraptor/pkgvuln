"""Snapshot installed Nix package versions into a SQLite database.

The snapshotter enumerates the closures of the NixOS system profile and the
current user's Nix profiles. For every store path it looks up the corresponding
derivation to recover the package name, version and store path, then appends a
snapshot to the shared database.

Run it repeatedly (e.g. from a systemd timer) to build a history that can be
queried with plain SQL:

    SELECT s.taken_at, p.name, p.version
      FROM packages AS p
      JOIN snapshots AS s ON s.id = p.snapshot_id
     WHERE p.name = 'python3'
     ORDER BY s.taken_at;

If a previous snapshot exists, a short summary of added/removed/updated
packages is printed after each run (disable with ``--no-diff``).
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from . import db

# Nix store paths look like /nix/store/<32 char hash>-<name>[-<output>].
STORE_HASH_RE = re.compile(r"^[0-9a-z]{32}-")

# Derivation names are usually "<pname>-<version>", where the version starts
# with a digit. Greedily take the shortest pname so that names like
# "python3.15-requests-2.32.3" split into "python3.15-requests" + "2.32.3".
VERSION_RE = re.compile(r"^(?P<name>.+?)-(?P<version>[0-9].*)$")

Package = tuple[str, str | None, str]

_nix_store: str | None = None


def find_nix_store() -> str:
    """Locate nix-store even when the PATH is minimal (systemd services)."""
    global _nix_store
    if _nix_store is not None:
        return _nix_store
    executable = shutil.which("nix-store")
    if not executable:
        for candidate in (
            "/run/current-system/sw/bin/nix-store",
            "/nix/var/nix/profiles/default/bin/nix-store",
        ):
            if os.access(candidate, os.X_OK):
                executable = candidate
                break
    if not executable:
        raise SystemExit("error: cannot find 'nix-store' on this system")
    _nix_store = executable
    return executable


def run_nix_store(args: list[str]) -> list[str]:
    """Run a read-only nix-store query and return its output lines."""
    command = [find_nix_store(), *args]
    try:
        completed = subprocess.run(command, capture_output=True, text=True)
    except OSError as error:
        raise SystemExit(f"error: failed to run {command[0]}: {error}") from error
    if completed.returncode != 0:
        raise SystemExit(
            f"error: {' '.join(command)} failed: {completed.stderr.strip()}"
        )
    return completed.stdout.splitlines()


def discover_roots() -> list[Path]:
    """Profiles whose closures make up the set of installed packages."""
    roots: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        real = os.path.realpath(path)
        if path.exists() and real not in seen:
            seen.add(real)
            roots.append(path)

    # The running system. Its closure contains everything the system installs.
    add(Path("/run/current-system"))

    # The current user's Nix profiles (nix profile / home-manager generations).
    profiles = Path.home() / ".local" / "state" / "nix" / "profiles"
    if profiles.is_dir():
        for entry in sorted(profiles.iterdir()):
            if entry.name.endswith("-link"):
                continue
            add(entry)

    add(Path.home() / ".nix-profile")
    return roots


def closure(root: Path) -> list[str]:
    """All store paths reachable from a profile, without the profile itself."""
    root_real = os.path.realpath(root)
    return [path for path in run_nix_store(["-qR", str(root)]) if path != root_real]


def deriver_map(store_paths: list[str]) -> dict[str, str]:
    """Map each store path to its .drv path (or "unknown-deriver")."""
    mapping: dict[str, str] = {}
    # Keep each invocation comfortably below the kernel's argument limit.
    for start in range(0, len(store_paths), 400):
        chunk = store_paths[start : start + 400]
        output = run_nix_store(["-q", "--deriver", *chunk])
        if len(output) != len(chunk):
            raise SystemExit("error: unexpected output from 'nix-store --deriver'")
        mapping.update(zip(chunk, output))
    return mapping


def split_derivation_name(store_path: str, deriver: str) -> Package:
    """Return (pname, version, full derivation name) for a store path."""
    if deriver and deriver != "unknown-deriver" and deriver.endswith(".drv"):
        basename = os.path.basename(deriver)[: -len(".drv")]
    else:
        # Fall back to the output path; split outputs may keep a suffix here.
        basename = os.path.basename(store_path)

    full_name = STORE_HASH_RE.sub("", basename)
    match = VERSION_RE.match(full_name)
    if match:
        return match.group("name"), match.group("version"), full_name
    return full_name, None, full_name


def collect_packages(roots: list[Path]) -> dict[str, Package]:
    """Return {derivation: (name, version, store_path)} for all roots."""
    packages: dict[str, Package] = {}
    for root in roots:
        store_paths = closure(root)
        if not store_paths:
            continue
        derivers = deriver_map(store_paths)
        for store_path in store_paths:
            name, version, full_name = split_derivation_name(
                store_path, derivers.get(store_path, "")
            )
            packages.setdefault(full_name, (name, version, store_path))
    return packages


def package_map(connection: sqlite3.Connection, snapshot_id: int) -> dict[str, str | None]:
    rows = connection.execute(
        "SELECT name, version FROM packages WHERE snapshot_id = ?", (snapshot_id,)
    )
    return {name: version for name, version in rows}


def record_snapshot(
    db_path: Path, packages: dict[str, Package]
) -> tuple[int, str, int | None, str | None, dict[str, list[str]]]:
    connection = db.connect(db_path)
    try:
        with connection:
            cursor = connection.execute("INSERT INTO snapshots DEFAULT VALUES")
            snapshot_id = cursor.lastrowid
            connection.executemany(
                "INSERT INTO packages"
                " (snapshot_id, name, version, derivation, store_path)"
                " VALUES (?, ?, ?, ?, ?)",
                [
                    (snapshot_id, name, version, full_name, store_path)
                    for full_name, (name, version, store_path) in packages.items()
                ],
            )

        taken_at = connection.execute(
            "SELECT taken_at FROM snapshots WHERE id = ?", (snapshot_id,)
        ).fetchone()[0]
        previous = db.previous_snapshot(connection, snapshot_id)

        changes: dict[str, list[str]] = {"added": [], "removed": [], "updated": []}
        if previous is not None:
            previous_id = previous["id"]
            old = package_map(connection, previous_id)
            new = package_map(connection, snapshot_id)
            changes["added"] = sorted(set(new) - set(old))
            changes["removed"] = sorted(set(old) - set(new))
            changes["updated"] = sorted(
                name for name in set(new) & set(old) if new[name] != old[name]
            )
            return snapshot_id, taken_at, previous_id, previous["taken_at"], changes

        return snapshot_id, taken_at, None, None, changes
    finally:
        connection.close()


def print_changes(
    changes: dict[str, list[str]], previous_id: int, previous_taken_at: str, limit: int = 20
) -> None:
    if not any(changes.values()):
        print(f"No changes since snapshot #{previous_id} ({previous_taken_at}).")
        return

    print(f"Changes since snapshot #{previous_id} ({previous_taken_at}):")
    for label, names in (
        ("added", changes["added"]),
        ("removed", changes["removed"]),
        ("updated", changes["updated"]),
    ):
        if not names:
            continue
        print(f"  {label}: {len(names)}")
        for name in names[:limit]:
            print(f"    {name}")
        if len(names) > limit:
            print(f"    ... and {len(names) - limit} more")