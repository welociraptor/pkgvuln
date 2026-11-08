"""Advisory sources.

Each module exposes ``scan(connection, snapshot_id, packages, ...) -> int`` and
writes rows into the shared ``advisories``/``matches`` tables. Adding a source
means adding a module and one line in :mod:`pkgvuln.cli`.
"""
