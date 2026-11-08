"""Vulnerability scanning and version snapshots for Nix packages.

:mod:`pkgvuln.snapshot` records the installed package versions, and the rest of
the package matches them against vulnerability advisories in the same SQLite
database.
"""

__version__ = "0.1.0"