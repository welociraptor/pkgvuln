"""Vulnerability scanning for the Nix package snapshots from track-packages.py.

The snapshot side of the database (tables ``snapshots`` and ``packages``) is
owned by ``track-packages.py``. Everything here lives in additional tables in
the same file, created on demand, so the two programs stay independent.
"""

__version__ = "0.1.0"