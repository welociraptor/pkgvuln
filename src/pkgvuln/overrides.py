"""Curated overrides: how Nix package names map onto NVD vendor/product names.

The data lives in ``overrides.toml`` next to this file (see the comments there
for why each entry exists). Loading is deliberately dumb: TOML in, dicts out,
with a user file able to add to or override the bundled one.
"""

from __future__ import annotations

import logging
import tomllib
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_PATH = Path(__file__).with_name("overrides.toml")


def _read(path: Path) -> dict[str, dict]:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, tomllib.TOMLDecodeError) as error:
        log.warning("cannot read overrides %s: %s", path, error)
        return {}
    entries: dict[str, dict] = {}
    for pname, values in data.items():
        if not isinstance(values, dict):
            log.warning("overrides %s: [%s] is not a table", path, pname)
            continue
        entry: dict = {}
        products = values.get("product")
        if isinstance(products, str):
            products = [products]
        if products:
            entry["products"] = [str(p).lower() for p in products]
        vendors = values.get("vendor")
        if isinstance(vendors, str):
            vendors = [vendors]
        if vendors:
            entry["vendors"] = {str(v).lower() for v in vendors}
        if entry:
            entries[pname.lower()] = entry
    return entries


def load(extra_paths=()) -> dict[str, dict]:
    """Bundled overrides, then each extra file (later files win per key)."""
    entries = _read(DEFAULT_PATH)
    for path in extra_paths:
        if path is None:
            continue
        override = _read(Path(path).expanduser())
        for pname, entry in override.items():
            entries.setdefault(pname, {}).update(entry)
    return entries


def products_for(entries: dict, pname: str) -> list[str]:
    return list((entries.get(pname.lower()) or {}).get("products") or [])


def vendors_for(entries: dict, pname: str) -> set[str] | None:
    """Vendors allowed for this pname, or None when unconstrained."""
    return (entries.get(pname.lower()) or {}).get("vendors")