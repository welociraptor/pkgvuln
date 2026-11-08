"""Map a derivation name to (ecosystem, package, version) for OSV.

Deliberately conservative. Every mapping that is guessed rather than known is a
false positive generator, so this module only maps the case it can decide
mechanically - ``python3.14-<pypi-name>`` - and returns None for everything
else. Phase 3 adds npm/crates.io/Go behind a ``--ecosystem-map`` override file.

There is no ``nixpkgs`` ecosystem in OSV (verified: ``invalid ecosystem``), so
this translation is unavoidable: Nix names carry the interpreter prefix, PyPI
names do not.
"""

from __future__ import annotations

import re

from .nixver import upstream_version

# python3.14-foo, python3-foo, python2.7-foo, python-foo
_PYTHON_PREFIX = re.compile(r"^python(?:[23](?:\.\d+)?)?-(?P<rest>.+)$")

_KNOWN_ECOSYSTEMS = ("PyPI",)


def canonicalise_pypi(name: str) -> str:
    """PEP 503 normalisation; OSV matches PyPI names case-insensitively."""
    return re.sub(r"[-_.]+", "-", name).lower()


def strip_output_suffix(name: str) -> str:
    """Remove the ``_fish-completions``-style output marker from a name."""
    return re.sub(r"_(?:fish-completions|fish_completions)$", "", name)


def osv_coordinates(
    name: str, version: str | None
) -> tuple[str, str, str] | None:
    """Return (ecosystem, package, version) or None if we cannot map it."""
    base = strip_output_suffix(name)
    match = _PYTHON_PREFIX.match(base)
    if match is None:
        return None
    package = strip_output_suffix(match.group("rest"))
    # A remainder starting with a digit is a version fragment, not a package
    # name (e.g. the "python3-3.15.0_fish-completions" derivation).
    if not package or package[0].isdigit():
        return None
    release = upstream_version(version)
    if release is None:
        return None
    return ("PyPI", canonicalise_pypi(package), release)


def ecosystem_supported(ecosystem: str) -> bool:
    return ecosystem in _KNOWN_ECOSYSTEMS