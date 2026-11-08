"""Version handling: Nix semantics, and the bits nixpkgs adds on top.

Version strings in the Nix store are not the same strings the upstream project
or the NVD publish:

* ``2.4.2-r3`` - the ``-rN`` suffix is a nixpkgs rebuild counter, upstream
  knows only ``2.4.2``.
* ``3.15.0_fish-completions`` - ``_name`` marks a non-default derivation
  output, not a version component.
* ``unstable-2024-05-06`` - no upstream version at all; structurally
  unmatchable, so it is reported as such instead of guessed at.
"""

from __future__ import annotations

import re

_SEPARATORS = ".-"
_REVISION_SUFFIX = re.compile(r"-(?:r|rev|patch)\d+$")
_OUTPUT_SUFFIX = re.compile(
    r"_(?:fish-completions|fish_completions|dev|man|doc|info|out|lib|bin|debug)$"
)
_DATED = re.compile(r"^\d{4}-\d{2}-\d{2}")
_UNMATCHABLE_PREFIXES = ("unstable", "git-", "master", "head-", "HEAD")
_DOTTED_NUMERIC = re.compile(r"^\d+(?:\.\d+)*$")

# nixpkgs builds *variants* of a package whose derivation name keeps the pname
# and version and appends a marker: ``coreutils-full-9.12_fish-completions``,
# ``alsa-firmware-1.2.4-zstd``, ``linux-7.3.1-modules``, ``perl-5.42.3-env``.
# The marker is not part of the upstream release, so it must not take part in a
# version comparison - but it *is* part of what the snapshotter parses out of
# the store path, so it arrives here attached to the version.
_VARIANT_SUFFIX = re.compile(
    r"(?:[-_]("
    r"fish[-_]completions|zstd|env|modules|gsettings[-_]schemas"
    r"|dev|man|doc|info|out|lib|bin|debug"
    r"))+$"
)


def _next_component(text: str, index: int) -> tuple[str, int]:
    """Port of Nix's ``nextComponent`` (src/libstore/names.cc)."""
    end = len(text)
    while index < end and text[index] in _SEPARATORS:
        index += 1
    if index >= end:
        return "", end
    start = index
    if text[index].isdigit():
        while index < end and text[index].isdigit():
            index += 1
    else:
        while index < end and not text[index].isdigit() and text[index] not in _SEPARATORS:
            index += 1
    return text[start:index], index


def _as_int(component: str) -> int | None:
    # Nix accepts leading zeros here ("007" compares equal to "7").
    return int(component) if component.isdigit() else None


def _components_lt(left: str, right: str) -> bool:
    """Port of Nix's ``componentsLT`` (src/libstore/names.cc)."""
    left_num = _as_int(left)
    right_num = _as_int(right)
    if left_num is not None and right_num is not None:
        return left_num < right_num
    if left == "" and right_num is not None:
        return True
    if left == "pre" and right != "pre":
        return True
    if right == "pre":
        return False
    if right_num is not None:
        # "2.3a" < "2.3.1"
        return True
    if left_num is not None:
        return False
    return left < right


def compare(left: str, right: str) -> int:
    """``builtins.compareVersions``: -1, 0 or 1."""
    index_left = index_right = 0
    while index_left < len(left) or index_right < len(right):
        component_left, index_left = _next_component(left, index_left)
        component_right, index_right = _next_component(right, index_right)
        if _components_lt(component_left, component_right):
            return -1
        if _components_lt(component_right, component_left):
            return 1
    return 0


def _dotted_key(version: str) -> tuple[int, ...] | None:
    if not _DOTTED_NUMERIC.match(version):
        return None
    parts = [int(part) for part in version.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def compare_release(left: str, right: str) -> int:
    """Compare as an upstream release rather than as a Nix version.

    Identical to :func:`compare` except that purely dotted numeric versions
    treat trailing zero components as insignificant, which is what upstream and
    the CPE data assume: ``153.0`` and ``153.0.0`` are the same release.
    """
    left_key = _dotted_key(left)
    right_key = _dotted_key(right)
    if left_key is not None and right_key is not None:
        return (left_key > right_key) - (left_key < right_key)
    return compare(left, right)


def upstream_version(version: str | None) -> str | None:
    """Return the version the upstream project would publish, or None.

    None means "this derivation cannot be matched against upstream advisories"
    (unstable snapshots, date-stamped builds), which callers must treat as a
    skip rather than as "not vulnerable".
    """
    if not version:
        return None
    candidate = version.strip()
    if not candidate:
        return None
    if candidate.startswith(_UNMATCHABLE_PREFIXES) or _DATED.match(candidate):
        return None
    candidate = _OUTPUT_SUFFIX.sub("", candidate)
    candidate = _REVISION_SUFFIX.sub("", candidate)
    return candidate or None


def strip_variants(version: str | None) -> str | None:
    """Drop derivation-variant markers from the end of a version string.

    Only for *comparisons* ("is there something newer?"): two derivations that
    differ only by the marker are the same upstream release, so
    ``9.12_fish-completions`` must compare equal to ``9.12`` rather than newer.
    :func:`upstream_version` is deliberately left alone - it answers a
    different question and its output feeds CPE matching.
    """
    if not version:
        return None
    candidate = version.strip()
    stripped = _VARIANT_SUFFIX.sub("", candidate)
    return stripped or candidate


def in_range(
    version: str,
    start_incl: str | None = None,
    start_excl: str | None = None,
    end_incl: str | None = None,
    end_excl: str | None = None,
) -> bool:
    """Evaluate a CPE version range (``versionStart*``/``versionEnd*``)."""
    if start_incl and compare_release(version, start_incl) < 0:
        return False
    if start_excl and compare_release(version, start_excl) <= 0:
        return False
    if end_incl and compare_release(version, end_incl) > 0:
        return False
    if end_excl and compare_release(version, end_excl) >= 0:
        return False
    return True