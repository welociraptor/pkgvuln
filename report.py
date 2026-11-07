"""Turn matches into a delta report.

The point of scanning a *history* of snapshots instead of the current system is
that a finding can be classified by when it appeared:

``initial``
    there is no previous snapshot to compare against, so nothing can be
    attributed to an update yet.
``introduced``
    the affected store path is new in this snapshot - this update brought it in.
``carried``
    the package was already installed in the previous snapshot and is still
    unfixed - either it was never noticed before, or the advisory is new.
``fixed``
    the package name is still installed, but the previous snapshot matched an
    advisory on it that no longer matches - the upgrade cleared it.

Exit codes: 0 = clean, 2 = un-whitelisted findings remain, 3 = only
whitelisted findings. ``1`` is left unused on purpose: that is what a Python
traceback exits with, and "only whitelisted findings" must never look like a
crash in a systemd unit.
"""

from __future__ import annotations

import datetime
import json
import logging
import tomllib
from pathlib import Path

_log = logging.getLogger(__name__)

INITIAL = "initial"
INTRODUCED = "introduced"
CARRIED = "carried"

EPSS_THRESHOLD = 0.1
CVSS_THRESHOLD = 7.0


def load_whitelist(paths) -> list[dict]:
    """Load TOML whitelists. Sections are package names, values are rules."""
    rules: list[dict] = []
    for path in paths:
        if path is None:
            continue
        file = Path(path).expanduser()
        if not file.exists():
            _log.info("whitelist %s not found, skipping", file)
            continue
        with file.open("rb") as handle:
            data = tomllib.load(handle)
        for name, options in data.items():
            if not isinstance(options, dict):
                _log.warning("whitelist %s: [%s] is not a table", file, name)
                continue
            rules.append(
                {
                    "name": name,
                    "cves": set(options.get("cve") or []),
                    "until": options.get("until"),
                    "issue_url": options.get("issue_url"),
                    "comment": options.get("comment"),
                    "source": str(file),
                }
            )
    return rules


def _split_name_version(full_name: str) -> tuple[str, str | None]:
    """Split "python3.14-requests-2.32.3" into ("python3.14-requests", "2.32.3")."""
    import re

    match = re.match(r"^(?P<name>.+?)-(?P<version>[0-9].*)$", full_name)
    return (match.group("name"), match.group("version")) if match else (full_name, None)


def _rule_applies(rule: dict, name: str, version: str | None, advisory_id: str, today: datetime.date) -> bool:
    if rule["until"]:
        try:
            expiry = datetime.date.fromisoformat(rule["until"])
        except ValueError:
            _log.warning("whitelist %s: bad until date %r", rule["source"], rule["until"])
            expiry = None
        if expiry is not None and today >= expiry:
            return False
    if rule["name"] != "*" and rule["name"] != name:
        # The section may name a version to confine the rule to one release.
        rule_name, rule_version = _split_name_version(rule["name"])
        if rule_name != name or rule_version != version:
            return False
    if rule["cves"] and advisory_id not in rule["cves"]:
        # A new CVE on a whitelisted package resurfaces, by design.
        return False
    return True


def priority(advisory: dict) -> str:
    if advisory["kev"]:
        return "exploited"
    if (advisory["epss"] or 0.0) >= EPSS_THRESHOLD:
        return "high"
    if (advisory["cvss_v3"] or 0.0) >= CVSS_THRESHOLD:
        return "high"
    if (advisory["severity"] or "") in ("CRITICAL", "HIGH"):
        return "high"
    return "normal"


_PRIORITY_ORDER = {"exploited": 0, "high": 1, "normal": 2}


def _advisory_payload(row) -> dict:
    return {
        "id": row["advisory_id"],
        "priority": priority(row),
        "kev": bool(row["kev"]),
        "epss": row["epss"],
        "cvss_v3": row["cvss_v3"],
        "severity": row["severity"],
        "summary": row["summary"],
        "aliases": [a for a in (row["aliases"] or "").split(",") if a],
        "source": row["source"],
        "first_seen": row["first_seen"],
    }


def _canonical_id(advisory: dict) -> str:
    """The CVE id for an advisory if it has one, else the advisory's own id."""
    for candidate in [advisory["id"], *advisory["aliases"]]:
        if candidate.startswith("CVE-"):
            return candidate
    return advisory["id"]


def dedupe(advisories: list[dict]) -> list[dict]:
    """Collapse advisories that are the same bug under different identifiers.

    OSV reports one issue as GHSA-x plus PYSEC-y plus CVE-z. Counting all three
    would triple the numbers and hide the real severity, so they are grouped by
    CVE id (or own id when there is no CVE) and the best-described member is
    kept; the others are recorded in ``duplicates``.
    """
    groups: dict[str, list[dict]] = {}
    for advisory in advisories:
        groups.setdefault(_canonical_id(advisory), []).append(advisory)

    merged: list[dict] = []
    for members in groups.values():
        members.sort(
            key=lambda a: (
                _PRIORITY_ORDER[a["priority"]],
                -(a["cvss_v3"] or 0.0),
                a["id"],
            )
        )
        primary = dict(members[0])
        identifiers = {
            identifier
            for member in members
            for identifier in [member["id"], *member["aliases"]]
        } - {primary["id"]}
        primary["aliases"] = sorted(identifiers)
        if len(members) > 1:
            primary["duplicates"] = sorted(member["id"] for member in members[1:])
            primary["priority"] = min(
                (member["priority"] for member in members),
                key=lambda name: _PRIORITY_ORDER[name],
            )
        merged.append(primary)
    return merged


def build(connection, snapshot_id: int, whitelist_paths=()) -> dict:
    """Assemble the report data for one snapshot."""
    from . import db

    snapshot = connection.execute(
        "SELECT id, taken_at FROM snapshots WHERE id = ?", (snapshot_id,)
    ).fetchone()
    previous = db.previous_snapshot(connection, snapshot_id)
    rules = load_whitelist(whitelist_paths)
    today = datetime.date.today()

    current_packages = db.snapshot_packages(connection, snapshot_id)
    current_names = {package["name"] for package in current_packages}
    current_paths = {package["store_path"] for package in current_packages}
    previous_packages = (
        db.snapshot_packages(connection, previous["id"]) if previous else []
    )
    previous_paths = {package["store_path"] for package in previous_packages}

    rows = list(
        connection.execute(
            "SELECT m.store_path, m.name, m.version, m.advisory_id, m.source,"
            " a.kev, a.epss, a.cvss_v3, a.severity, a.summary, a.aliases, a.first_seen"
            " FROM matches m LEFT JOIN advisories a ON a.id = m.advisory_id"
            " WHERE m.snapshot_id = ?",
            (snapshot_id,),
        )
    )

    current: dict[str, dict] = {}
    masked: dict[str, dict] = {}
    for row in rows:
        payload = _advisory_payload(row)
        if previous is None:
            classification = INITIAL
        elif row["store_path"] not in previous_paths:
            classification = INTRODUCED
        else:
            classification = CARRIED
        target = current
        for rule in rules:
            if _rule_applies(rule, row["name"], row["version"], row["advisory_id"], today):
                payload["whitelist"] = {
                    "source": rule["source"],
                    "until": rule["until"],
                    "issue_url": rule["issue_url"],
                    "comment": rule["comment"],
                }
                target = masked
                break
        entry = target.setdefault(
            row["store_path"],
            {
                "store_path": row["store_path"],
                "name": row["name"],
                "version": row["version"],
                "classification": classification,
                "advisories": [],
            },
        )
        entry["advisories"].append(payload)

    fixed = []
    if previous is not None:
        previous_matches = list(
            connection.execute(
                "SELECT name, advisory_id FROM matches WHERE snapshot_id = ?",
                (previous["id"],),
            )
        )
        current_by_name: dict[str, set[str]] = {}
        for row in rows:
            current_by_name.setdefault(row["name"], set()).add(row["advisory_id"])
        gone: dict[str, set[str]] = {}
        for row in previous_matches:
            if row["name"] not in current_names:
                continue  # package removed entirely, not fixed by an upgrade
            if row["advisory_id"] in current_by_name.get(row["name"], set()):
                continue
            gone.setdefault(row["name"], set()).add(row["advisory_id"])
        for name, advisory_ids in sorted(gone.items()):
            for advisory_id in sorted(advisory_ids):
                advisory = connection.execute(
                    "SELECT id, summary FROM advisories WHERE id = ?", (advisory_id,)
                ).fetchone()
                fixed.append(
                    {
                        "name": name,
                        "advisory_id": advisory_id,
                        "summary": advisory["summary"] if advisory else None,
                    }
                )

    for entry in current.values():
        entry["advisories"] = dedupe(entry["advisories"])
        entry["advisories"].sort(
            key=lambda a: (_PRIORITY_ORDER[a["priority"]], -(a["cvss_v3"] or 0.0), a["id"])
        )
        entry["worst"] = entry["advisories"][0]["priority"]
    for entry in masked.values():
        entry["advisories"] = dedupe(entry["advisories"])

    return {
        "snapshot": {"id": snapshot_id, "taken_at": snapshot["taken_at"]},
        "previous": dict(previous) if previous else None,
        "new_store_paths": len(current_paths - previous_paths) if previous else len(current_paths),
        "current": sorted(current.values(), key=lambda e: (e["name"], e["version"] or "")),
        "masked": sorted(masked.values(), key=lambda e: (e["name"], e["version"] or "")),
        "fixed": fixed,
    }


def _format_advisory(advisory: dict) -> str:
    bits = [f"{advisory['id']:<20}"]
    if advisory["cvss_v3"]:
        bits.append(f"cvss {advisory['cvss_v3']:.1f}")
    elif advisory["severity"]:
        bits.append(f"{advisory['severity'].lower():<9}")
    else:
        bits.append(f"{'-':<9}")
    if advisory["kev"]:
        bits.append("CISA KEV")
    elif (advisory["epss"] or 0.0) >= 0.001:
        bits.append(f"epss {advisory['epss']:.3f}")
    if advisory["aliases"]:
        bits.append("(" + ", ".join(advisory["aliases"][:2]) + ")")
    return "  ".join(bits)


def format_text(report: dict, limit: int = 20, show_masked: bool = False) -> str:
    lines: list[str] = []
    active = report["current"]
    snapshot = report["snapshot"]

    if not active and not report["masked"] and not report["fixed"]:
        return f"Snapshot #{snapshot['id']}: found no advisories."

    lines.append(
        f"Snapshot #{snapshot['id']} ({snapshot['taken_at']}): "
        f"{len(active)} affected packages, {len(report['fixed'])} fixed since "
        f"{'snapshot #' + str(report['previous']['id']) if report['previous'] else 'ever'}"
    )

    buckets = (
        (INITIAL, "affected packages in the first snapshot"),
        (INTRODUCED, "introduced by this snapshot"),
        (CARRIED, "carried over from the previous snapshot"),
    )
    for classification, label in buckets:
        entries = [e for e in active if e["classification"] == classification]
        if not entries:
            continue
        lines.append("")
        lines.append(f"{len(entries)} {label}:")
        for entry in entries[:limit]:
            title = f"{entry['name']}-{entry['version']}" if entry["version"] else entry["name"]
            marker = "!" if entry["worst"] == "exploited" else " "
            lines.append(f" {marker} {title}  ({len(entry['advisories'])} advisory(ies))")
            for advisory in entry["advisories"]:
                lines.append("     " + _format_advisory(advisory))
        if len(entries) > limit:
            lines.append(f"   ... and {len(entries) - limit} more")

    if report["fixed"]:
        lines.append("")
        lines.append(f"{len(report['fixed'])} advisory(ies) cleared by upgrades:")
        for item in report["fixed"][:limit]:
            lines.append(f"   {item['advisory_id']:<20} {item['name']}")
        if len(report["fixed"]) > limit:
            lines.append(f"   ... and {len(report['fixed']) - limit} more")

    if report["masked"]:
        lines.append("")
        masked_count = sum(len(e["advisories"]) for e in report["masked"])
        lines.append(
            f"{masked_count} advisory(ies) on {len(report['masked'])} package(s) whitelisted"
            + ("" if show_masked else " (--show-whitelisted to list)")
        )
        if show_masked:
            for entry in report["masked"][:limit]:
                title = f"{entry['name']}-{entry['version']}" if entry["version"] else entry["name"]
                lines.append(f"   {title}")
                for advisory in entry["advisories"]:
                    expiry = (advisory.get("whitelist") or {}).get("until")
                    lines.append(
                        f"     {_format_advisory(advisory)}"
                        + (f"  until {expiry}" if expiry else "")
                    )

    return "\n".join(lines)


def format_json(report: dict) -> str:
    return json.dumps(report, indent=1, sort_keys=False)


CLEAN = 0
WHITELISTED_ONLY = 3
FINDINGS = 2


def exit_code(report: dict) -> int:
    if report["current"]:
        return FINDINGS
    if report["masked"]:
        return WHITELISTED_ONLY
    return CLEAN