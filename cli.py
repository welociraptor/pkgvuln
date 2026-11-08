"""Command line interface.

    pkgvuln sync     refresh KEV, EPSS (and NVD with --nvd)
    pkgvuln scan     run the matchers against the newest snapshot
    pkgvuln report   print the delta report
    pkgvuln run      refresh NVD, scan, enrich, report - for the systemd timer
    pkgvuln outdated compare the snapshot with the versions nixpkgs pins

Exit codes: 0 clean, 2 un-whitelisted findings, 3 only whitelisted findings.
``outdated`` exits 0 as well unless ``--fail-on-outdated`` is given; "an upgrade
exists" is information, not a failure.
``1`` is deliberately left to mean "crashed", so a traceback cannot be mistaken
for a successful scan that merely found nothing. (vulnix uses 1 for
"whitelisted only"; that collision is not worth inheriting.)
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__, db, fetch, match, outdated, report
from . import overrides as overrides_module
from .sources import epss, kev, nvd, osv, vulnix

DEFAULT_WHITELIST = "~/.config/pkgvuln/whitelist.toml"


def _resolve_snapshot(connection, requested: int | None):
    snapshot = (
        connection.execute(
            "SELECT id, taken_at FROM snapshots WHERE id = ?", (requested,)
        ).fetchone()
        if requested is not None
        else db.latest_snapshot(connection)
    )
    if snapshot is None:
        raise SystemExit(
            "error: no snapshot found in the database; run track-packages first"
        )
    return snapshot


def _whitelist_paths(args: argparse.Namespace) -> list[str]:
    if getattr(args, "no_whitelist", False):
        return []
    paths = list(getattr(args, "whitelist", None) or [])
    if not paths:
        paths = [DEFAULT_WHITELIST]
    return paths


def _sync_nvd(connection, args: argparse.Namespace) -> None:
    names = getattr(args, "archives", None) or nvd.archives(
        getattr(args, "years", nvd.YEARS)
    )
    try:
        counts = nvd.sync(connection, names)
    except fetch.FetchError as error:
        logging.warning("NVD sync failed: %s", error)
        return
    for name in names:
        count = counts.get(name, 0)
        status = "unchanged" if count == -1 else f"{count} advisories"
        print(f"nvd {name}: {status}")


def _sync_enrichment(connection) -> None:
    """KEV and EPSS: cheap, and applied to whatever advisories exist now."""
    for module in (kev, epss):
        try:
            module.sync(connection)
        except fetch.FetchError as error:
            logging.warning("%s sync failed: %s", module.__name__, error)


def _sync(connection, args: argparse.Namespace) -> None:
    if getattr(args, "nvd", False):
        _sync_nvd(connection, args)
    _sync_enrichment(connection)
    connection.commit()


def _scan(connection, args: argparse.Namespace) -> int:
    snapshot = _resolve_snapshot(connection, getattr(args, "snapshot", None))
    packages = db.snapshot_packages(connection, snapshot["id"])
    if not packages:
        raise SystemExit(f"error: snapshot #{snapshot['id']} has no packages")

    total = 0

    if getattr(args, "vulnix", False) or getattr(args, "vulnix_json", None):
        if getattr(args, "no_vulnix", False) and not getattr(args, "vulnix_json", None):
            pass
        else:
            try:
                result = vulnix.scan(
                    connection, snapshot["id"], packages, args.vulnix_json
                )
            except (vulnix.VulnixError, OSError) as error:
                logging.warning("vulnix source skipped: %s", error)
            else:
                total += result["matches"]
                print(
                    f"vulnix: {result['matches']} matches"
                    f" (covered {result['with_drv']}/{result['packages']} derivations;"
                    f" {result['without_drv']} have no .drv left)"
                )

    if not getattr(args, "no_nvd", False):
        try:
            entries = overrides_module.load(getattr(args, "overrides", None) or [])
            count = match.scan(connection, snapshot["id"], packages, entries)
        except Exception as error:  # never lose the whole scan to one source
            logging.warning("NVD/CPE source skipped: %s", error)
        else:
            total += count
            print(f"nvd: {count} matches")

    if not getattr(args, "no_osv", False):
        try:
            count = osv.scan(
                connection, snapshot["id"], packages,
                offline=getattr(args, "offline", False),
            )
        except Exception as error:  # network failures must not lose the scan
            logging.warning("OSV source skipped: %s", error)
        else:
            total += count
            print(f"osv: {count} matches")

    connection.commit()
    print(f"scan of snapshot #{snapshot['id']}: {total} matches recorded")
    return 0


def _report(connection, args: argparse.Namespace) -> int:
    snapshot = _resolve_snapshot(connection, getattr(args, "snapshot", None))
    data = report.build(connection, snapshot["id"], _whitelist_paths(args))
    if getattr(args, "json", False):
        print(report.format_json(data))
    else:
        print(
            report.format_text(
                data,
                limit=getattr(args, "limit", 20),
                show_masked=getattr(args, "show_whitelisted", False),
            )
        )
    return report.exit_code(data)


def cmd_sync(args: argparse.Namespace) -> int:
    connection = db.connect(args.db)
    try:
        _sync(connection, args)
    finally:
        connection.close()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    connection = db.connect(args.db)
    try:
        return _scan(connection, args)
    finally:
        connection.close()


def cmd_report(args: argparse.Namespace) -> int:
    connection = db.connect(args.db)
    try:
        return _report(connection, args)
    finally:
        connection.close()


def cmd_outdated(args: argparse.Namespace) -> int:
    connection = db.connect(args.db)
    try:
        snapshot = _resolve_snapshot(connection, args.snapshot)
        try:
            pin = outdated.resolve_pin(args.nixpkgs)
            data = outdated.build(
                connection,
                snapshot["id"],
                pin,
                system=args.system,
                refresh=args.refresh,
                verify=args.verify_store_paths,
            )
        except outdated.EvaluationError as error:
            raise SystemExit(f"error: {error}") from error
        if args.json:
            print(outdated.format_json(data))
        else:
            print(outdated.format_text(data, limit=args.limit))
        if args.fail_on_outdated and data["counts"][outdated.OUTDATED]:
            return report.FINDINGS
        return 0
    finally:
        connection.close()


def cmd_run(args: argparse.Namespace) -> int:
    connection = db.connect(args.db)
    try:
        # Order matters, twice over:
        #   1. NVD data has to exist *before* matching, otherwise the first run
        #      after install would report zero findings.
        #   2. KEV/EPSS are applied *after* the scan so advisories discovered by
        #      this very run get their scores.
        if getattr(args, "nvd", False):
            _sync_nvd(connection, args)
            connection.commit()
        _scan(connection, args)
        _sync_enrichment(connection)
        connection.commit()
        return _report(connection, args)
    finally:
        connection.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pkgvuln",
        description="Match Nix package snapshots against vulnerability advisories.",
    )
    parser.add_argument("--version", action="version", version=f"pkgvuln {__version__}")
    parser.add_argument(
        "--db",
        type=Path,
        default=db.default_db_path(),
        help="SQLite database written by track-packages (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        # SUPPRESS so a subcommand does not overwrite the value parsed before it.
        sub.add_argument("--db", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        sub.add_argument("-v", "--verbose", action="store_true", default=False)

    def add_scan_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--snapshot", type=int, help="snapshot id (default: newest)")
        sub.add_argument(
            "--vulnix",
            action="store_true",
            help="also run vulnix (sees only derivations whose .drv survives)",
        )
        sub.add_argument("--vulnix-json", metavar="FILE", help="ingest saved 'vulnix --json' output")
        sub.add_argument("--no-nvd", action="store_true", help="skip the NVD/CPE source")
        sub.add_argument(
            "-o",
            "--overrides",
            action="append",
            metavar="FILE",
            help="extra TOML with product/vendor facts (bundled overrides.toml is always used)",
        )
        sub.add_argument("--no-osv", action="store_true", help="skip OSV lookups")
        sub.add_argument("--offline", action="store_true", help="use cached OSV answers only")

    def add_report_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--json", action="store_true", help="machine readable output")
        sub.add_argument("-w", "--whitelist", action="append", metavar="FILE")
        sub.add_argument("--no-whitelist", action="store_true")
        sub.add_argument(
            "-s", "--show-whitelisted", action="store_true", help="list whitelisted findings"
        )
        sub.add_argument(
            "--limit", type=int, default=20, help="entries per section (default: %(default)s)"
        )

    def add_nvd_options(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--nvd", action="store_true", help="also refresh the NVD CVE feeds")
        sub.add_argument("--years", type=int, default=nvd.YEARS, help=argparse.SUPPRESS)
        sub.add_argument("--archives", nargs="+", help="explicit NVD archive names")

    sync_parser = subparsers.add_parser("sync", help="refresh advisory feeds")
    add_common(sync_parser)
    add_nvd_options(sync_parser)
    sync_parser.set_defaults(func=cmd_sync, nvd=False, archives=None)

    scan_parser = subparsers.add_parser("scan", help="run the matchers")
    add_common(scan_parser)
    add_scan_options(scan_parser)
    scan_parser.set_defaults(func=cmd_scan)

    report_parser = subparsers.add_parser("report", help="print the delta report")
    add_common(report_parser)
    report_parser.add_argument("--snapshot", type=int, help="snapshot id (default: newest)")
    add_report_options(report_parser)
    report_parser.set_defaults(func=cmd_report)

    run_parser = subparsers.add_parser("run", help="refresh NVD, scan, enrich, report")
    add_common(run_parser)
    add_scan_options(run_parser)
    add_report_options(run_parser)
    add_nvd_options(run_parser)
    run_parser.set_defaults(func=cmd_run, nvd=False, archives=None)

    outdated_parser = subparsers.add_parser(
        "outdated", help="compare the snapshot with the versions nixpkgs pins"
    )
    add_common(outdated_parser)
    outdated_parser.add_argument(
        "--snapshot", type=int, help="snapshot id (default: newest)"
    )
    outdated_parser.add_argument(
        "--nixpkgs",
        metavar="PATH",
        help="nixpkgs source to compare against (default: $PKGVULN_NIXPKGS, else"
        " the flake in the current directory)",
    )
    outdated_parser.add_argument(
        "--system", help="Nix system to evaluate for (default: current system)"
    )
    outdated_parser.add_argument(
        "--refresh",
        action="store_true",
        help="re-evaluate nixpkgs even if this pin is cached",
    )
    outdated_parser.add_argument(
        "--verify-store-paths",
        action="store_true",
        help="check candidates against the pin's outputs, so an alternate version"
        " line is not reported as outdated",
    )
    outdated_parser.add_argument("--json", action="store_true", help="machine readable output")
    outdated_parser.add_argument(
        "--limit", type=int, default=20, help="entries per section (default: %(default)s)"
    )
    outdated_parser.add_argument(
        "--fail-on-outdated",
        action="store_true",
        help="exit 2 when something is outdated",
    )
    outdated_parser.set_defaults(func=cmd_outdated)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if getattr(args, "verbose", False) else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if not hasattr(args, "db"):
        args.db = db.default_db_path()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())