"""Command line interface.

    pkgvuln sync     refresh KEV, EPSS (and NVD with --nvd)
    pkgvuln scan     run the matchers against the newest snapshot
    pkgvuln report   print the delta report for the newest snapshot
    pkgvuln run      scan + sync + report, for the systemd timer
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__, db, match, report
from .sources import epss, kev, nvd, osv, vulnix

DEFAULT_WHITELIST = "~/.config/pkgvuln/whitelist.toml"


def _log_level(args: argparse.Namespace) -> int:
    return logging.INFO if args.verbose else logging.WARNING


def _open(args: argparse.Namespace):
    connection = db.connect(args.db)
    return connection


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
    if args.no_whitelist:
        return []
    paths = list(args.whitelist or [])
    if not paths and DEFAULT_WHITELIST:
        paths = [DEFAULT_WHITELIST]
    return paths


def cmd_sync(args: argparse.Namespace) -> int:
    connection = _open(args)
    try:
        if args.nvd:
            names = args.archives or nvd.archives(args.years)
            counts = nvd.sync(connection, names)
            for name in names:
                count = counts.get(name, 0)
                status = "unchanged" if count == -1 else f"{count} advisories"
                print(f"nvd {name}: {status}")
        kev.sync(connection)
        epss.sync(connection)
        connection.commit()
    finally:
        connection.close()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    if not hasattr(args, "vulnix"):
        args.vulnix = False
    connection = _open(args)
    try:
        snapshot = _resolve_snapshot(connection, args.snapshot)
        packages = db.snapshot_packages(connection, snapshot["id"])
        if not packages:
            raise SystemExit(f"error: snapshot #{snapshot['id']} has no packages")

        total = 0
        if args.vulnix or args.vulnix_json:
            if args.no_vulnix:
                args.vulnix = False
            connection.execute(
                "DELETE FROM matches WHERE snapshot_id = ? AND source = ?",
                (snapshot["id"], vulnix.SOURCE),
            )
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

        if not args.no_nvd:
            try:
                count = match.scan(connection, snapshot["id"], packages)
            except Exception as error:  # never lose the whole scan to one source
                logging.warning("NVD/CPE source skipped: %s", error)
            else:
                total += count
                print(f"nvd: {count} matches")

        if not args.no_osv:
            connection.execute(
                "DELETE FROM matches WHERE snapshot_id = ? AND source = ?",
                (snapshot["id"], osv.SOURCE),
            )
            try:
                count = osv.scan(
                    connection, snapshot["id"], packages, offline=args.offline
                )
            except Exception as error:  # network failures must not lose the scan
                logging.warning("OSV source skipped: %s", error)
            else:
                total += count
                print(f"osv: {count} matches")

        connection.commit()
        print(f"scan of snapshot #{snapshot['id']}: {total} matches recorded")
    finally:
        connection.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    connection = _open(args)
    try:
        snapshot = _resolve_snapshot(connection, args.snapshot)
        data = report.build(connection, snapshot["id"], _whitelist_paths(args))
    finally:
        connection.close()

    if args.json:
        print(report.format_json(data))
    else:
        print(report.format_text(data, limit=args.limit, show_masked=args.show_whitelisted))
    return report.exit_code(data)


def cmd_run(args: argparse.Namespace) -> int:
    # Scan first: KEV and EPSS are applied to the advisories that exist, so
    # syncing before the scan would leave newly found advisories unenriched
    # until the next run.
    cmd_scan(args)
    cmd_sync(args)
    return cmd_report(args)


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
    parser.add_argument("-v", "--verbose", action="store_true", help="more logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--db", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        sub.add_argument("-v", "--verbose", action="store_true", default=False)

    sync_parser = subparsers.add_parser("sync", help="refresh advisory feeds")
    add_common(sync_parser)
    sync_parser.add_argument("--nvd", action="store_true", help="also refresh the NVD CVE feeds")
    sync_parser.add_argument("--years", type=int, default=nvd.YEARS, help=argparse.SUPPRESS)
    sync_parser.add_argument("--archives", nargs="+", help="explicit NVD archive names")
    sync_parser.set_defaults(func=cmd_sync)

    scan_parser = subparsers.add_parser("scan", help="run the matchers")
    add_common(scan_parser)
    scan_parser.add_argument("--snapshot", type=int, help="snapshot id (default: newest)")
    scan_parser.add_argument(
        "--vulnix", action="store_true", help="also run vulnix (only sees derivations whose .drv survives)"
    )
    scan_parser.add_argument("--no-vulnix", action="store_true", help="skip the vulnix source")
    scan_parser.add_argument("--no-nvd", action="store_true", help="skip the NVD/CPE source")
    scan_parser.add_argument("--no-osv", action="store_true", help="skip OSV lookups")
    scan_parser.add_argument(
        "--vulnix-json", metavar="FILE", help="ingest saved 'vulnix --json' output ('-' for stdin)"
    )
    scan_parser.add_argument(
        "--offline", action="store_true", help="use cached OSV answers only"
    )
    scan_parser.set_defaults(func=cmd_scan)

    report_parser = subparsers.add_parser("report", help="print the delta report")
    add_common(report_parser)
    report_parser.add_argument("--snapshot", type=int, help="snapshot id (default: newest)")
    report_parser.add_argument("--json", action="store_true", help="machine readable output")
    report_parser.add_argument("-w", "--whitelist", action="append", metavar="FILE")
    report_parser.add_argument("--no-whitelist", action="store_true")
    report_parser.add_argument(
        "-s", "--show-whitelisted", action="store_true", help="list whitelisted findings"
    )
    report_parser.add_argument(
        "--limit", type=int, default=20, help="entries per section (default: %(default)s)"
    )
    report_parser.set_defaults(func=cmd_report)

    run_parser = subparsers.add_parser("run", help="sync + scan + report")
    add_common(run_parser)
    run_parser.add_argument("--snapshot", type=int, default=None, help=argparse.SUPPRESS)
    run_parser.add_argument("--vulnix", action="store_true")
    run_parser.add_argument("--no-vulnix", action="store_true")
    run_parser.add_argument("--no-nvd", action="store_true")
    run_parser.add_argument("--no-osv", action="store_true")
    run_parser.add_argument("--vulnix-json", metavar="FILE")
    run_parser.add_argument("--nvd", action="store_true", help="also refresh NVD during sync")
    run_parser.add_argument("--offline", action="store_true")
    run_parser.add_argument("--json", action="store_true")
    run_parser.add_argument("-w", "--whitelist", action="append", metavar="FILE")
    run_parser.add_argument("--no-whitelist", action="store_true")
    run_parser.add_argument("-s", "--show-whitelisted", action="store_true")
    run_parser.add_argument("--limit", type=int, default=20)
    run_parser.set_defaults(func=cmd_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=_log_level(args), format="%(levelname)s %(name)s: %(message)s"
    )
    if not hasattr(args, "db"):
        args.db = db.default_db_path()
    if not hasattr(args, "verbose"):
        args.verbose = False
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())