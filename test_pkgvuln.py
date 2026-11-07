"""Unit tests. Run with: python3 -m unittest pkgvuln.test_pkgvuln"""

from __future__ import annotations

import datetime
import json
import tempfile
import unittest
from pathlib import Path

from . import db, names, nixver, report
from .sources import vulnix

# The tables owned by track-packages.py, needed by the tests that build a
# database from scratch. Kept in sync with track-packages.py's SCHEMA.
SNAPSHOT_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    taken_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE TABLE IF NOT EXISTS packages (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    version     TEXT,
    derivation  TEXT NOT NULL,
    store_path  TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, derivation)
);
"""


class VersionComparisonTest(unittest.TestCase):
    """Expected values taken from `nix eval builtins.compareVersions`."""

    PAIRS = [
        ("1.0", "1.0.0", -1),
        ("153.0", "153.0.0", -1),
        ("1.0pre1", "1.0", -1),
        ("1.0.2p", "1.0.2", 1),
        ("2.0", "10.0", -1),
        ("1.0a", "1.0.1", -1),
        ("3.5.4", "3.5.4-r1", -1),
        ("007", "7", 0),
        ("1.2.3", "1.2.3", 0),
        ("2.4.2", "2.4.2-r3", -1),
        ("1.0-beta", "1.0", 1),
        ("2024-05-06", "1.0", 1),
        ("python3.14", "python3.9", 1),
        ("1.0_1", "1.0.1", -1),
        ("5.2p37", "5.2", 1),
    ]

    def test_matches_nix_semantics(self):
        for left, right, expected in self.PAIRS:
            with self.subTest(left=left, right=right):
                self.assertEqual(nixver.compare(left, right), expected)
                self.assertEqual(nixver.compare(right, left), -expected)

    def test_release_comparison_ignores_trailing_zeros(self):
        self.assertEqual(nixver.compare_release("153.0", "153.0.0"), 0)
        self.assertEqual(nixver.compare_release("1.0", "1.0.0"), 0)
        self.assertEqual(nixver.compare_release("1.0.1", "1.0"), 1)

    def test_release_comparison_falls_back_for_non_numeric(self):
        self.assertEqual(nixver.compare_release("1.0pre1", "1.0"), -1)


class VersionRangeTest(unittest.TestCase):
    def test_ranges(self):
        self.assertTrue(nixver.in_range("2.0", start_incl="1.0", end_excl="3.0"))
        self.assertFalse(nixver.in_range("3.0", start_incl="1.0", end_excl="3.0"))
        self.assertTrue(nixver.in_range("3.0", end_incl="3.0"))
        self.assertFalse(nixver.in_range("1.0", start_excl="1.0"))
        self.assertTrue(nixver.in_range("153.0", start_incl="153.0.0"))
        self.assertTrue(nixver.in_range("anything"))


class UpstreamVersionTest(unittest.TestCase):
    def test_strips_nixpkgs_revisions(self):
        self.assertEqual(nixver.upstream_version("2.4.2-r3"), "2.4.2")
        self.assertEqual(nixver.upstream_version("1.0-rev5"), "1.0")

    def test_strips_output_suffixes(self):
        self.assertEqual(nixver.upstream_version("3.15.0_fish-completions"), "3.15.0")
        self.assertEqual(nixver.upstream_version("1.2.3_man"), "1.2.3")

    def test_unmatchable_versions(self):
        self.assertIsNone(nixver.upstream_version("unstable-2024-05-06"))
        self.assertIsNone(nixver.upstream_version("2024-05-06"))
        self.assertIsNone(nixver.upstream_version(None))
        self.assertIsNone(nixver.upstream_version(""))

    def test_keeps_normal_versions(self):
        self.assertEqual(nixver.upstream_version("8.22.0"), "8.22.0")
        self.assertEqual(nixver.upstream_version("2.32.3"), "2.32.3")


class NamesTest(unittest.TestCase):
    def test_python_packages_map_to_pypi(self):
        cases = {
            "python3.14-markupsafe": ("PyPI", "markupsafe"),
            "python3.14-dnspython": ("PyPI", "dnspython"),
            "python3.14-mako": ("PyPI", "mako"),
            "python3.14-pycairo": ("PyPI", "pycairo"),
        }
        for pname, (ecosystem, package) in cases.items():
            with self.subTest(pname=pname):
                self.assertEqual(
                    names.osv_coordinates(pname, "1.0"), (ecosystem, package, "1.0")
                )

    def test_interpreter_derivations_do_not_map(self):
        self.assertIsNone(names.osv_coordinates("python3-", "3.15.0"))
        self.assertIsNone(names.osv_coordinates("python3", "3.15.0_fish-completions"))
        self.assertIsNone(names.osv_coordinates("python3.14-pyxdg", None))

    def test_non_python_does_not_map(self):
        self.assertIsNone(names.osv_coordinates("curl", "8.22.0"))
        self.assertIsNone(names.osv_coordinates("perl5.40-foo", "1.0"))

    def test_canonicalisation_is_pep503(self):
        self.assertEqual(names.canonicalise_pypi("PyGObject"), "pygobject")
        self.assertEqual(names.canonicalise_pypi("zope.interface"), "zope-interface")

    def test_version_is_normalised_before_lookup(self):
        self.assertEqual(
            names.osv_coordinates("python3.14-requests", "2.19.1-r2"),
            ("PyPI", "requests", "2.19.1"),
        )


class DatabaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "packages.db"
        self.conn = db.connect(self.path)
        self.addCleanup(self.conn.close)
        self.conn.executescript(SNAPSHOT_SCHEMA)

    def seed(self, packages, previous=None):
        """Insert a snapshot like track-packages.py does."""
        if previous:
            self.conn.execute("INSERT INTO snapshots (taken_at) VALUES (?)", (previous,))
        cursor = self.conn.execute("INSERT INTO snapshots DEFAULT VALUES")
        snapshot_id = cursor.lastrowid
        self.conn.executemany(
            "INSERT INTO packages (snapshot_id, name, version, derivation, store_path)"
            " VALUES (?, ?, ?, ?, ?)",
            [(snapshot_id, *package) for package in packages],
        )
        self.conn.commit()
        return snapshot_id

    def test_schema_does_not_collide_with_snapshot_tables(self):
        self.conn.execute("INSERT INTO snapshots DEFAULT VALUES")
        tables = {
            row["name"]
            for row in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        self.assertTrue({"snapshots", "packages", "advisories", "matches"} <= tables)

    def test_vulnix_ingest_joins_on_full_name(self):
        snapshot_id = self.seed(
            [("curl", "8.22.0", "curl-8.22.0", "/nix/store/aaa-curl-8.22.0")]
        )
        packages = list(self.conn.execute("SELECT * FROM packages"))
        items = [
            {
                "name": "curl-8.22.0",
                "pname": "curl",
                "version": "8.22.0",
                "derivation": "/nix/store/bbb-curl-8.22.0.drv",
                "affected_by": ["CVE-2024-0001"],
                "whitelisted": [],
                "cvssv3_basescore": {"CVE-2024-0001": 7.5},
                "description": {"CVE-2024-0001": "bad"},
            },
            {"name": "curl-bin", "affected_by": [], "whitelisted": []},
        ]
        self.assertEqual(vulnix.ingest(self.conn, snapshot_id, packages, items), 1)
        row = self.conn.execute("SELECT * FROM matches").fetchone()
        self.assertEqual(row["store_path"], "/nix/store/aaa-curl-8.22.0")
        self.assertEqual(row["name"], "curl")
        self.assertEqual(row["source"], "vulnix")
        advisory = self.conn.execute(
            "SELECT * FROM advisories WHERE id = 'CVE-2024-0001'"
        ).fetchone()
        self.assertEqual(advisory["cvss_v3"], 7.5)
        self.assertEqual(advisory["source"], "vulnix")

    def test_advisory_merge_keeps_richer_data(self):
        db.record_advisory(self.conn, {"id": "GHSA-1", "source": "osv", "summary": "s"})
        db.record_advisory(
            self.conn,
            {"id": "GHSA-1", "source": "kev", "aliases": ["CVE-2024-1"], "cvss_v3": 9.8},
        )
        row = self.conn.execute("SELECT * FROM advisories WHERE id = 'GHSA-1'").fetchone()
        self.assertEqual(row["summary"], "s")
        self.assertEqual(row["cvss_v3"], 9.8)
        self.assertEqual(row["sources"], "osv,kev")
        self.assertEqual(row["aliases"], "CVE-2024-1")


class ReportTest(DatabaseTest):
    def _match(self, snapshot_id, store_path, name, version, advisory_id, source="vulnix"):
        db.record_match(self.conn, snapshot_id, store_path, name, version, advisory_id, source)

    def test_classification_introduced_carried_fixed(self):
        previous_id = self.seed(
            [
                ("openssl", "3.5.3", "openssl-3.5.3", "/nix/store/old-openssl-3.5.3"),
                ("curl", "8.21.0", "curl-8.21.0", "/nix/store/old-curl-8.21.0"),
            ],
            previous="2024-01-01T00:00:00Z",
        )
        self._match(previous_id, "/nix/store/old-openssl-3.5.3", "openssl", "3.5.3", "CVE-2024-OLD")
        self._match(previous_id, "/nix/store/old-curl-8.21.0", "curl", "8.21.0", "CVE-2024-STILL")

        snapshot_id = self.seed(
            [
                ("openssl", "3.5.4", "openssl-3.5.4", "/nix/store/new-openssl-3.5.4"),
                ("curl", "8.21.0", "curl-8.21.0", "/nix/store/old-curl-8.21.0"),
                ("zlib", "1.3", "zlib-1.3", "/nix/store/new-zlib-1.3"),
            ]
        )
        self._match(snapshot_id, "/nix/store/old-curl-8.21.0", "curl", "8.21.0", "CVE-2024-STILL")
        self._match(snapshot_id, "/nix/store/new-zlib-1.3", "zlib", "1.3", "CVE-2024-NEW")

        data = report.build(self.conn, snapshot_id, [])
        by_name = {entry["name"]: entry for entry in data["current"]}
        self.assertEqual(by_name["curl"]["classification"], report.CARRIED)
        self.assertEqual(by_name["zlib"]["classification"], report.INTRODUCED)
        # openssl was upgraded and no longer matches -> reported as fixed
        self.assertEqual(
            [(item["name"], item["advisory_id"]) for item in data["fixed"]],
            [("openssl", "CVE-2024-OLD")],
        )
        self.assertEqual(report.exit_code(data), 2)

    def test_duplicate_identifiers_collapse_to_one_bug(self):
        snapshot_id = self.seed([("mako", "1.4.1", "mako-1.4.1", "/nix/store/a-mako-1.4.1")])
        db.record_advisory(
            self.conn,
            {
                "id": "GHSA-5639-2j2p-m4mx",
                "source": "osv",
                "severity": "MODERATE",
                "summary": "ghsa view",
                "aliases": ["CVE-2026-102991", "PYSEC-2026-4243"],
            },
        )
        db.record_advisory(
            self.conn,
            {
                "id": "PYSEC-2026-4243",
                "source": "osv",
                "cvss_v3": 9.8,
                "aliases": ["CVE-2026-102991", "GHSA-5639-2j2p-m4mx"],
            },
        )
        for advisory_id in ("GHSA-5639-2j2p-m4mx", "PYSEC-2026-4243"):
            self._match(snapshot_id, "/nix/store/a-mako-1.4.1", "mako", "1.4.1", advisory_id)
        data = report.build(self.conn, snapshot_id, [])
        advisories = data["current"][0]["advisories"]
        self.assertEqual(len(advisories), 1)
        self.assertEqual(advisories[0]["id"], "PYSEC-2026-4243")  # higher cvss wins
        self.assertEqual(advisories[0]["duplicates"], ["GHSA-5639-2j2p-m4mx"])
        self.assertIn("CVE-2026-102991", advisories[0]["aliases"])
        self.assertEqual(advisories[0]["priority"], "high")

    def test_first_snapshot_is_initial_not_introduced(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", "CVE-1")
        data = report.build(self.conn, snapshot_id, [])
        self.assertEqual(data["current"][0]["classification"], report.INITIAL)
        self.assertIsNone(data["previous"])
        self.assertIn("first snapshot", report.format_text(data))

    def test_priority_ordering(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        db.record_advisory(self.conn, {"id": "CVE-1", "source": "kev", "cvss_v3": 5.0})
        db.record_advisory(self.conn, {"id": "CVE-2", "source": "osv", "cvss_v3": 9.0})
        db.record_advisory(self.conn, {"id": "CVE-3", "source": "osv"})
        self.conn.execute("UPDATE advisories SET kev = 1 WHERE id = 'CVE-1'")
        for advisory_id in ("CVE-1", "CVE-2", "CVE-3"):
            self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", advisory_id)
        data = report.build(self.conn, snapshot_id, [])
        self.assertEqual(
            [a["priority"] for a in data["current"][0]["advisories"]],
            ["exploited", "high", "normal"],
        )

    def _write_whitelist(self, text: str) -> Path:
        path = Path(self.tmp.name) / "whitelist.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def test_whitelist_masks_listed_only(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        for advisory_id in ("CVE-1", "CVE-2"):
            self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", advisory_id)
        path = self._write_whitelist('["curl-1.0"]\ncve = ["CVE-1"]\n')
        data = report.build(self.conn, snapshot_id, [path])
        self.assertEqual([a["id"] for a in data["current"][0]["advisories"]], ["CVE-2"])
        self.assertEqual([a["id"] for a in data["masked"][0]["advisories"]], ["CVE-1"])
        self.assertEqual(report.exit_code(data), 2)

    def test_whitelist_without_cves_masks_everything(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", "CVE-1")
        path = self._write_whitelist('["*"]\ncomment = "accepted risk"\n')
        data = report.build(self.conn, snapshot_id, [path])
        self.assertFalse(data["current"])
        self.assertEqual(report.exit_code(data), report.WHITELISTED_ONLY)

    def test_whitelist_until_expiry(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", "CVE-1")
        expired = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        future = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()

        data = report.build(
            self.conn, snapshot_id, [self._write_whitelist(f'["curl"]\nuntil = "{expired}"\n')]
        )
        self.assertEqual(report.exit_code(data), 2)

        data = report.build(
            self.conn, snapshot_id, [self._write_whitelist(f'["curl"]\nuntil = "{future}"\n')]
        )
        self.assertEqual(report.exit_code(data), report.WHITELISTED_ONLY)

    def test_whitelist_respects_version_sections(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", "CVE-1")
        data = report.build(self.conn, snapshot_id, [self._write_whitelist('["curl-2.0"]\n')])
        self.assertEqual(report.exit_code(data), 2)

    def test_json_output_is_serialisable(self):
        snapshot_id = self.seed([("curl", "1.0", "curl-1.0", "/nix/store/a-curl-1.0")])
        self._match(snapshot_id, "/nix/store/a-curl-1.0", "curl", "1.0", "CVE-1")
        data = report.build(self.conn, snapshot_id, [])
        self.assertIsInstance(json.loads(report.format_json(data)), dict)
        self.assertIsInstance(report.format_text(data), str)


class NvdParseTest(unittest.TestCase):
    def test_cpe_parsing(self):
        from .sources import nvd

        parsed = nvd.parse_cpe(
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
        )
        self.assertEqual(parsed["vendor"], "apache")
        self.assertEqual(parsed["product"], "log4j")
        self.assertEqual(parsed["version_exact"], "2.14.1")

    def test_cpe_wildcards_and_other_parts(self):
        from .sources import nvd

        self.assertIsNone(nvd.parse_cpe("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"))
        self.assertIsNone(nvd.parse_cpe("cpe:2.3:a:vendor:*:*:*:*:*:*:*:*"))
        self.assertIsNone(nvd.parse_cpe("cpe:/a:apache:log4j:2.0"))  # CPE 2.2
        self.assertIsNone(nvd.parse_cpe(""))

    def test_cpe_escaped_colon(self):
        from .sources import nvd

        parsed = nvd.parse_cpe(
            "cpe:2.3:a:some\\:vendor:thing:1.0:*:*:*:*:*:*:*"
        )
        self.assertEqual(parsed["product"], "thing")

    def test_cve_parsing_keeps_ranges_only_for_vulnerable_matches(self):
        from .sources import nvd

        item = {
            "cve": {
                "id": "CVE-2021-44228",
                "lastModified": "2024-01-01T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "log4shell"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0",
                                        "versionEndExcluding": "2.15.0",
                                    },
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*",
                                    },
                                ]
                            }
                        ]
                    }
                ],
            }
        }
        advisory, affected = nvd.parse_cve(item)
        self.assertEqual(advisory["id"], "CVE-2021-44228")
        self.assertEqual(advisory["cvss_v3"], 10.0)
        self.assertEqual(advisory["description"], "log4shell")
        self.assertEqual(len(affected), 1)
        self.assertEqual(affected[0]["product"], "log4j")
        self.assertEqual(affected[0]["start_incl"], "2.0")
        self.assertEqual(affected[0]["end_excl"], "2.15.0")


class CpeMatchTest(DatabaseTest):
    def _affected(self, product, **ranges):
        db.record_advisory(
            self.conn,
            {"id": ranges.get("advisory_id", "CVE-2021-44228"), "source": "nvd"},
        )
        self.conn.execute(
            "INSERT INTO affected (advisory_id, product, version_exact, start_incl,"
            " start_excl, end_incl, end_excl) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                ranges.pop("advisory_id", "CVE-2021-44228"),
                product,
                ranges.pop("version_exact", None),
                ranges.pop("start_incl", None),
                ranges.pop("start_excl", None),
                ranges.pop("end_incl", None),
                ranges.pop("end_excl", None),
            ),
        )

    def test_product_candidates_are_ordered_and_deduped(self):
        from . import match

        self.assertEqual(
            match.product_candidates("Python-Numpy"), ["python-numpy", "python_numpy"]
        )
        self.assertEqual(match.product_candidates("curl"), ["curl"])

    def test_range_match(self):
        from . import match

        self._affected("log4j", start_incl="2.0", end_excl="2.15.0")
        self.conn.commit()
        self.assertEqual(
            list(match.candidates_for(self.conn, "2.14.1", "log4j")),
            [("log4j", ["CVE-2021-44228"])],
        )
        self.assertEqual(list(match.candidates_for(self.conn, "2.15.0", "log4j")), [])

    def test_exact_version_ignores_trailing_zeros(self):
        from . import match

        self._affected("curl", version_exact="7.80")
        self.conn.commit()
        self.assertEqual(
            list(match.candidates_for(self.conn, "7.80.0", "curl")),
            [("curl", ["CVE-2021-44228"])],
        )

    def test_version_without_constraints_never_matches(self):
        from . import match

        self._affected("log4j")
        self.conn.commit()
        self.assertEqual(list(match.candidates_for(self.conn, "2.14.1", "log4j")), [])

    def test_scan_records_matches_and_skips_unmatchable_versions(self):
        from . import match

        self._affected("log4j", start_incl="2.0", end_excl="2.15.0")
        self.conn.commit()
        snapshot_id = self.seed(
            [
                ("log4j", "2.14.1", "log4j-2.14.1", "/nix/store/a-log4j-2.14.1"),
                ("foo", "unstable-2024-05-06", "foo-unstable-2024-05-06", "/nix/store/b-foo"),
            ]
        )
        packages = db.snapshot_packages(self.conn, snapshot_id)
        self.assertEqual(match.scan(self.conn, snapshot_id, packages), 1)
        row = self.conn.execute("SELECT * FROM matches").fetchone()
        self.assertEqual(row["source"], "nvd")
        self.assertEqual(row["store_path"], "/nix/store/a-log4j-2.14.1")

    def test_rerun_does_not_duplicate(self):
        from . import match

        self._affected("log4j", start_incl="2.0", end_excl="2.15.0")
        self.conn.commit()
        snapshot_id = self.seed([("log4j", "2.14.1", "log4j-2.14.1", "/nix/store/a-log4j")])
        packages = db.snapshot_packages(self.conn, snapshot_id)
        match.scan(self.conn, snapshot_id, packages)
        match.scan(self.conn, snapshot_id, packages)
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) AS n FROM matches").fetchone()["n"], 1
        )


class CliTest(unittest.TestCase):
    def test_run_parser_provides_every_option_cmd_run_touches(self):
        from . import cli

        args = cli.build_parser().parse_args(["run", "--nvd"])
        for attribute in (
            "archives",
            "years",
            "nvd",
            "snapshot",
            "vulnix",
            "vulnix_json",
            "no_nvd",
            "no_osv",
            "offline",
            "json",
            "whitelist",
            "no_whitelist",
            "show_whitelisted",
            "limit",
            "db",
        ):
            self.assertTrue(hasattr(args, attribute), attribute)

    def test_exit_codes_leave_one_free_for_crashes(self):
        self.assertEqual(report.CLEAN, 0)
        self.assertEqual(report.FINDINGS, 2)
        self.assertEqual(report.WHITELISTED_ONLY, 3)


class OsvParseTest(unittest.TestCase):
    def test_epss_csv_parsing(self):
        from .sources import epss

        text = (
            "#model_version:v2024.01.01,score_date:2024-01-02T00:00:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2024-1,0.91,0.99\n"
            "CVE-2024-2,0.001,0.10\n"
            "not-a-cve,0.5,0.5\n"
        )
        scores = epss.parse(text)
        self.assertEqual(scores["CVE-2024-1"], (0.91, 0.99))
        self.assertNotIn("not-a-cve", scores)

    def test_osv_severity_is_coarse(self):
        from .sources import osv

        vuln = {"database_specific": {"severity": "HIGH"}}
        self.assertEqual(osv._severity(vuln), "HIGH")
        self.assertIsNone(osv._severity({}))


if __name__ == "__main__":
    unittest.main()