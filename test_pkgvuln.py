"""Unit tests. Run with: python3 -m unittest pkgvuln.test_pkgvuln"""

from __future__ import annotations

import contextlib
import datetime
import io
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


class VariantStripTest(unittest.TestCase):
    """Variant markers are part of the derivation name, not of the release."""

    def test_strips_variant_markers(self):
        self.assertEqual(nixver.strip_variants("9.12_fish-completions"), "9.12")
        self.assertEqual(nixver.strip_variants("1.2.4-zstd"), "1.2.4")
        self.assertEqual(nixver.strip_variants("7.3.1-modules"), "7.3.1")
        self.assertEqual(nixver.strip_variants("5.42.3-env"), "5.42.3")
        self.assertEqual(nixver.strip_variants("50.1-gsettings-schemas"), "50.1")
        self.assertEqual(nixver.strip_variants("2026.09.03-zstd"), "2026.09.03")

    def test_keeps_real_version_suffixes(self):
        for version in ("1.0", "1.0.0", "1.0-beta", "1.0-rc2", "2.4.2-r3", "5.2p37"):
            with self.subTest(version=version):
                self.assertEqual(nixver.strip_variants(version), version)

    def test_empty_and_none(self):
        self.assertIsNone(nixver.strip_variants(None))
        self.assertIsNone(nixver.strip_variants(""))


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


class OverridesTest(DatabaseTest):
    def _affected(self, advisory_id, product, vendor, **ranges):
        db.record_advisory(self.conn, {"id": advisory_id, "source": "nvd"})
        self.conn.execute(
            "INSERT INTO affected (advisory_id, vendor, product, version_exact,"
            " start_incl, start_excl, end_incl, end_excl) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                advisory_id,
                vendor,
                product,
                ranges.pop("version_exact", None),
                ranges.pop("start_incl", None),
                ranges.pop("start_excl", None),
                ranges.pop("end_incl", None),
                ranges.pop("end_excl", None),
            ),
        )

    def test_bundled_file_loads(self):
        from . import overrides

        entries = overrides.load()
        self.assertIn("git-scm", overrides.vendors_for(entries, "git"))
        self.assertEqual(overrides.products_for(entries, "python3"), ["python"])
        # Variant pnames of the same upstream project need their own entry.
        self.assertEqual(overrides.products_for(entries, "nodejs-slim"), ["node.js"])
        # Nothing is constrained for a package we have no opinion about.
        self.assertIsNone(overrides.vendors_for(entries, "wget"))
        self.assertEqual(overrides.products_for(entries, "wget"), [])

    def test_vendor_gate_ignores_other_projects_with_the_same_product(self):
        from . import match, overrides

        entries = overrides.load()
        self._affected("CVE-2022-36882", "git", "jenkins", end_incl="4.11.3")
        self._affected("CVE-2022-0001", "git", "git-scm", end_excl="2.60")
        self.conn.commit()
        hits = list(match.candidates_for(self.conn, "2.56.0", "git", entries))
        self.assertEqual(hits, [("git", ["CVE-2022-0001"])])

    def test_product_alias_is_tried_before_the_heuristic(self):
        from . import match, overrides

        entries = overrides.load()
        self._affected("CVE-2025-0002", "python", "python", end_excl="3.15.1")
        self.conn.commit()
        self.assertEqual(
            list(match.candidates_for(self.conn, "3.15.0", "python3", entries)),
            [("python", ["CVE-2025-0002"])],
        )
        # Without the curated entry the same package is unmatched.
        self.assertEqual(list(match.candidates_for(self.conn, "3.15.0", "python3", {})), [])

    def test_vendor_constraint_does_not_hide_known_vendors(self):
        from . import match, overrides

        entries = overrides.load()
        # GLib is filed under several vendors by Red Hat; gnome is ours.
        self._affected("CVE-2026-58016", "glib", "redhat", end_excl="2.90")
        self._affected("CVE-2026-58017", "glib", "gnome", end_excl="2.90")
        self.conn.commit()
        hits = list(match.candidates_for(self.conn, "2.88.3", "glib", entries))
        self.assertEqual(hits, [("glib", ["CVE-2026-58017"])])

    def test_extra_file_extends_the_bundled_one(self):
        from . import overrides

        path = Path(self.tmp.name) / "extra.toml"
        path.write_text('["wget"]\nvendor = ["gnu"]\n', encoding="utf-8")
        entries = overrides.load([path])
        self.assertEqual(overrides.vendors_for(entries, "wget"), {"gnu"})
        self.assertIn("git-scm", overrides.vendors_for(entries, "git"))


class OutdatedTest(DatabaseTest):
    """Layer 1 compares versions, layer 2 resolves alternate version lines."""

    # A miniature nixpkgs built from the cases measured on the real system.
    ATTRS = {
        "boost": {"pname": "boost", "version": "1.91.0"},
        "boost189": {"pname": "boost", "version": "1.89.0"},
        "db": {"pname": "db", "version": "5.3.28"},
        "db4": {"pname": "db", "version": "4.8.30"},
        "dbus": {"pname": "dbus", "version": "1.16.2"},
        "makeDBusConf": {"pname": "dbus", "version": "1"},
        "gtk3": {"pname": "gtk+3", "version": "3.24.52"},
        "coreutils-full": {"pname": "coreutils-full", "version": "9.12"},
        "haskellPackages.dbus": {"pname": "dbus", "version": "1.4.2"},
        "python314Packages.foo": {"pname": "foo", "version": "1.0"},
    }

    def _patch(self, name, value):
        from . import outdated

        original = getattr(outdated, name)
        setattr(outdated, name, value)
        self.addCleanup(setattr, outdated, name, original)

    def _fake_evaluate(self, with_output_paths=None):
        """A stand-in for nix-env that records how often it was called."""
        calls = []

        def evaluate(pin, names=None, with_outputs=False, timeout=None):
            calls.append((set(names or ()), with_outputs))
            # nix-env filters on pname, so does the stand-in.
            selected = {
                attr: meta
                for attr, meta in self.ATTRS.items()
                if names is None or meta["pname"] in names
            }
            if not with_outputs:
                return selected
            payload = {}
            for attr, meta in selected.items():
                payload[attr] = dict(meta)
                payload[attr]["outputs"] = (
                    with_output_paths or {}
                ).get(attr, {"out": f"/nix/store/{attr}"})
            return payload

        evaluate.calls = calls
        self._patch("evaluate", evaluate)
        return evaluate

    def test_default_attribute_beats_alternatives(self):
        from . import outdated

        top = outdated.top_level(self.ATTRS)
        index = outdated.index_by_pname(top)
        self.assertEqual(outdated.resolve_attr("boost", top, index), ("boost", "default"))
        # dbus must map onto pkgs.dbus, never onto makeDBusConf's dbus-1.
        self.assertEqual(outdated.resolve_attr("dbus", top, index), ("dbus", "default"))
        # A pname that is not an attribute path resolves when it is unambiguous.
        self.assertEqual(outdated.resolve_attr("gtk+3", top, index), ("gtk3", "pname"))
        # Only nested attributes carry this pname, so the top level cannot say.
        self.assertEqual(outdated.resolve_attr("foo", top, index), (None, "absent"))
        self.assertNotIn("haskellPackages.dbus", top)

    def test_ambiguous_names_are_not_guessed(self):
        from . import outdated

        attrs = {
            "curl": {"pname": "curl", "version": "8.22.0"},
            "curlFull": {"pname": "curl", "version": "8.22.0"},
        }
        index = outdated.index_by_pname(attrs)
        self.assertEqual(outdated.resolve_attr("curl-minimal", attrs, index), (None, "absent"))
        del attrs["curl"]
        index = outdated.index_by_pname(attrs)
        self.assertEqual(outdated.resolve_attr("curl-minimal", attrs, index), (None, "absent"))

    def test_classify(self):
        from . import outdated

        self.assertEqual(outdated.classify("1.2.3", "1.2.3"), outdated.CURRENT)
        self.assertEqual(outdated.classify("1.2.3", "1.3"), outdated.OUTDATED)
        self.assertEqual(outdated.classify("2.0", "1.9"), outdated.AHEAD)
        self.assertEqual(outdated.classify(None, "1.0"), outdated.UNMAPPED)
        # Variant markers are the same release, not a newer one.
        self.assertEqual(outdated.classify("9.12_fish-completions", "9.12"), outdated.CURRENT)
        self.assertEqual(outdated.classify("5.42.3-env", "5.42.3"), outdated.CURRENT)

    def test_compare_packages_reproduces_the_measured_candidates(self):
        from . import outdated

        packages = [
            {"name": "boost", "version": "1.89.0", "store_path": "/nix/store/boost189"},
            {"name": "dbus", "version": "1", "store_path": "/nix/store/dbus-1"},
            {"name": "gtk+3", "version": "3.24.52", "store_path": "/nix/store/gtk3"},
            {"name": "coreutils-full", "version": "9.12_fish-completions", "store_path": "/nix/store/coreutils"},
            {"name": "X-Restart-Triggers-polkit", "version": None, "store_path": "/nix/store/triggers"},
        ]
        rows = {row["name"]: row for row in outdated.compare_packages(packages, self.ATTRS)}
        self.assertEqual(rows["boost"]["status"], outdated.OUTDATED)
        self.assertEqual(rows["boost"]["attr"], "boost")
        self.assertEqual(rows["boost"]["confidence"], "certain")
        self.assertEqual(rows["dbus"]["status"], outdated.OUTDATED)
        self.assertEqual(rows["gtk+3"]["status"], outdated.CURRENT)
        self.assertEqual(rows["gtk+3"]["attr"], "gtk3")
        self.assertEqual(rows["coreutils-full"]["status"], outdated.CURRENT)
        self.assertEqual(rows["X-Restart-Triggers-polkit"]["status"], outdated.UNMAPPED)

    def test_unstable_versions_are_reported_as_unsure(self):
        from . import outdated

        rows = outdated.compare_packages(
            [{"name": "boost", "version": "1.89.0-unstable-2021-05-09", "store_path": "/nix/store/x"}],
            {"boost": {"pname": "boost", "version": "1.91.0"}},
        )
        self.assertEqual(rows[0]["status"], outdated.OUTDATED)
        self.assertEqual(rows[0]["confidence"], "unsure")

    def test_truncated_versions_are_reported_as_unsure(self):
        """`dbus-1` is the makeDBusConf derivation, not dbus version 1."""
        from . import outdated

        self.assertTrue(outdated.looks_truncated("1", "1.16.2"))
        self.assertFalse(outdated.looks_truncated("1.0", "1.0.1"))
        self.assertFalse(outdated.looks_truncated("3", "3") )
        rows = outdated.compare_packages(
            [{"name": "dbus", "version": "1", "store_path": "/nix/store/dbus-1"}],
            {"dbus": {"pname": "dbus", "version": "1.16.2"}},
        )
        self.assertEqual(rows[0]["status"], outdated.OUTDATED)
        self.assertEqual(rows[0]["confidence"], "unsure")
        self.assertIn("unsure", outdated.format_text(
            {
                "snapshot": {"id": 1, "taken_at": "now"},
                "nixpkgs": {"pin": "/nix/store/x", "system": "s", "attrs": 1,
                            "verified": False, "resolved_candidates": 0},
                "packages": 1,
                "counts": {outdated.CURRENT: 0, outdated.OUTDATED: 1,
                           outdated.AHEAD: 0, outdated.UNMAPPED: 0},
                "outdated": rows,
                "ahead": [],
            }
        ))

    def test_store_path_verification_drops_alternate_lines(self):
        from . import outdated

        packages = [
            {"name": "boost", "version": "1.89.0", "store_path": "/nix/store/boost189"},
            {"name": "dbus", "version": "1", "store_path": "/nix/store/makeDBusConf"},
            {"name": "db", "version": "4.7.0", "store_path": "/nix/store/old-db"},
        ]
        rows = outdated.compare_packages(packages, self.ATTRS)
        paths = {
            "/nix/store/boost189": {"attr": "boost189", "output": "out"},
            "/nix/store/makeDBusConf": {"attr": "makeDBusConf", "output": "out"},
        }
        outdated.apply_verification(rows, paths)
        by_name = {row["name"]: row for row in rows}
        self.assertEqual(by_name["boost"]["status"], outdated.CURRENT)
        self.assertEqual(by_name["boost"]["attr"], "boost189")
        self.assertEqual(by_name["boost"]["verified_output"], "out")
        self.assertTrue(by_name["boost"]["in_pin"])
        self.assertEqual(by_name["dbus"]["status"], outdated.CURRENT)
        # Not in the pin: real drift, and it must stay visible.
        self.assertEqual(by_name["db"]["status"], outdated.OUTDATED)
        self.assertFalse(by_name["db"]["in_pin"])
        self.assertNotIn("verified_output", by_name["db"])

    def test_attributes_are_cached_per_pin(self):
        from . import outdated

        evaluate = self._fake_evaluate()
        first = outdated.load_attrs(self.conn, "/nix/store/aaa-source", "x86_64-linux")
        second = outdated.load_attrs(self.conn, "/nix/store/aaa-source", "x86_64-linux")
        self.assertEqual(len(evaluate.calls), 1)
        self.assertEqual(first, second)
        outdated.load_attrs(self.conn, "/nix/store/aaa-source", "x86_64-linux", refresh=True)
        self.assertEqual(len(evaluate.calls), 2)
        # A different pin is a different evaluation.
        outdated.load_attrs(self.conn, "/nix/store/bbb-source", "x86_64-linux")
        self.assertEqual(len(evaluate.calls), 3)
        # Another system is too, so a remote pin cannot reuse local paths.
        outdated.load_attrs(self.conn, "/nix/store/aaa-source", "aarch64-linux")
        self.assertEqual(len(evaluate.calls), 4)

    def test_store_paths_are_cached_per_pname(self):
        from . import outdated

        evaluate = self._fake_evaluate()
        pin = "/nix/store/aaa-source"
        paths = outdated.verify_store_paths(self.conn, pin, "x86_64-linux", ["boost", "dbus"])
        self.assertEqual(len(evaluate.calls), 1)
        self.assertEqual(paths["/nix/store/boost189"]["attr"], "boost189")
        self.assertEqual(evaluate.calls[0][1], True)  # asked for outputs
        # Nothing left to evaluate the second time.
        outdated.verify_store_paths(self.conn, pin, "x86_64-linux", ["boost"])
        self.assertEqual(len(evaluate.calls), 1)
        # A pname that was never evaluated is fetched on its own.
        outdated.verify_store_paths(self.conn, pin, "x86_64-linux", ["gtk+3"])
        self.assertEqual(len(evaluate.calls), 2)

    def test_batches_and_filter(self):
        from . import outdated

        names = [f"pkg{index}" for index in range(5)]
        self.assertEqual(outdated.batches(names, size=2), [names[0:2], names[2:4], names[4:]])
        self.assertEqual(outdated.batches([], size=2), [])
        self.assertEqual(
            outdated.filter_regex(["a+b", "c.d", "x-y"]),
            "^(a\\+b|c\\.d|x-y)$",  # "-" must stay literal, nix rejects \\-
        )

    def test_build_reports_and_verifies(self):
        from . import outdated

        pin = "/nix/store/aaa-source"
        snapshot_id = self.seed(
            [
                ("boost", "1.89.0", "boost-1.89.0", "/nix/store/boost189"),
                ("dbus", "1", "dbus-1", "/nix/store/makeDBusConf"),
                ("gtk+3", "3.24.52", "gtk+3-3.24.52", "/nix/store/gtk3"),
                ("X-Restart-Triggers-polkit", None, "X-Restart-Triggers-polkit", "/nix/store/t"),
            ]
        )
        self._fake_evaluate()

        plain = outdated.build(self.conn, snapshot_id, pin, system="x86_64-linux")
        self.assertEqual(plain["counts"], {outdated.CURRENT: 1, outdated.OUTDATED: 2, outdated.AHEAD: 0, outdated.UNMAPPED: 1})
        self.assertFalse(plain["nixpkgs"]["verified"])
        self.assertIn("--verify-store-paths", outdated.format_text(plain))
        json.loads(outdated.format_json(plain))  # must be serialisable

        verified = outdated.build(
            self.conn, snapshot_id, pin, system="x86_64-linux", verify=True
        )
        self.assertEqual(verified["counts"][outdated.OUTDATED], 0)
        self.assertEqual(verified["counts"][outdated.CURRENT], 3)
        self.assertEqual(verified["nixpkgs"]["resolved_candidates"], 2)
        self.assertIn("store-path check", outdated.format_text(verified))

    def test_build_rejects_a_missing_snapshot(self):
        from . import outdated

        self._fake_evaluate()
        with self.assertRaises(SystemExit):
            outdated.build(self.conn, 99, "/nix/store/aaa-source", system="x86_64-linux")


class RunOutdatedTest(DatabaseTest):
    """`run` carries the version check, and must survive it failing."""

    def _args(self, **overrides):
        from . import cli

        args = cli.build_parser().parse_args(["run"])
        for key, value in overrides.items():
            setattr(args, key, value)
        return args

    def test_broken_nixpkgs_does_not_break_the_scan(self):
        from . import cli, outdated

        self.seed([("curl", "8.22.0", "curl-8.22.0", "/nix/store/aaa-curl")])

        def broken(*_args, **_kwargs):
            raise outdated.EvaluationError("no nixpkgs here")

        original = outdated.build
        outdated.build = broken
        self.addCleanup(setattr, outdated, "build", original)

        captured = io.StringIO()
        with self.assertLogs(level="WARNING") as logs, contextlib.redirect_stdout(captured):
            cli._report_outdated(self.conn, self._args(nixpkgs="/nix/store/nope"))
        self.assertIn("nixpkgs version source skipped", logs.output[0])
        # Skipped, not raised: the run continues to the advisory report.
        self.assertEqual(captured.getvalue(), "")

    def test_no_outdated_skips_the_comparison(self):
        from . import cli, outdated

        self.seed([("curl", "8.22.0", "curl-8.22.0", "/nix/store/aaa-curl")])

        def must_not_run(*_args, **_kwargs):
            raise AssertionError("outdated was evaluated despite --no-outdated")

        original = outdated.build
        outdated.build = must_not_run
        self.addCleanup(setattr, outdated, "build", original)
        cli._report_outdated(self.conn, self._args(no_outdated=True))

    def test_section_is_printed_with_the_advisory_report(self):
        from . import cli, outdated

        self.seed([("boost", "1.89.0", "boost-1.89.0", "/nix/store/aaa-boost")])
        args = self._args(nixpkgs="/nix/store/aaa-source", verify_store_paths=True)

        def fake_build(connection, snapshot_id, pin, **kwargs):
            return {
                "snapshot": {"id": snapshot_id, "taken_at": "now"},
                "nixpkgs": {
                    "pin": str(pin),
                    "system": "x86_64-linux",
                    "attrs": 1,
                    "verified": kwargs.get("verify", False),
                    "resolved_candidates": 0,
                },
                "packages": 1,
                "counts": {
                    outdated.CURRENT: 0,
                    outdated.OUTDATED: 1,
                    outdated.AHEAD: 0,
                    outdated.UNMAPPED: 0,
                },
                "outdated": [
                    {
                        "name": "boost",
                        "version": "1.89.0",
                        "store_path": "/nix/store/aaa-boost",
                        "attr": "boost",
                        "how": "default",
                        "nixpkgs_version": "1.91.0",
                        "status": outdated.OUTDATED,
                        "confidence": "certain",
                        "in_pin": False,
                    }
                ],
                "ahead": [],
            }

        original = outdated.build
        outdated.build = fake_build
        self.addCleanup(setattr, outdated, "build", original)

        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            cli._report_outdated(self.conn, args)
        text = captured.getvalue()
        self.assertIn("1.89.0 -> 1.91.0", text)
        self.assertIn("not built by this pin", text)
        self.assertTrue(text.endswith("\n\n"), "the report follows on a new paragraph")


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
            "nixpkgs",
            "system",
            "refresh",
            "verify_store_paths",
            "no_outdated",
        ):
            self.assertTrue(hasattr(args, attribute), attribute)

    def test_run_does_the_outdated_check_by_default(self):
        from . import cli

        self.assertFalse(cli.build_parser().parse_args(["run"]).no_outdated)
        self.assertTrue(cli.build_parser().parse_args(["run", "--no-outdated"]).no_outdated)

    def test_outdated_parser_provides_every_option_cmd_outdated_touches(self):
        from . import cli

        args = cli.build_parser().parse_args(["outdated", "--verify-store-paths"])
        for attribute in (
            "nixpkgs",
            "system",
            "snapshot",
            "refresh",
            "verify_store_paths",
            "json",
            "limit",
            "fail_on_outdated",
            "db",
        ):
            self.assertTrue(hasattr(args, attribute), attribute)
        self.assertTrue(args.verify_store_paths)
        self.assertFalse(args.fail_on_outdated)

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