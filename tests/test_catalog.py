import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))

from unslop import catalog                                       # noqa: E402
from unslop.findings import Finding, Coverage, write, load       # noqa: E402

SEVERITIES = {"P0", "P1", "P2", "P3"}
FIX_CLASSES = {"auto", "assisted", "manual"}
METHODS = {"static", "config", "semantic", "net"}
DOMAINS = set("SDARCPOHXT")


class TestCatalog(unittest.TestCase):
    def test_catalog_has_all_64_checks(self):
        self.assertEqual(len(catalog.CHECKS), 64)

    def test_every_check_is_well_formed(self):
        for cid, chk in catalog.CHECKS.items():
            with self.subTest(check=cid):
                self.assertEqual(cid, chk.id)
                self.assertIn(cid[0], DOMAINS)
                self.assertIn(chk.severity, SEVERITIES)
                self.assertIn(chk.fix_class, FIX_CLASSES)
                self.assertIn(chk.method, METHODS)
                self.assertGreater(len(chk.title), 10)
                self.assertGreater(len(chk.why), 30, "why must be a concrete failure scenario")
                self.assertGreater(len(chk.fix), 20)

    def test_domain_counts_match_spec(self):
        expected = {"S": 6, "D": 9, "A": 6, "R": 9, "C": 8, "P": 5, "O": 5, "H": 8, "X": 5, "T": 3}
        actual = {}
        for cid in catalog.CHECKS:
            actual[cid[0]] = actual.get(cid[0], 0) + 1
        self.assertEqual(actual, expected)

    def test_by_method_filters(self):
        self.assertTrue(all(c.method == "semantic" for c in catalog.by_method("semantic")))
        self.assertGreaterEqual(len(catalog.by_method("semantic")), 10)


class TestFindings(unittest.TestCase):
    def test_roundtrip(self):
        import tempfile
        cov = Coverage()
        cov.scanned_files = 12
        cov.note("dependency verification skipped: offline")
        f = Finding(check_id="S1", file="src/a.ts", line=4, snippet="const k = 'sk-live_x'")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "findings.json"
            write(p, [f], cov)
            loaded, meta = load(p)
        self.assertEqual(meta["schemaVersion"], 1)
        self.assertEqual(loaded[0].check_id, "S1")
        self.assertEqual(loaded[0].confidence, "SUSPECTED")
        self.assertIn("offline", meta["coverage"]["notes"][0])

    def test_finding_rejects_unknown_check(self):
        with self.assertRaises(ValueError):
            Finding(check_id="Z9", file="a", line=1, snippet="x")


if __name__ == "__main__":
    unittest.main()


from unslop.ruleset import RULES              # noqa: E402


class TestRuleCoverage(unittest.TestCase):
    def test_every_static_check_has_a_rule(self):
        covered = {r.check_id for r in RULES}
        expected = {c.id for c in catalog.by_method("static")}
        self.assertEqual(expected - covered, set(), "static checks with no rule")

    def test_no_rule_targets_an_unknown_check(self):
        self.assertEqual({r.check_id for r in RULES} - set(catalog.CHECKS), set())

    def test_inert_rules_are_covered_by_a_detector(self):
        from unslop import detectors
        inert = {"R1", "H8", "S4"}
        emitted = detectors.detector_check_ids()
        self.assertTrue(inert <= emitted, "inert rule with no detector: %s" % (inert - emitted))
