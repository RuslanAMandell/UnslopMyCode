import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from scan import scan                            # noqa: E402
from unslop.catalog import CHECKS                # noqa: E402

VULN = ROOT / "tests" / "fixtures" / "vulnerable-next-supabase"
CLEAN = ROOT / "tests" / "fixtures" / "clean-next-supabase"


class TestFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = json.loads((VULN / "expected.json").read_text())
        cls.vuln_found, _ = scan(VULN)
        cls.clean_found, _ = scan(CLEAN)

    def test_p0_recall_is_total(self):
        expected_p0 = {cid for cid in self.expected if CHECKS[cid].severity == "P0"}
        found = {f.check_id for f in self.vuln_found}
        self.assertEqual(expected_p0 - found, set(), "P0 checks the scanner missed")

    def test_overall_recall_at_least_90_percent(self):
        expected = set(self.expected)
        found = {f.check_id for f in self.vuln_found}
        recall = len(expected & found) / float(len(expected))
        self.assertGreaterEqual(recall, 0.90, "missed: %s" % sorted(expected - found))

    def test_planted_findings_land_on_the_right_file(self):
        by_check = {}
        for f in self.vuln_found:
            by_check.setdefault(f.check_id, set()).add(f.file)
        for cid, sites in self.expected.items():
            if cid not in by_check:
                continue
            wanted = {s["file"] for s in sites}
            with self.subTest(check=cid):
                self.assertTrue(wanted & by_check[cid],
                                "%s found in %s, expected one of %s"
                                % (cid, by_check[cid], wanted))

    def test_clean_fixture_precision(self):
        # Findings on the corrected twin are false positives. A small set of
        # inherently advisory checks is tolerated; everything else is a bug.
        advisory = {"H7", "O3", "C6", "T2", "H8"}
        fps = [f for f in self.clean_found if f.check_id not in advisory]
        precision = 1.0 - (len(fps) / float(max(len(set(self.expected)), 1)))
        self.assertGreaterEqual(
            precision, 0.95,
            "false positives on clean fixture: %s"
            % sorted({(f.check_id, f.file) for f in fps}))

    def test_clean_fixture_has_no_p0(self):
        p0 = [f for f in self.clean_found if CHECKS[f.check_id].severity == "P0"]
        self.assertEqual(p0, [], "P0 false positives: %s"
                                 % [(f.check_id, f.file) for f in p0])

    def test_fixture_readme_warns_it_is_intentionally_vulnerable(self):
        text = (ROOT / "tests" / "fixtures" / "README.md").read_text()
        self.assertIn("intentionally vulnerable", text.lower())


if __name__ == "__main__":
    unittest.main()
