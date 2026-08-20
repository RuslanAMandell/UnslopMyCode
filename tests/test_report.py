import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import report                        # noqa: E402
from unslop.findings import Coverage, Finding     # noqa: E402


def f(cid, rel="src/a.ts", line=1):
    return Finding(cid, rel, line, "snippet for %s" % cid, confidence="CONFIRMED")


class TestReport(unittest.TestCase):
    def test_verdict_levels(self):
        self.assertEqual(report.verdict([f("S1")]), "DO NOT SHIP")
        self.assertEqual(report.verdict([f("A3")]), "SHIP WITH CAUTION")
        self.assertEqual(report.verdict([f("H7")]), "CLEAR")
        self.assertEqual(report.verdict([]), "CLEAR")

    def test_fix_plan_counts_by_class(self):
        plan = report.fix_plan([f("S3"), f("A3"), f("S1"), f("D5")])
        self.assertEqual(plan["auto"], 2)
        self.assertEqual(plan["manual"], 1)
        self.assertEqual(plan["assisted"], 1)

    def test_blocking_section_caps_at_five(self):
        many = [f("S1", "src/%d.ts" % i, i) for i in range(9)]
        text = report.render(many, Coverage())
        self.assertEqual(text.count("\n### "), 5)
        self.assertIn("4 more critical", text)

    def test_blocking_items_carry_evidence_and_consequence(self):
        text = report.render([f("D5", "src/app/api/orders/[id]/route.ts", 9)], Coverage())
        self.assertIn("src/app/api/orders/[id]/route.ts:9", text)
        self.assertIn("Change 1042 to 1043", text)

    def test_coverage_always_present(self):
        cov = Coverage()
        cov.scanned_files = 5
        cov.note("dependency verification skipped: offline")
        text = report.render([], cov)
        self.assertIn("## Coverage", text)
        self.assertIn("offline", text)
        self.assertIn("5 files", text)

    def test_clear_verdict_lists_what_was_checked(self):
        text = report.render([], Coverage())
        self.assertIn("CLEAR", text)
        self.assertIn("64 checks", text)

    def test_diff_between_runs(self):
        prev = [f("S1"), f("A3")]
        cur = [f("A3"), f("D5")]
        d = report.diff(prev, cur)
        self.assertEqual([x.check_id for x in d["fixed"]], ["S1"])
        self.assertEqual([x.check_id for x in d["new"]], ["D5"])
        self.assertEqual([x.check_id for x in d["unchanged"]], ["A3"])

    def test_suspected_findings_are_segregated(self):
        confirmed = f("S1")
        suspected = Finding("C3", "src/b.ts", 4, "select('*')")
        text = report.render([confirmed, suspected], Coverage())
        blocking, appendix = text.split("## Suspected", 1)
        self.assertIn("S1", blocking)
        self.assertIn("C3", appendix)


if __name__ == "__main__":
    unittest.main()
