import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop.catalog import CHECKS                # noqa: E402


class TestReadme(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "README.md").read_text()

    def test_title_is_the_project_name(self):
        self.assertTrue(self.text.startswith("# UnslopMyCode\n"),
                        "README must lead with the project name")

    def test_install_command_is_present_and_correct(self):
        self.assertIn("/plugin marketplace add RuslanAMandell/UnslopMyCode", self.text)
        self.assertIn("/plugin install unslop@unslop-my-code", self.text)

    def test_claims_the_real_check_count(self):
        self.assertIn(str(len(CHECKS)), self.text)

    def test_documents_every_domain(self):
        for name in ("Secrets", "access control", "unhappy path", "Cost",
                     "Supply chain", "AI rot", "Observability", "Deployment", "Tests"):
            with self.subTest(domain=name):
                self.assertIn(name, self.text)

    def test_no_broken_relative_links(self):
        for rel in re.findall(r"\]\((?!https?:)([^)#]+)\)", self.text):
            with self.subTest(link=rel):
                self.assertTrue((ROOT / rel).exists(), rel)

    def test_publishes_the_corpus_study(self):
        import json
        agg = json.loads((ROOT / "research/results/aggregate.json").read_text())
        self.assertIn(str(agg["repos_scanned"]), self.text,
                      "README must state the corpus size actually measured")
        self.assertIn("%.1f%%" % agg["repos_with_any_p0_pct"], self.text,
                      "README must state the measured critical rate")
        self.assertIn("research/METHOD.md", self.text,
                      "README must link the methodology, not just the result")

    def test_charts_match_the_data(self):
        """Regenerating must be a no-op: a stale chart is a wrong claim."""
        import subprocess
        results = ROOT / "research" / "results"
        before = {p.name: p.read_text() for p in sorted(results.glob("*.svg"))}
        self.assertTrue(before, "no charts generated")
        subprocess.run([sys.executable, str(ROOT / "research" / "make_charts.py")],
                       capture_output=True, check=True)
        after = {p.name: p.read_text() for p in sorted(results.glob("*.svg"))}
        self.assertEqual(before, after,
                         "charts are stale: run python3 research/make_charts.py")

    def test_every_headline_figure_matches_aggregate_json(self):
        import json
        agg = json.loads((ROOT / "research/results/aggregate.json").read_text())
        crit = agg["critical_prevalence_pct"]
        for label, value in (
            ("critical rate", "%.1f%%" % agg["repos_with_any_p0_pct"]),
            ("supabase rate", "%.1f%%" % agg["segments"]["supabase"]["with_p0_pct"]),
            ("committed .env", "%.1f%%" % crit["S3"]),
            ("hardcoded credential", "%.1f%%" % crit["S1"]),
            ("rls disabled", "%.1f%%" % crit["D1"]),
            ("files analyzed", format(agg["files_scanned_total"], ",")),
        ):
            with self.subTest(figure=label):
                self.assertIn(value, self.text,
                              "README figure for %s does not match the data" % label)

    def test_charts_are_theme_aware(self):
        text = self.text
        self.assertIn("prefers-color-scheme: dark", text)
        self.assertIn("prefers-color-scheme: light", text)
        for name in ("domains-dark", "domains-light", "critical-dark", "critical-light"):
            with self.subTest(chart=name):
                self.assertTrue((ROOT / ("research/results/%s.svg" % name)).exists())

    def test_charts_have_alt_text(self):
        import re
        for m in re.finditer(r"<img alt=\"([^\"]*)\"", self.text):
            with self.subTest(alt=m.group(1)[:40]):
                self.assertGreater(len(m.group(1)), 60,
                                   "chart alt text must describe the data, not just name it")

    def test_credits_prior_art(self):
        self.assertIn("vibecoding-security-scanner", self.text)
        self.assertIn("trailofbits", self.text)

    def test_states_what_it_will_not_do(self):
        low = self.text.lower()
        self.assertIn("not a penetration test", low)

    def test_states_the_fixture_warning(self):
        text = (ROOT / "tests" / "fixtures" / "README.md").read_text()
        self.assertIn("intentionally vulnerable", text.lower())

    def test_command_front_door_exists(self):
        cmd = (ROOT / "commands" / "unslop.md").read_text()
        self.assertIn("unslop-audit", cmd)
        self.assertIn("unslop-fix", cmd)


if __name__ == "__main__":
    unittest.main()
