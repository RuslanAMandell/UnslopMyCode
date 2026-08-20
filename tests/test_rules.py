import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import rules                        # noqa: E402
from unslop.walker import SourceFile            # noqa: E402


def sf(rel, text):
    return SourceFile(Path(rel), rel, text)


class TestRuleEngine(unittest.TestCase):
    def test_simple_match_reports_line_and_snippet(self):
        r = rules.Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"))
        f = sf("src/a.ts", "const x = 1\nconst k = 'REDACTED-FAKE-TEST-VALUE'\n")
        found = rules.run([r], [f])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].line, 2)
        self.assertIn("AKIA", found[0].snippet)

    def test_includes_filters_by_suffix(self):
        r = rules.Rule("S1", re.compile(r"AKIA"), includes=(".py",))
        self.assertEqual(rules.run([r], [sf("a.ts", "AKIA")]), [])
        self.assertEqual(len(rules.run([r], [sf("a.py", "AKIA")])), 1)

    def test_absent_suppresses_when_guard_present(self):
        r = rules.Rule("R2", re.compile(r"await fetch\("),
                       absent=(re.compile(r"\.ok\b|\.status\b"),), window=120)
        guarded = sf("a.ts", "const r = await fetch(u)\nif (!r.ok) throw new Error('x')\n")
        bare = sf("b.ts", "const r = await fetch(u)\nconst j = await r.json()\n")
        self.assertEqual(rules.run([r], [guarded]), [])
        self.assertEqual(len(rules.run([r], [bare])), 1)

    def test_predicate_gates_the_match(self):
        r = rules.Rule("C5", re.compile(r"setInterval\([^,]+,\s*(\d+)\s*\)"),
                       predicate=lambda m, f: int(m.group(1)) < 30000)
        self.assertEqual(len(rules.run([r], [sf("a.ts", "setInterval(tick, 1000)")])), 1)
        self.assertEqual(rules.run([r], [sf("b.ts", "setInterval(tick, 60000)")]), [])

    def test_dedupes_repeat_matches_on_same_line(self):
        r = rules.Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"))
        f = sf("a.ts", "REDACTED-FAKE-TEST-VALUE REDACTED-FAKE-TEST-VALUE\n")
        self.assertEqual(len(rules.run([r], [f])), 1)

    def test_entropy_separates_secrets_from_words(self):
        self.assertGreater(rules.shannon_entropy("k3J8sQ2mNp0zXv7LtB4y"), 3.5)
        self.assertLess(rules.shannon_entropy("password"), 3.5)

    def test_placeholder_detection(self):
        for s in ("your-api-key-here", "xxxxxxxxxxxx", "changeme", "<YOUR_KEY>",
                  "process.env.API_KEY", "sk-example"):
            self.assertTrue(rules.PLACEHOLDER_RE.search(s), s)


if __name__ == "__main__":
    unittest.main()
