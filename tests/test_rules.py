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
        key = "AKIA" + "ABCDEFGHIJKLMNOP"   # split: no provider-shaped literal in-file
        f = sf("src/a.ts", "const x = 1\nconst k = '%s'\n" % key)
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
        a, b = "AKIA" + "A" * 16, "AKIA" + "B" * 16
        f = sf("a.ts", "%s %s\n" % (a, b))
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


class TestTestPathHandling(unittest.TestCase):
    """A project's own test tree is not its production surface."""

    def test_rules_skip_test_paths_by_default(self):
        r = rules.Rule("C3", re.compile(r"SELECT \* FROM"))
        for rel in ("tests/test_ruleset.py", "tests/fixtures/app/db.ts",
                    "src/__tests__/db.test.ts", "spec/db_spec.rb"):
            with self.subTest(rel=rel):
                self.assertEqual(rules.run([r], [sf(rel, "SELECT * FROM users")]), [],
                                 rel)

    def test_rules_still_apply_to_production_paths(self):
        r = rules.Rule("C3", re.compile(r"SELECT \* FROM"))
        self.assertEqual(len(rules.run([r], [sf("src/db.ts", "SELECT * FROM users")])), 1)

    def test_a_path_merely_containing_test_is_not_a_test_path(self):
        r = rules.Rule("C3", re.compile(r"SELECT \* FROM"))
        for rel in ("src/latest/db.ts", "src/contest/db.ts", "src/protester.ts"):
            with self.subTest(rel=rel):
                self.assertEqual(len(rules.run([r], [sf(rel, "SELECT * FROM u")])), 1, rel)

    def test_a_rule_can_opt_in_to_test_paths(self):
        r = rules.Rule("T2", re.compile(r"it\("), allow_tests=True)
        self.assertEqual(len(rules.run([r], [sf("tests/a.test.ts", "it('x', () => {})")])), 1)
