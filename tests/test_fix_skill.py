import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop.catalog import CHECKS                # noqa: E402

FIX = ROOT / "skills" / "unslop-fix"


class TestFixSkill(unittest.TestCase):
    def setUp(self):
        self.text = (FIX / "SKILL.md").read_text()
        self.recipes = (FIX / "references" / "fix-recipes.md").read_text()

    def test_states_the_branch_and_commit_protocol(self):
        for phrase in ("unslop/fixes", "one commit per finding", "dirty working tree"):
            with self.subTest(phrase=phrase):
                self.assertIn(phrase, self.text)

    def test_refuses_to_fake_rotation(self):
        low = self.text.lower()
        self.assertIn("rotat", low)
        self.assertIn("deleting it from head does not", low)

    def test_forbids_stacking_a_third_patch(self):
        self.assertIn("failed twice", self.text.lower())

    def test_every_auto_and_assisted_check_has_a_recipe(self):
        for cid, chk in CHECKS.items():
            if chk.fix_class in ("auto", "assisted"):
                with self.subTest(check=cid):
                    self.assertIn("### %s " % cid, self.recipes)

    def test_manual_checks_are_not_silently_dropped(self):
        for cid, chk in CHECKS.items():
            if chk.fix_class == "manual":
                with self.subTest(check=cid):
                    self.assertIn(cid, self.recipes)


if __name__ == "__main__":
    unittest.main()
