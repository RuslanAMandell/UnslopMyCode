import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "skills" / "unslop-audit"
sys.path.insert(0, str(AUDIT / "scripts"))
from unslop.catalog import CHECKS                # noqa: E402


class TestDocs(unittest.TestCase):
    def test_catalog_doc_is_in_sync(self):
        generated = subprocess.run(
            [sys.executable, str(AUDIT / "scripts" / "gen_catalog_doc.py")],
            capture_output=True, text=True, check=True).stdout
        on_disk = (AUDIT / "references" / "check-catalog.md").read_text()
        self.assertEqual(generated, on_disk,
                         "run: python3 scripts/gen_catalog_doc.py > references/check-catalog.md")

    def test_every_semantic_check_has_a_procedure(self):
        text = (AUDIT / "references" / "semantic-passes.md").read_text()
        for cid, chk in CHECKS.items():
            if chk.method == "semantic":
                with self.subTest(check=cid):
                    self.assertIn("## %s " % cid, text)

    def test_skill_references_resolve(self):
        text = (AUDIT / "SKILL.md").read_text()
        for rel in re.findall(r"\]\((references/[^)]+|scripts/[^)]+)\)", text):
            with self.subTest(link=rel):
                self.assertTrue((AUDIT / rel).exists(), rel)

    def test_skill_forbids_editing_code(self):
        self.assertIn("never edit", (AUDIT / "SKILL.md").read_text().lower())

    def test_skill_tells_the_agent_to_gitignore_the_report(self):
        self.assertIn(".gitignore", (AUDIT / "SKILL.md").read_text())

    def test_skill_covers_the_p4_gap_with_ecosystem_audit(self):
        text = (AUDIT / "SKILL.md").read_text() + \
            (AUDIT / "references" / "semantic-passes.md").read_text()
        self.assertIn("npm audit", text)

    def test_stack_notes_exist_for_every_detected_tag(self):
        notes = {p.stem for p in (AUDIT / "references" / "stack-notes").glob("*.md")}
        self.assertTrue({"supabase", "firebase", "nextjs", "vercel"} <= notes)


if __name__ == "__main__":
    unittest.main()
