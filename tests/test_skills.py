import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILLS = ROOT / "skills"
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


def parse_frontmatter(text):
    if not text.startswith("---\n"):
        raise AssertionError("SKILL.md must start with YAML frontmatter")
    end = text.index("\n---\n", 3)
    body = text[end + 5:]
    fields = {}
    key = None
    for line in text[4:end].splitlines():
        m = re.match(r"^([a-z-]+):\s*(.*)$", line)
        if m:
            key = m.group(1)
            fields[key] = m.group(2).strip()
        elif key and line.startswith(" "):
            fields[key] += " " + line.strip()
    return fields, body


class TestSkillConformance(unittest.TestCase):
    def test_all_skills_have_valid_frontmatter(self):
        skill_files = sorted(SKILLS.glob("*/SKILL.md"))
        self.assertTrue(skill_files, "no SKILL.md files found")
        for path in skill_files:
            with self.subTest(skill=path.parent.name):
                fields, body = parse_frontmatter(path.read_text())
                self.assertIn("name", fields)
                self.assertIn("description", fields)
                self.assertEqual(fields["name"], path.parent.name)
                self.assertTrue(NAME_RE.match(fields["name"]))
                self.assertLessEqual(len(fields["name"]), 64)
                self.assertGreater(len(fields["description"]), 40)
                self.assertLessEqual(len(fields["description"]), 1024)
                self.assertLess(len(path.read_text().splitlines()), 500)
                self.assertGreater(len(body.strip()), 200)

    def test_marketplace_lists_every_skill(self):
        mk = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        listed = {s.split("/")[-1] for p in mk["plugins"] for s in p["skills"]}
        on_disk = {p.parent.name for p in SKILLS.glob("*/SKILL.md")}
        self.assertEqual(listed, on_disk)


if __name__ == "__main__":
    unittest.main()
