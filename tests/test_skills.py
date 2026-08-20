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

    def test_marketplace_identifiers_are_kebab_case(self):
        """The plugin spec requires kebab-case identifiers; branding goes in
        displayName, which allows any casing."""
        mk = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertTrue(NAME_RE.match(mk["name"]), mk["name"])
        for plugin in mk["plugins"]:
            with self.subTest(plugin=plugin["name"]):
                self.assertTrue(NAME_RE.match(plugin["name"]), plugin["name"])
        self.assertEqual(mk["plugins"][0]["displayName"], "UnslopMyCode")

    def test_marketplace_does_not_redeclare_plugin_components(self):
        """plugin.json owns the component list; the marketplace must not repeat it.

        Declaring components in both places fails the load with "conflicting
        manifests". Skills are auto-discovered from skills/ at the plugin root.
        """
        mk = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        component_keys = ("skills", "commands", "agents", "hooks", "mcpServers")
        for plugin in mk["plugins"]:
            for key in component_keys:
                with self.subTest(plugin=plugin["name"], key=key):
                    self.assertNotIn(
                        key, plugin,
                        "marketplace entry redeclares %s; plugin.json already owns it"
                        % key)

    def test_skills_are_discoverable_at_the_plugin_root(self):
        on_disk = {p.parent.name for p in SKILLS.glob("*/SKILL.md")}
        self.assertEqual(on_disk, {"unslop-audit", "unslop-fix", "unslop-guard"})


if __name__ == "__main__":
    unittest.main()


class TestLicensing(unittest.TestCase):
    """One license, stated identically everywhere it is declared."""

    SPDX = "Apache-2.0"

    def test_license_file_is_the_real_apache_text(self):
        text = (ROOT / "LICENSE").read_text()
        for marker in ("Apache License",
                       "Version 2.0, January 2004",
                       "http://www.apache.org/licenses/",
                       "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
                       '"AS IS" BASIS'):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)
        self.assertNotIn("[name of copyright owner]", text,
                         "the appendix placeholder was left unfilled")
        self.assertIn("Copyright 2026 Ruslan Mandell", text)

    def test_notice_file_exists(self):
        self.assertIn("Apache", (ROOT / "LICENSE").read_text())
        self.assertTrue((ROOT / "NOTICE").is_file(), "Apache 2.0 expects a NOTICE file")

    def test_every_manifest_declares_the_same_spdx_id(self):
        plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(plugin["license"], self.SPDX)
        market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        for entry in market["plugins"]:
            with self.subTest(plugin=entry["name"]):
                self.assertEqual(entry.get("license"), self.SPDX)

    def test_every_skill_declares_the_same_license(self):
        for path in sorted(SKILLS.glob("*/SKILL.md")):
            fields, _ = parse_frontmatter(path.read_text())
            with self.subTest(skill=path.parent.name):
                self.assertEqual(fields.get("license"), self.SPDX)

    def test_readme_states_the_license(self):
        text = (ROOT / "README.md").read_text()
        self.assertIn("Apache License 2.0", text)
        self.assertNotIn("MIT", text)
