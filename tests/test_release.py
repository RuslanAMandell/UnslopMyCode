import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


class TestReleaseConsistency(unittest.TestCase):
    """Every place a version appears has to agree.

    Users install the tag named in the marketplace source. If that ref, the
    plugin version, and the changelog drift apart, people receive code that is
    not the code the release claims to be.
    """

    def setUp(self):
        self.plugin = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
        self.market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
        self.entry = self.market["plugins"][0]

    def test_version_is_semver(self):
        self.assertRegex(self.plugin["version"], SEMVER_RE)

    def test_plugin_and_marketplace_versions_agree(self):
        self.assertEqual(self.entry.get("version"), self.plugin["version"])
        self.assertEqual(self.market["metadata"]["version"], self.plugin["version"])

    def test_source_pins_a_tag_not_a_branch(self):
        source = self.entry["source"]
        self.assertIsInstance(source, dict,
                              "a bare './' source installs whatever is on the "
                              "default branch, which makes main the live channel")
        self.assertEqual(source["source"], "github")
        self.assertEqual(source["ref"], "v" + self.plugin["version"])

    def test_changelog_documents_this_version(self):
        text = (ROOT / "CHANGELOG.md").read_text()
        self.assertIn("## %s" % self.plugin["version"], text,
                      "the released version has no changelog entry")

    def test_release_script_is_executable(self):
        import os
        script = ROOT / "scripts" / "release.sh"
        self.assertTrue(script.is_file())
        self.assertTrue(os.access(script, os.X_OK), "scripts/release.sh is not executable")
