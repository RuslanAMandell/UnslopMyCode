import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
import verify_deps                               # noqa: E402


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


class TestVerifyDeps(unittest.TestCase):
    def test_collects_npm_and_python_deps(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"},'
                                     '"devDependencies":{"vitest":"2.0.0"}}',
                     "requirements.txt": "fastapi==0.110.0\n# comment\nuvicorn\n"})
        got = verify_deps.collect_dependencies(root)
        self.assertEqual(set(got), {"next", "vitest", "fastapi", "uvicorn"})

    def test_missing_package_becomes_p1(self):
        root = tree({"package.json": '{"dependencies":{"reqeusts-http":"1.0.0"}}'})
        fake = {"reqeusts-http": False}
        found = verify_deps.build_findings(root, fetch=lambda n, eco: fake.get(n, True))
        self.assertEqual([f.check_id for f in found], ["P1"])
        self.assertIn("reqeusts-http", found[0].snippet)

    def test_typosquat_flagged_when_package_exists(self):
        root = tree({"package.json": '{"dependencies":{"recat":"1.0.0"}}'})
        found = verify_deps.build_findings(root, fetch=lambda n, eco: True)
        self.assertIn("P2", [f.check_id for f in found])

    def test_offline_degrades_with_a_coverage_note(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"}}'})

        def boom(name, eco):
            raise OSError("network unreachable")

        found, notes = verify_deps.build_findings(root, fetch=boom, return_notes=True)
        self.assertEqual(found, [])
        self.assertTrue(any("offline" in n or "unreachable" in n for n in notes))

    def test_merge_into_existing_findings_file(self):
        root = tree({"package.json": '{"dependencies":{"ghostpkg-xyz":"1.0.0"}}'})
        out = root / ".unslop" / "findings.json"
        out.parent.mkdir(parents=True)
        out.write_text(json.dumps({
            "schemaVersion": 1,
            "coverage": {"scanned_files": 1, "skipped": [], "notes": [], "stack": []},
            "findings": []}))
        verify_deps.main([str(root), "--out", str(out)],
                         fetch=lambda n, eco: n != "ghostpkg-xyz")
        data = json.loads(out.read_text())
        self.assertIn("P1", {f["check_id"] for f in data["findings"]})

    def test_real_package_is_not_flagged(self):
        root = tree({"package.json": '{"dependencies":{"react":"19.0.0"}}'})
        self.assertEqual(verify_deps.build_findings(root, fetch=lambda n, eco: True), [])


if __name__ == "__main__":
    unittest.main()
