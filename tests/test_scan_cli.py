import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCAN = ROOT / "skills" / "unslop-audit" / "scripts" / "scan.py"


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def run_scan(root, *args):
    out = Path(root) / ".unslop" / "findings.json"
    r = subprocess.run([sys.executable, str(SCAN), str(root), "--out", str(out)] + list(args),
                       capture_output=True, text=True)
    return r, json.loads(out.read_text())


class TestScanCli(unittest.TestCase):
    def test_exits_zero_and_writes_schema(self):
        root = tree({"src/a.ts": "const k = '%s'" % ("AKIA" + "3XKQZ7RTBV2NWPLQ")})
        r, data = run_scan(root)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(data["schemaVersion"], 1)
        self.assertIn("S1", {f["check_id"] for f in data["findings"]})
        self.assertGreaterEqual(data["coverage"]["scanned_files"], 1)

    def test_empty_project_is_clear_not_crash(self):
        root = tree({"README.md": "# hello"})
        r, data = run_scan(root)
        self.assertEqual(r.returncode, 0)
        self.assertIsInstance(data["findings"], list)

    def test_s5_env_drift(self):
        root = tree({"src/a.ts": "const u = process.env.DATABASE_URL",
                     ".env.example": "OTHER_KEY=\n"})
        _, data = run_scan(root)
        s5 = [f for f in data["findings"] if f["check_id"] == "S5"]
        self.assertTrue(s5)
        self.assertIn("DATABASE_URL", s5[0]["snippet"])

    def test_s5_quiet_when_documented(self):
        root = tree({"src/a.ts": "const u = process.env.DATABASE_URL",
                     ".env.example": "DATABASE_URL=\n"})
        _, data = run_scan(root)
        self.assertEqual([f for f in data["findings"] if f["check_id"] == "S5"], [])

    def test_o3_collapses_per_file(self):
        root = tree({"src/a.ts": "\n".join("console.log(%d)" % i for i in range(40))})
        _, data = run_scan(root)
        o3 = [f for f in data["findings"] if f["check_id"] == "O3"]
        self.assertEqual(len(o3), 1)
        self.assertIn("40", o3[0]["snippet"])

    def test_stack_recorded_in_coverage(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"}}'})
        _, data = run_scan(root)
        self.assertIn("nextjs", data["coverage"]["stack"])

    def test_json_flag_prints_summary_to_stdout(self):
        root = tree({"src/a.ts": "const k = '%s'" % ("AKIA" + "3XKQZ7RTBV2NWPLQ")})
        r, _ = run_scan(root, "--json")
        summary = json.loads(r.stdout)
        self.assertIn("counts", summary)
        self.assertGreaterEqual(summary["counts"]["P0"], 1)


if __name__ == "__main__":
    unittest.main()
