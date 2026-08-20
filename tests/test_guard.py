import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "skills" / "unslop-audit" / "scripts" / "gate.py"
GUARD = ROOT / "skills" / "unslop-guard"


def findings_file(check_ids):
    d = Path(tempfile.mkdtemp())
    p = d / "findings.json"
    p.write_text(json.dumps({
        "schemaVersion": 1,
        "coverage": {"scanned_files": 1, "skipped": [], "notes": [], "stack": []},
        "findings": [{"check_id": c, "file": "a.ts", "line": 1, "snippet": "x",
                      "confidence": "CONFIRMED", "evidence": ""} for c in check_ids],
    }))
    return p


def gate(path, *args):
    return subprocess.run([sys.executable, str(GATE), str(path)] + list(args),
                          capture_output=True, text=True)


class TestGate(unittest.TestCase):
    def test_fails_on_p0(self):
        self.assertEqual(gate(findings_file(["S1"])).returncode, 1)

    def test_passes_when_only_low_severity(self):
        self.assertEqual(gate(findings_file(["H7"])).returncode, 0)

    def test_threshold_is_configurable(self):
        self.assertEqual(gate(findings_file(["A3"]), "--fail-on", "P1").returncode, 1)
        self.assertEqual(gate(findings_file(["A3"]), "--fail-on", "P0").returncode, 0)

    def test_only_flag_narrows_to_named_checks(self):
        self.assertEqual(gate(findings_file(["D1"]), "--only", "S1,S2").returncode, 0)
        self.assertEqual(gate(findings_file(["S1"]), "--only", "S1,S2").returncode, 1)

    def test_missing_file_is_not_an_error(self):
        self.assertEqual(gate(Path("/nonexistent/findings.json")).returncode, 0)

    def test_prints_the_blocking_findings(self):
        self.assertIn("S1", gate(findings_file(["S1"])).stdout)


class TestGuardAssets(unittest.TestCase):
    def test_hook_is_warn_only_except_secrets(self):
        hook = (GUARD / "assets" / "pre-commit").read_text()
        self.assertIn("--fail-on", hook)
        self.assertIn("S1", hook)
        self.assertIn("exit 0", hook)
        self.assertIn("--no-verify", hook)

    def test_workflow_runs_the_scanner_and_the_gate(self):
        wf = (GUARD / "assets" / "unslop-audit.yml").read_text()
        self.assertIn("scan.py", wf)
        self.assertIn("gate.py", wf)


if __name__ == "__main__":
    unittest.main()
