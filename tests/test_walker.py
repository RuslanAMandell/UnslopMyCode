import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import walker                       # noqa: E402
from unslop.findings import Coverage            # noqa: E402


def make_tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


class TestWalker(unittest.TestCase):
    def test_skips_vendor_directories(self):
        root = make_tree({
            "src/a.ts": "export const a = 1",
            "node_modules/pkg/index.js": "module.exports = 1",
            ".next/build.js": "x",
            "dist/bundle.min.js": "x",
        })
        cov = Coverage()
        rels = {f.rel for f in walker.walk(root, cov)}
        self.assertEqual(rels, {"src/a.ts"})
        self.assertEqual(cov.scanned_files, 1)

    def test_skips_binary_and_oversized_files(self):
        root = make_tree({"src/a.ts": "ok", "src/big.ts": "x" * 5000})
        (root / "src" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00")
        cov = Coverage()
        rels = {f.rel for f in walker.walk(root, cov, max_file_bytes=1000)}
        self.assertEqual(rels, {"src/a.ts"})
        self.assertTrue(any("big.ts" in s for s in cov.skipped))

    def test_file_cap_is_reported_not_silent(self):
        root = make_tree({"src/f%d.ts" % i: "x" for i in range(10)})
        cov = Coverage()
        files = walker.walk(root, cov, max_files=4)
        self.assertEqual(len(files), 4)
        self.assertTrue(any("file cap" in n for n in cov.notes))

    def test_detect_stack(self):
        root = make_tree({
            "package.json": '{"dependencies":{"next":"15.0.0","@supabase/supabase-js":"2.0.0"}}',
            "pnpm-lock.yaml": "lockfileVersion: 9",
        })
        tags = walker.detect_stack(root)
        self.assertIn("nextjs", tags)
        self.assertIn("supabase", tags)
        self.assertIn("pnpm", tags)


if __name__ == "__main__":
    unittest.main()
