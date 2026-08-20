import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop.detectors import structure          # noqa: E402
from unslop.findings import Coverage            # noqa: E402
from unslop.walker import SourceFile            # noqa: E402


def sf(rel, text):
    return SourceFile(Path(rel), rel, text)


def ids(fs):
    return sorted({f.check_id for f in fs})


class TestStructure(unittest.TestCase):
    def test_h2_patch_fossil_pairs(self):
        files = [sf("src/Checkout.tsx", "export const C = 1"),
                 sf("src/Checkout-fixed.tsx", "export const C = 2")]
        found = structure.detect(Path("/tmp"), files, Coverage())
        self.assertIn("H2", ids(found))
        self.assertTrue(any("Checkout" in f.snippet for f in found if f.check_id == "H2"))

    def test_h2_ignores_unrelated_names(self):
        files = [sf("src/Checkout.tsx", "a"), sf("src/Cart.tsx", "b")]
        self.assertNotIn("H2", ids(structure.detect(Path("/tmp"), files, Coverage())))

    def test_h3_orphan_module(self):
        files = [sf("src/app/page.tsx", "import { used } from './used'"),
                 sf("src/app/used.ts", "export const used = 1"),
                 sf("src/app/orphan.ts", "export const orphan = 1")]
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage()) if f.check_id == "H3"]
        self.assertEqual([f.file for f in found], ["src/app/orphan.ts"])

    def test_h6_commented_out_block(self):
        body = "\n".join("// const x%d = call(%d);" % (i, i) for i in range(6))
        self.assertIn("H6", ids(structure.detect(Path("/tmp"), [sf("src/a.ts", body)], Coverage())))

    def test_h6_ignores_prose_comments(self):
        body = "\n".join("// this explains why the thing works" for _ in range(6))
        self.assertNotIn("H6", ids(structure.detect(Path("/tmp"), [sf("src/a.ts", body)], Coverage())))

    def test_h7_oversized_file(self):
        big = sf("src/big.ts", "\n".join("const x%d = %d" % (i, i) for i in range(700)))
        self.assertIn("H7", ids(structure.detect(Path("/tmp"), [big], Coverage())))

    def test_h8_triplicated_block(self):
        block = "if (!user) {\n  throw new Error('unauthorized request rejected')\n}\n"
        files = [sf("src/a.ts", block), sf("src/b.ts", block), sf("src/c.ts", block)]
        self.assertIn("H8", ids(structure.detect(Path("/tmp"), files, Coverage())))


if __name__ == "__main__":
    unittest.main()
