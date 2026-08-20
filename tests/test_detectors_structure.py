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


class TestPathAliasResolution(unittest.TestCase):
    """Alias imports resolve, and duplicate blocks collapse to one finding."""

    def test_h3_understands_path_aliases(self):
        # "@/..." is the default alias in Vite and Next scaffolds. Without
        # resolving it, every alias-imported module looks orphaned.
        files = [sf("src/app/page.tsx", 'import { Button } from "@/components/ui/button"'),
                 sf("src/components/ui/button.tsx", "export const Button = () => null")]
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage())
                 if f.check_id == "H3"]
        self.assertEqual(found, [], "alias import treated as orphan")

    def test_h3_still_flags_a_genuine_orphan(self):
        files = [sf("src/app/page.tsx", 'import { Button } from "@/components/ui/button"'),
                 sf("src/components/ui/button.tsx", "export const Button = () => null"),
                 sf("src/lib/dead.ts", "export const dead = 1")]
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage())
                 if f.check_id == "H3"]
        self.assertEqual([f.file for f in found], ["src/lib/dead.ts"])

    def test_h8_collapses_to_one_finding_per_repo(self):
        # A component library has hundreds of near-identical blocks. One finding
        # per block buries every other finding in the report.
        files = []
        for i in range(12):
            body = "\n".join([
                "export function Card%d({ title, children }) {" % i,
                "  const cls = 'rounded border bg-white p-4 shadow-sm'",
                "  return <div className={cls}>{title}{children}</div>",
                "}",
            ])
            files.append(sf("src/ui/card%d.tsx" % i, body))
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage())
                 if f.check_id == "H8"]
        self.assertEqual(len(found), 1)
        self.assertIn("repeated", found[0].snippet)


class TestEntrypointAndProseScoping(unittest.TestCase):
    """Entrypoints, prose, and test trees are out of scope for structure checks."""

    def test_h3_recognizes_a_python_main_guard(self):
        # A script with `if __name__ == "__main__"` is an entrypoint. Nothing
        # imports it because nothing is supposed to.
        files = [sf("research/collect_corpus.py",
                    "def main():\n    pass\n\n\nif __name__ == \"__main__\":\n    main()\n")]
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage())
                 if f.check_id == "H3"]
        self.assertEqual(found, [])

    def test_h3_still_flags_a_python_module_nothing_imports(self):
        files = [sf("src/app.py", "import os\n"),
                 sf("src/dead.py", "def helper():\n    return 1\n")]
        found = [f for f in structure.detect(Path("/tmp"), files, Coverage())
                 if f.check_id == "H3"]
        self.assertEqual([f.file for f in found], ["src/dead.py"])

    def test_h7_ignores_prose_files(self):
        # A long design document is not context rot in code.
        doc = sf("docs/plan.md", "\n".join("line %d of prose" % i for i in range(900)))
        found = [f for f in structure.detect(Path("/tmp"), [doc], Coverage())
                 if f.check_id == "H7"]
        self.assertEqual(found, [])

    def test_h7_still_flags_an_oversized_source_file(self):
        big = sf("src/big.ts", "\n".join("const x%d = %d" % (i, i) for i in range(700)))
        self.assertIn("H7", ids(structure.detect(Path("/tmp"), [big], Coverage())))

    def test_structure_checks_skip_test_and_fixture_trees(self):
        files = [
            sf("tests/fixtures/app/src/Checkout.tsx", "export const C = 1"),
            sf("tests/fixtures/app/src/Checkout-fixed.tsx", "export const C = 2"),
            sf("tests/fixtures/app/src/orphan.ts", "export const o = 1"),
        ]
        self.assertEqual(structure.detect(Path("/tmp"), files, Coverage()), [])
