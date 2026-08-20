import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import detectors                                             # noqa: E402
from unslop.detectors import gitignore, sqlrls, deps, gitmeta, project   # noqa: E402
from unslop.findings import Coverage                                     # noqa: E402
from unslop.walker import walk                                           # noqa: E402


def tree(files):
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return d


def ids(findings):
    return sorted({f.check_id for f in findings})


class TestGitignore(unittest.TestCase):
    def test_s3_env_not_ignored(self):
        root = tree({".env": "SECRET=x", ".gitignore": "node_modules\n"})
        cov = Coverage()
        self.assertIn("S3", ids(gitignore.detect(root, walk(root, cov), cov)))

    def test_s3_clean_when_ignored(self):
        root = tree({".env": "SECRET=x", ".gitignore": ".env\nnode_modules\n"})
        cov = Coverage()
        self.assertNotIn("S3", ids(gitignore.detect(root, walk(root, cov), cov)))

    def test_s6_production_sourcemaps(self):
        root = tree({"next.config.js": "module.exports = { productionBrowserSourceMaps: true }"})
        cov = Coverage()
        self.assertIn("S6", ids(gitignore.detect(root, walk(root, cov), cov)))


class TestSqlRls(unittest.TestCase):
    def test_d1_table_without_rls(self):
        root = tree({"supabase/migrations/0001.sql":
                     "create table public.profiles (id uuid primary key, email text);"})
        cov = Coverage()
        self.assertIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d1_clear_when_rls_enabled(self):
        root = tree({"supabase/migrations/0001.sql":
                     "create table public.profiles (id uuid primary key);\n"
                     "alter table public.profiles enable row level security;\n"
                     "create policy p on public.profiles for select using (auth.uid() = id);"})
        cov = Coverage()
        self.assertNotIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d2_permissive_policy(self):
        root = tree({"supabase/migrations/0002.sql":
                     "create table t (id int);\nalter table t enable row level security;\n"
                     "create policy open on t for all using (true);"})
        cov = Coverage()
        self.assertIn("D2", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d4_public_bucket(self):
        root = tree({"supabase/migrations/0003.sql":
                     "insert into storage.buckets (id, name, public) values ('avatars','avatars', true);"})
        cov = Coverage()
        self.assertIn("D4", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d9_open_firebase_rules(self):
        root = tree({"firestore.rules":
                     "service cloud.firestore {\n match /{document=**} {\n allow read, write: if true;\n }\n}"})
        cov = Coverage()
        self.assertIn("D9", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_c2_filtered_column_without_index(self):
        root = tree({
            "supabase/migrations/0001.sql": "create table orders (id uuid primary key, user_id uuid);",
            "src/api.ts": "await supabase.from('orders').select('*').eq('user_id', uid).limit(10)",
        })
        cov = Coverage()
        self.assertIn("C2", ids(sqlrls.detect(root, walk(root, cov), cov)))


class TestDeps(unittest.TestCase):
    def test_p3_missing_lockfile(self):
        root = tree({"package.json": '{"dependencies":{"next":"15.0.0"}}'})
        cov = Coverage()
        self.assertIn("P3", ids(deps.detect(root, walk(root, cov), cov)))

    def test_p5_install_script(self):
        root = tree({
            "package.json": '{"dependencies":{"sharp":"1.0.0"}}',
            "package-lock.json": '{"lockfileVersion":3,"packages":{"node_modules/sharp":{"hasInstallScript":true}}}',
        })
        cov = Coverage()
        found = ids(deps.detect(root, walk(root, cov), cov))
        self.assertIn("P5", found)
        self.assertNotIn("P3", found)


class TestGitMeta(unittest.TestCase):
    def test_h1_no_git(self):
        root = tree({"src/a.ts": "x"})
        cov = Coverage()
        self.assertIn("H1", ids(gitmeta.detect(root, walk(root, cov), cov)))

    def test_h1_single_commit(self):
        root = tree({"src/a.ts": "x"})
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"],
                    ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "initial"]):
            subprocess.run(cmd, cwd=root, check=True, capture_output=True)
        cov = Coverage()
        self.assertIn("H1", ids(gitmeta.detect(root, walk(root, cov), cov)))


class TestProject(unittest.TestCase):
    def test_r1_no_error_boundary(self):
        root = tree({"package.json": '{"dependencies":{"react":"19.0.0"}}',
                     "src/App.tsx": "export default function App(){return <div/>}"})
        cov = Coverage()
        self.assertIn("R1", ids(project.detect(root, walk(root, cov), cov)))

    def test_x2_missing_security_headers(self):
        root = tree({"next.config.js": "module.exports = {}"})
        cov = Coverage()
        self.assertIn("X2", ids(project.detect(root, walk(root, cov), cov)))

    def test_t1_placeholder_test_script(self):
        root = tree({"package.json":
                     '{"scripts":{"test":"echo \\"Error: no test specified\\" && exit 1"}}'})
        cov = Coverage()
        found = ids(project.detect(root, walk(root, cov), cov))
        self.assertIn("T1", found)
        self.assertIn("T3", found)


class TestRegistry(unittest.TestCase):
    def test_detector_check_ids_union(self):
        got = detectors.detector_check_ids()
        self.assertTrue({"S3", "S4", "D1", "H1", "R1", "T3"} <= got)


if __name__ == "__main__":
    unittest.main()


class TestTestPathAwareness(unittest.TestCase):
    """Fixture migrations and .env files describe test data, not production."""

    def test_sql_under_a_fixtures_directory_is_not_reported(self):
        root = tree({"tests/fixtures/app/migrations/0001.sql":
                     "create table public.profiles (id uuid primary key);"})
        cov = Coverage()
        self.assertNotIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_env_under_a_fixtures_directory_is_not_reported(self):
        root = tree({"tests/fixtures/app/.env": "SECRET=x", ".gitignore": "node_modules\n"})
        cov = Coverage()
        self.assertNotIn("S3", ids(gitignore.detect(root, walk(root, cov), cov)))

    def test_real_migrations_are_still_reported(self):
        root = tree({"supabase/migrations/0001.sql":
                     "create table public.profiles (id uuid primary key);"})
        cov = Coverage()
        self.assertIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))


class TestDatabaseCheckScoping(unittest.TestCase):
    """RLS is a Supabase expectation, and permissive reads are often deliberate."""

    def test_d1_does_not_fire_on_plain_postgres(self):
        root = tree({"db/migration/000001_init.up.sql":
                     "create table patients (id serial primary key, name text);"})
        cov = Coverage()
        found = ids(sqlrls.detect(root, walk(root, cov), cov))
        self.assertNotIn("D1", found)
        self.assertTrue(any("Supabase" in n for n in cov.notes))

    def test_d1_fires_when_supabase_is_in_use(self):
        root = tree({
            "package.json": '{"dependencies":{"@supabase/supabase-js":"2.45.0"}}',
            "supabase/migrations/0001.sql":
                "create table public.profiles (id uuid primary key);",
        })
        cov = Coverage()
        self.assertIn("D1", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d2_ignores_a_deliberately_public_read_policy(self):
        root = tree({
            "package.json": '{"dependencies":{"@supabase/supabase-js":"2.45.0"}}',
            "supabase/migrations/0002.sql":
                "alter table public.docs enable row level security;\n"
                'create policy "public can read docs" on public.docs\n'
                "  for select using (true);",
        })
        cov = Coverage()
        self.assertNotIn("D2", ids(sqlrls.detect(root, walk(root, cov), cov)))

    def test_d2_still_flags_a_permissive_write_policy(self):
        root = tree({
            "package.json": '{"dependencies":{"@supabase/supabase-js":"2.45.0"}}',
            "supabase/migrations/0002.sql":
                "alter table public.orders enable row level security;\n"
                'create policy "orders_all" on public.orders for all using (true);',
        })
        cov = Coverage()
        self.assertIn("D2", ids(sqlrls.detect(root, walk(root, cov), cov)))
