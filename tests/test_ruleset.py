import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
from unslop import rules                        # noqa: E402
from unslop.ruleset import RULES                # noqa: E402
from unslop.walker import SourceFile            # noqa: E402

BY_ID = {}
for _r in RULES:
    BY_ID.setdefault(_r.check_id, []).append(_r)


def fires(check_id, rel, text):
    f = SourceFile(Path(rel), rel, text)
    return [x for x in rules.run(BY_ID[check_id], [f]) if x.check_id == check_id]


class TestRuleset(unittest.TestCase):
    def test_s1_aws_and_stripe_keys(self):
        self.assertTrue(fires("S1", "src/a.ts", "const k='REDACTED-FAKE-TEST-VALUE'"))
        self.assertTrue(fires("S1", "src/a.ts", "const k='REDACTED-FAKE-TEST-VALUE'"))

    def test_s1_ignores_env_reads_and_placeholders(self):
        self.assertFalse(fires("S1", "src/a.ts", "const key = process.env.STRIPE_SECRET_KEY"))
        self.assertFalse(fires("S1", "src/a.ts", "const apiKey = 'your-api-key-here'"))

    def test_s2_public_prefixed_secret(self):
        self.assertTrue(fires("S2", "src/a.ts", "process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY"))
        self.assertFalse(fires("S2", "src/a.ts", "process.env.NEXT_PUBLIC_SITE_URL"))

    def test_d8_sql_interpolation(self):
        self.assertTrue(fires("D8", "src/db.ts", "db.query(`SELECT * FROM users WHERE id = ${id}`)"))
        self.assertFalse(fires("D8", "src/db.ts", "db.query('SELECT * FROM users WHERE id = $1', [id])"))

    def test_a3_cookie_flags(self):
        self.assertTrue(fires("A3", "src/s.ts", "res.cookie('sid', t, { maxAge: 900000 })"))
        self.assertFalse(fires("A3", "src/s.ts",
                               "res.cookie('sid', t, { httpOnly: true, secure: true, sameSite: 'lax' })"))

    def test_a5_wildcard_cors(self):
        self.assertTrue(fires("A5", "src/api.ts", "'Access-Control-Allow-Origin': '*'"))

    def test_r2_unchecked_fetch(self):
        self.assertTrue(fires("R2", "src/a.ts", "const r = await fetch(u)\nconst j = await r.json()"))
        self.assertFalse(fires("R2", "src/a.ts", "const r = await fetch(u)\nif (!r.ok) return null"))

    def test_r5_empty_catch(self):
        self.assertTrue(fires("R5", "src/a.ts", "try { go() } catch (e) {}"))
        self.assertTrue(fires("R5", "src/a.py", "try:\n    go()\nexcept Exception:\n    pass\n"))

    def test_c3_unbounded_select(self):
        self.assertTrue(fires("C3", "src/a.ts", "await supabase.from('orders').select('*')"))
        self.assertFalse(fires("C3", "src/a.ts", "await supabase.from('orders').select('*').limit(50)"))

    def test_c5_polling(self):
        self.assertTrue(fires("C5", "src/a.ts", "setInterval(refresh, 2000)"))
        self.assertFalse(fires("C5", "src/a.ts", "setInterval(refresh, 300000)"))

    def test_o1_secret_in_log(self):
        self.assertTrue(fires("O1", "src/a.ts", "console.log('token', accessToken)"))

    def test_o2_stack_trace_to_client(self):
        self.assertTrue(fires("O2", "src/api.ts", "res.status(500).json({ error: err.stack })"))

    def test_x3_open_redirect(self):
        self.assertTrue(fires("X3", "src/api.ts", "res.redirect(req.query.next)"))

    def test_h5_mock_on_prod_path(self):
        self.assertTrue(fires("H5", "src/app/api/orders/route.ts", "const MOCK_ORDERS = []"))


if __name__ == "__main__":
    unittest.main()
