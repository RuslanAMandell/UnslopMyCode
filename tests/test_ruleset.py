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
        # Prefixes are concatenated at runtime so this file never contains a
        # contiguous provider-shaped key for GitHub push protection to flag.
        aws = "AKIA" + "3XKQZ7RTBV2NWPLQ"
        stripe = "sk_" + "live_51H8qMkJ2eRb7TnZaWvXcYd0F"
        self.assertTrue(fires("S1", "src/a.ts", "const k='%s'" % aws))
        self.assertTrue(fires("S1", "src/a.ts", "const k='%s'" % stripe))

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


class TestFrameworkShapes(unittest.TestCase):
    """Real framework idioms the patterns have to handle.

    Object-literal arguments, quote-bearing SQL, App Router responses, and
    fetch inside try/catch.
    """

    def test_a2_hardcoded_secret_after_object_literal_first_arg(self):
        self.assertTrue(fires("A2", "src/api.ts",
                              'const token = jwt.sign({ sub: id, hashed }, "dev-secret")'))

    def test_d8_interpolation_after_a_quoted_like_clause(self):
        self.assertTrue(fires(
            "D8", "src/api.ts",
            "db.query(`SELECT * FROM orders WHERE addr LIKE '%${q}%'`)"))

    def test_o2_app_router_response_leaks_stack(self):
        self.assertTrue(fires(
            "O2", "src/app/api/x/route.ts",
            "return new Response(JSON.stringify({ error: (err as Error).stack }))"))

    def test_r2_try_catch_does_not_excuse_an_unchecked_fetch(self):
        # fetch resolves normally on a 500, so the catch block never runs.
        self.assertTrue(fires("R2", "src/a.ts",
                              "try {\n  const r = await fetch(u)\n  const j = await r.json()\n"
                              "} catch (e) { report(e) }"))


if __name__ == "__main__":
    unittest.main()


class TestIdentifierVsProse(unittest.TestCase):
    """A keyword inside a message is not the thing the keyword names.

    "update" in a toast, "token" in a log line, and "password" in an enum
    member are all prose. Only a real statement or a real value counts.
    """

    # --- D8: "update" and "select" appear constantly in ordinary strings ---
    def test_d8_ignores_the_word_update_in_a_message(self):
        self.assertFalse(fires("D8", "src/a.tsx",
                               "toast.error(`Failed to update user: ${error.message}`)"))

    def test_d8_ignores_update_in_a_url_path(self):
        self.assertFalse(fires("D8", "src/api.js",
                               "await fetch(`${API_BASE_URL}/cart/update/${itemId}`)"))

    def test_d8_ignores_update_in_html_copy(self):
        self.assertFalse(fires("D8", "src/mail.ts",
                               "`<h2>${variables.marketName} Market Update</h2>`"))

    def test_d8_ignores_static_sql_in_a_migration(self):
        self.assertFalse(fires("D8", "supabase/migrations/0001.sql",
                               "INSERT INTO materials (class_id, title, type, url)\n"
                               "  VALUES ('a', 'b', 'c', 'd');"))

    def test_d8_still_catches_real_interpolated_sql(self):
        self.assertTrue(fires("D8", "src/db.ts",
                              "db.query(`SELECT * FROM users WHERE email = '${email}'`)"))
        self.assertTrue(fires("D8", "src/db.ts",
                              "db.query(`UPDATE orders SET total = ${total} WHERE id = 1`)"))
        self.assertTrue(fires("D8", "app/db.py",
                              'cur.execute(f"SELECT * FROM users WHERE id = {uid}")'))

    # --- O1: the word "token" in a message is not a leaked token ---
    def test_o1_ignores_the_word_token_in_a_message(self):
        for line in (
            "console.error('[ClerkSync] No token available')",
            "console.log('[UserProvider] Attempting to refresh token...')",
            "console.log(\"STEP 1: Getting token...\")",
        ):
            with self.subTest(line=line):
                self.assertFalse(fires("O1", "src/a.tsx", line), line)

    def test_o1_ignores_guarded_uses_that_cannot_leak(self):
        self.assertFalse(fires("O1", "src/a.tsx",
                               "console.log('token present:', !!token)"))
        self.assertFalse(fires("O1", "src/a.tsx",
                               "console.log('len', token?.length)"))

    def test_o1_still_catches_a_logged_credential(self):
        self.assertTrue(fires("O1", "src/a.tsx",
                              "console.log('Login:', email, password)"))
        self.assertTrue(fires("O1", "src/a.tsx",
                              "console.log('Token:', token.substring(0, 50))"))

    # --- S1: enum members are not credentials ---
    def test_s1_ignores_snake_case_constants(self):
        for line in ('PASSWORD_CHANGE = "password_change"',
                     'AUTHENTICATION_FAILED = "authentication_failed"'):
            with self.subTest(line=line):
                self.assertFalse(fires("S1", "app/core/enums.py", line), line)

    def test_s1_ignores_values_labelled_not_real(self):
        self.assertFalse(fires(
            "S1", ".github/workflows/deploy.yml",
            'SECRET_KEY: "test-secret-key-for-ci-only-not-real-abcdefghijklmnop1234"'))

    def test_s1_still_catches_a_real_looking_key(self):
        self.assertTrue(fires("S1", "src/ai.py",
                              'api_key="gsk_V09A8TRsOULLizZhIJ9hWGdyb3FYUcDuTIbFHePv"'))


class TestPublicCredentialScoping(unittest.TestCase):
    """Some credentials are published on purpose.

    A Supabase anon key ships to the browser by design, and a service key read
    from a private env var on the server is the correct pattern.
    """

    def test_s1_ignores_a_supabase_anon_key(self):
        # Every Supabase client ships this. It is a signed JWT with role "anon"
        # and is public by design; flagging it buries the key that matters.
        import base64
        import json as _json
        head = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        body = base64.urlsafe_b64encode(
            _json.dumps({"iss": "supabase", "role": "anon"}).encode()).decode().rstrip("=")
        anon = "%s.%s.7Hxk2QpLm4" % (head, body)
        self.assertFalse(fires("S1", "src/integrations/supabase/client.ts",
                               'const SUPABASE_PUBLISHABLE_KEY = "%s"' % anon))

    def test_s1_still_catches_a_service_role_jwt(self):
        import base64
        import json as _json
        head = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        body = base64.urlsafe_b64encode(
            _json.dumps({"iss": "supabase", "role": "service_role"}).encode()).decode().rstrip("=")
        svc = "%s.%s.7Hxk2QpLm4" % (head, body)
        self.assertTrue(fires("S1", "src/lib/admin.ts",
                              'const KEY = "%s"' % svc))

    def test_d3_ignores_server_side_usage(self):
        for path in ("backend/src/config/supabase.js",
                     "src/scripts/fix-tables.js",
                     "src/prompts/supabase_prompt.ts"):
            with self.subTest(path=path):
                self.assertFalse(
                    fires("D3", path,
                          "const key = process.env.SUPABASE_SERVICE_ROLE_KEY"), path)

    def test_d3_still_flags_a_client_module(self):
        self.assertTrue(fires("D3", "src/lib/supabaseClient.ts",
                              "const key = process.env.NEXT_PUBLIC_SERVICE_ROLE_KEY"))


class TestUrlAndInstructionScoping(unittest.TestCase):
    """Endpoint URLs and setup instructions name credentials without holding one."""

    def test_s1_ignores_oauth_urls(self):
        for line in ('token_uri: "https://oauth2.googleapis.com/token",',
                     'auth_uri: "https://accounts.google.com/o/oauth2/auth",',
                     'auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",'):
            with self.subTest(line=line):
                self.assertFalse(fires("S1", "src/config/firebase.config.js", line), line)

    def test_s1_still_catches_the_key_in_the_same_file(self):
        self.assertTrue(fires("S1", "src/config/firebase.config.js",
                              'apiKey: "AIzaSyAKfj1pKGz2ADOlamF5K0NLdda9276IfDs",'))

    def test_d3_ignores_setup_instructions_in_a_component(self):
        self.assertFalse(fires(
            "D3", "src/components/dashboard/Settings.tsx",
            "For the data sync to work, you need to add the <strong>SUPABASE_SERVICE_ROLE_KEY</strong>"))
