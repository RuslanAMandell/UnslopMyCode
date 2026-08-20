import re

from .rules import (QUOTED_RE, Rule, is_public_jwt, logs_a_sensitive_value,
                    looks_like_a_credential, looks_like_example)

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue", ".astro")
PY = (".py",)
CODE = JS + PY + (".go", ".rb", ".php", ".java", ".cs", ".rs")
CFG = (".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".conf")
TEST_PATHS = ("test", "spec", "__tests__", "fixtures", "mock", ".example")
SERVER_PATHS = ("/api/", "route.ts", "route.js", "server", "actions", "handler",
                "views.py", "app.py")


# SELECT needs a FROM, UPDATE needs a SET. Prose has neither.
SQL_SHAPE = (r"(?:select\b[^`\"';]{1,200}?\bfrom\b"
             r"|insert\s+into\s+[\w.\"`\[]+"
             r"|update\s+[\w.\"`\[]+\s+set\b"
             r"|delete\s+from\s+[\w.\"`\[]+)")


def _entropic_secret(m, f):
    return looks_like_a_credential(m.group("val"))


def _on_server_path(m, f):
    rel = f.rel.lower()
    return any(p in rel for p in SERVER_PATHS)


def _real_credential(m, f):
    """Provider-prefixed match that is not a documented dummy value."""
    return not looks_like_example(m.group(0))


SERVER_ONLY_RE = re.compile(r"[\"']server-only[\"']")


# The identifier has to be used, not described. Setup instructions rendered in
# a component mention the variable name without ever holding its value.
D3_CODE_CONTEXT_RE = re.compile(r"process\.env|import\.meta\.env|createClient|eyJ|=|:")
D3_PROSE_RE = re.compile(r"(?i)<[a-z]+>|you need|add the|copy the|paste|set up|configure")


def _client_reachable_service_role(m, f):
    """A service_role key is only a finding if it can reach the browser.

    Reading it from a private env var inside a module that imports "server-only"
    is the correct pattern, not a defect. The dangerous shapes - a hardcoded
    literal, or a NEXT_PUBLIC_ prefix - stay reportable (S1 and S2 also cover
    those independently).
    """
    if SERVER_ONLY_RE.search(f.text):
        return False
    start = f.text.rfind("\n", 0, m.start()) + 1
    end = f.text.find("\n", m.end())
    line = f.text[start:end if end != -1 else len(f.text)]
    if D3_PROSE_RE.search(line) or not D3_CODE_CONTEXT_RE.search(line):
        return False
    if "process.env." in line and "NEXT_PUBLIC" not in line:
        return False
    return True


CONST_INTERP_RE = re.compile(r"\$\{\s*[A-Z][A-Z0-9_]{2,}\b")


def _interpolates_non_constant(m, f):
    """Interpolation is not injection when the value is a module constant.

    `${PINNED_MIGRATION.sha256}` is a build hash. `${email}` is user input.
    Without taint analysis this is the honest line to draw.
    """
    text = m.group(0)
    interps = re.findall(r"\$\{[^}]{0,80}\}", text)
    if not interps:
        return True
    return not all(CONST_INTERP_RE.match(i) for i in interps)


def _never(m, f):
    """Marker for checks emitted by a detector, not by a line match."""
    return False


RULES = [
    # ---- S1 hardcoded credentials ----------------------------------------
    Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"), excludes=TEST_PATHS,
         allow_docs=True, predicate=_real_credential),
    Rule("S1", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{16,}"), excludes=TEST_PATHS,
         allow_docs=True, predicate=_real_credential),
    Rule("S1", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), excludes=TEST_PATHS,
         allow_docs=True, predicate=_real_credential),
    Rule("S1", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), excludes=TEST_PATHS,
         allow_docs=True, predicate=_real_credential),
    Rule("S1", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), excludes=TEST_PATHS,
         allow_docs=True, predicate=_real_credential),
    Rule("S1", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), excludes=TEST_PATHS,
         allow_docs=True, predicate=_real_credential),
    Rule("S1", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), excludes=TEST_PATHS,
         allow_docs=True),
    Rule("S1", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key|auth)\w*"
        r"\s*[:=]\s*[\"'](?P<val>[^\"'\s]{12,})[\"']"),
        includes=CODE + CFG, excludes=TEST_PATHS, predicate=_entropic_secret),

    # ---- S2 client-exposed secret ----------------------------------------
    # TOKEN and API_KEY are deliberately absent: a Paddle client token, a GA
    # measurement id, and a Supabase anon key all carry those names and are all
    # meant to ship to the browser. Only names that cannot be public qualify.
    Rule("S2", re.compile(
        r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]*"
        r"(SERVICE_ROLE|SECRET|PRIVATE_KEY|PASSWORD|ACCESS_KEY)[A-Z0-9_]*"),
         excludes=TEST_PATHS),

    # A signed JWT pasted into source, unless it is a deliberately public one
    # (a Supabase anon key ships to the browser by design).
    Rule("S1", re.compile(r"[\"'`](eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*)"),
         excludes=TEST_PATHS,
         predicate=lambda m, f: not is_public_jwt(m.group(1))),

    # ---- S4 emitted by detectors/gitmeta.py --------------------------------
    Rule("S4", re.compile(r"^\Z"), predicate=_never),

    # ---- S5 env var references (post-filtered in scan.py) ------------------
    Rule("S5", re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})"),
         includes=JS),
    Rule("S5", re.compile(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']"),
         includes=PY),

    # ---- D3 service role client-side ---------------------------------------
    Rule("D3", re.compile(r"(?i)service[_-]?role"), includes=JS,
         excludes=("/server/", "server/", "/api/", "api/", "route.ts",
                   "supabase/functions", ".env", "backend/", "scripts/", "script/",
                   "prompt", "/lib/db", "migrations/", "seed") + TEST_PATHS,
         predicate=_client_reachable_service_role),

    # ---- D8 SQL string interpolation ---------------------------------------
    # A bare "update" or "select" appears constantly in ordinary strings
    # ("Failed to update user: ${err}", "/cart/update/${id}"). Requiring a real
    # statement shape (SELECT..FROM, UPDATE..SET, INSERT INTO, DELETE FROM) is
    # what separates injection from prose.
    Rule("D8", re.compile(r"(?is)`[^`]{0,400}?" + SQL_SHAPE + r"[^`]{0,300}?\$\{"),
         excludes=TEST_PATHS, predicate=_interpolates_non_constant),
    Rule("D8", re.compile(r"(?is)`[^`]{0,200}?\$\{[^`]{0,300}?" + SQL_SHAPE + r"[^`]{0,200}`"),
         excludes=TEST_PATHS, predicate=_interpolates_non_constant),
    Rule("D8", re.compile(r"(?is)f[\"'][^\"']{0,300}?" + SQL_SHAPE + r"[^\"']{0,200}?\{"),
         includes=PY, excludes=TEST_PATHS),
    Rule("D8", re.compile(r"(?is)[\"']" + SQL_SHAPE + r"[^\"']{0,160}[\"']\s*\+\s*\w"),
         excludes=TEST_PATHS),

    # ---- A2 JWT weaknesses ---------------------------------------------------
    Rule("A2", re.compile(r"(?i)verify\s*[:=]\s*(false|False)"), excludes=TEST_PATHS),
    Rule("A2", re.compile(r"(?i)algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']"), excludes=TEST_PATHS),
    Rule("A2", re.compile(r"jwt\.decode\((?![^)]*verify)[^)]*\)"), includes=PY),
    Rule("A2", re.compile(r"jwt\.(sign|verify)\(.{0,160}?,\s*[\"'][^\"']{1,24}[\"']"),
         includes=JS, excludes=TEST_PATHS),

    # ---- A3 cookie flags ------------------------------------------------------
    Rule("A3", re.compile(r"(?:res\.cookie|cookies\(\)\.set|setCookie)\("),
         absent=(re.compile(r"(?i)httpOnly\s*:\s*true"),), window=220),
    Rule("A3", re.compile(r"(?:res\.cookie|cookies\(\)\.set|setCookie)\("),
         absent=(re.compile(r"(?i)sameSite"),), window=220),
    Rule("A3", re.compile(r"set_cookie\("), includes=PY, excludes=TEST_PATHS,
         absent=(re.compile(r"httponly\s*=\s*True"),), window=220),

    # ---- A5 wildcard CORS -------------------------------------------------------
    Rule("A5", re.compile(r"[\"']Access-Control-Allow-Origin[\"']\s*[:,]\s*[\"']\*[\"']"),
         excludes=TEST_PATHS),
    Rule("A5", re.compile(r"origin\s*:\s*[\"']\*[\"']"), excludes=TEST_PATHS),
    Rule("A5", re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']"), includes=PY),
    Rule("A5", re.compile(r"\bcors\(\s*\)"), excludes=TEST_PATHS),

    # ---- A6 weak password storage --------------------------------------------------
    Rule("A6", re.compile(r"(?i)(md5|sha1)\s*\(\s*\w*(pass|pwd)"), excludes=TEST_PATHS),
    Rule("A6", re.compile(r"(?i)createHash\([\"'](md5|sha1|sha256)[\"']\)[^;]{0,80}(pass|pwd)")),

    # ---- R1 emitted by detectors/project.py -----------------------------------------
    Rule("R1", re.compile(r"^\Z"), predicate=_never),

    # ---- R2 unchecked fetch ------------------------------------------------------------
    Rule("R2", re.compile(r"await\s+fetch\("), includes=JS, excludes=TEST_PATHS,
         absent=(re.compile(r"\.ok\b|\.status\b|statusText"),), window=200),

    # ---- R3 no timeout --------------------------------------------------------------------
    Rule("R3", re.compile(r"\bfetch\("), includes=JS, excludes=TEST_PATHS,
         absent=(re.compile(r"signal|AbortController|timeout"),), window=200),
    Rule("R3", re.compile(r"requests\.(get|post|put|delete)\("), includes=PY, excludes=TEST_PATHS,
         absent=(re.compile(r"timeout\s*="),), window=160),

    # ---- R5 swallowed errors ------------------------------------------------------------------
    Rule("R5", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}"), includes=JS),
    Rule("R5", re.compile(r"except[^\n:]*:\s*\n\s*pass\b"), includes=PY),

    # ---- R9 floating promise ----------------------------------------------------------------------
    Rule("R9", re.compile(r"(?m)^\s*(?:supabase|prisma|db)\.[\w.]+\([^\n]*\)\s*;?\s*$"),
         includes=JS, absent=(re.compile(r"await|then|catch"),), window=1),

    # ---- C3 unbounded select -------------------------------------------------------------------------
    Rule("C3", re.compile(r"\.select\(\s*[\"']\*[\"']\s*\)"), includes=JS, excludes=TEST_PATHS,
         absent=(re.compile(r"\.limit\(|\.range\(|\.single\(|\.maybeSingle\("),), window=160),
    Rule("C3", re.compile(r"(?i)select\s+\*\s+from\s+\w+"),
         absent=(re.compile(r"(?i)\blimit\b"),), window=200),

    # ---- C4 unbounded loop in a handler ------------------------------------------------------------------
    Rule("C4", re.compile(r"while\s*\(\s*true\s*\)"), includes=JS, excludes=TEST_PATHS, predicate=_on_server_path),
    Rule("C4", re.compile(r"while\s+True\s*:"), includes=PY, excludes=TEST_PATHS, predicate=_on_server_path),

    # ---- C5 aggressive polling -----------------------------------------------------------------------------
    Rule("C5", re.compile(r"setInterval\([^,]+,\s*(\d+)\s*\)"), includes=JS, excludes=TEST_PATHS,
         predicate=lambda m, f: int(m.group(1)) < 30000),

    # ---- C6 no caching --------------------------------------------------------------------------------------
    Rule("C6", re.compile(r"export\s+const\s+dynamic\s*=\s*[\"']force-dynamic[\"']"), includes=JS),
    Rule("C6", re.compile(r"cache\s*:\s*[\"']no-store[\"']"), includes=JS),

    # ---- O1 secrets in logs ------------------------------------------------------------------------------------
    # Logging the *word* "token" in a message is not a leak; logging the
    # variable is. Strip the quoted strings, then look for the identifier.
    Rule("O1", re.compile(
        r"(?im)^(.{0,240}?(?:console\.(?:log|info|warn|error|debug)"
        r"|logger?\.(?:info|debug|warn|error)|print)\(.*)$"),
         excludes=TEST_PATHS,
         predicate=lambda m, f: logs_a_sensitive_value(m.group(1))),

    # ---- O2 internal error to client ---------------------------------------------------------------------------
    Rule("O2", re.compile(r"(?s)(res|response)\.(status\(\d+\)\.)?(json|send)\([^)]{0,160}"
                          r"(err(or)?\.(stack|message)|traceback|exc_info)"), excludes=TEST_PATHS),

    Rule("O2", re.compile(
        r"(?s)(Response\.json|new\s+Response)\([^;]{0,200}"
        r"(\.stack\b|err(or)?\.message|traceback)"), includes=JS, excludes=TEST_PATHS),

    # ---- O3 console as logging -----------------------------------------------------------------------------------
    Rule("O3", re.compile(r"console\.(log|debug)\("), includes=JS,
         excludes=TEST_PATHS + ("script", "bin/")),

    # ---- H5 mock/stub on production path ----------------------------------------------------------------------------
    Rule("H5", re.compile(r"\b(MOCK_[A-Z_]+|mockData|fakeData|dummyData|sampleData)\b"),
         predicate=_on_server_path),
    Rule("H5", re.compile(r"(?i)//\s*(TODO|FIXME|HACK|XXX)\b"), predicate=_on_server_path),
    Rule("H5", re.compile(r"(?i)#\s*(TODO|FIXME|HACK|XXX)\b"), includes=PY,
         predicate=_on_server_path),

    # ---- H2/H3/H6/H7 emitted by detectors/structure.py; H8 marker ------------------------------------------------------
    Rule("H8", re.compile(r"^\Z"), predicate=_never),
    Rule("H2", re.compile(r"^\Z"), predicate=_never),
    Rule("H3", re.compile(r"^\Z"), predicate=_never),
    Rule("H6", re.compile(r"^\Z"), predicate=_never),
    Rule("H7", re.compile(r"^\Z"), predicate=_never),

    # ---- T2 assertion-free test ----------------------------------------------------------------------------------------
    Rule("T2", re.compile(r"(?:it|test)\(\s*[\"'][^\"']+[\"']\s*,\s*(?:async\s*)?\(\s*\)\s*=>\s*\{"),
         includes=JS, absent=(re.compile(r"expect\(|assert"),), window=400),

    # ---- X3 open redirect ------------------------------------------------------------------------------------------------
    Rule("X3", re.compile(r"redirect\(\s*(req|request)\.(query|params|body)\."), excludes=TEST_PATHS),
    Rule("X3", re.compile(r"redirect\(\s*searchParams\.get\("), excludes=TEST_PATHS),

    # ---- C2 emitted by detectors/sqlrls.py --------------------------------------------------------------------------------
    Rule("C2", re.compile(r"^\Z"), predicate=_never),
]
