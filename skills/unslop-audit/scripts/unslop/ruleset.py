import re

from .rules import PLACEHOLDER_RE, Rule, shannon_entropy

JS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".svelte", ".vue", ".astro")
PY = (".py",)
CODE = JS + PY + (".go", ".rb", ".php", ".java", ".cs", ".rs")
CFG = (".json", ".yml", ".yaml", ".toml", ".env", ".ini", ".conf")
TEST_PATHS = ("test", "spec", "__tests__", "fixtures", "mock", ".example")
SERVER_PATHS = ("/api/", "route.ts", "route.js", "server", "actions", "handler",
                "views.py", "app.py")


def _entropic_secret(m, f):
    value = m.group("val")
    if PLACEHOLDER_RE.search(value) or len(set(value)) < 8:
        return False
    return shannon_entropy(value) >= 3.5


def _on_server_path(m, f):
    rel = f.rel.lower()
    return any(p in rel for p in SERVER_PATHS)


def _never(m, f):
    """Marker for checks emitted by a detector, not by a line match."""
    return False


RULES = [
    # ---- S1 hardcoded credentials ----------------------------------------
    Rule("S1", re.compile(r"AKIA[0-9A-Z]{16}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{16,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), excludes=TEST_PATHS),
    Rule("S1", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), excludes=TEST_PATHS),
    Rule("S1", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|access[_-]?key|auth)\w*"
        r"\s*[:=]\s*[\"'](?P<val>[^\"'\s]{12,})[\"']"),
        includes=CODE + CFG, excludes=TEST_PATHS, predicate=_entropic_secret),

    # ---- S2 client-exposed secret ----------------------------------------
    Rule("S2", re.compile(
        r"\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_[A-Z0-9_]*"
        r"(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|API_KEY|ACCESS_KEY)[A-Z0-9_]*")),

    # ---- S4 emitted by detectors/gitmeta.py --------------------------------
    Rule("S4", re.compile(r"^\Z"), predicate=_never),

    # ---- S5 env var references (post-filtered in scan.py) ------------------
    Rule("S5", re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})"),
         includes=JS),
    Rule("S5", re.compile(r"os\.(?:environ\.get|getenv)\(\s*[\"']([A-Z][A-Z0-9_]{2,})[\"']"),
         includes=PY),

    # ---- D3 service role client-side ---------------------------------------
    Rule("D3", re.compile(r"(?i)service[_-]?role"), includes=JS,
         excludes=("/server/", "/api/", "route.ts", "supabase/functions", ".env")),

    # ---- D8 SQL string interpolation ---------------------------------------
    Rule("D8", re.compile(
        r"(?is)(select|insert\s+into|update|delete\s+from)\b[^`\"';]{0,200}"
        r"(\$\{|\"\s*\+\s*\w|'\s*\+\s*\w|f[\"'])")),
    Rule("D8", re.compile(r"(?i)(execute|query|raw)\(\s*f[\"']"), includes=PY),

    # ---- A2 JWT weaknesses ---------------------------------------------------
    Rule("A2", re.compile(r"(?i)verify\s*[:=]\s*(false|False)")),
    Rule("A2", re.compile(r"(?i)algorithms?\s*[:=]\s*\[?\s*[\"']none[\"']")),
    Rule("A2", re.compile(r"jwt\.decode\((?![^)]*verify)[^)]*\)"), includes=PY),
    Rule("A2", re.compile(r"jwt\.(sign|verify)\([^,]+,\s*[\"'][^\"']{1,24}[\"']"), includes=JS),

    # ---- A3 cookie flags ------------------------------------------------------
    Rule("A3", re.compile(r"(?:res\.cookie|cookies\(\)\.set|setCookie)\("),
         absent=(re.compile(r"(?i)httpOnly\s*:\s*true"),), window=220),
    Rule("A3", re.compile(r"(?:res\.cookie|cookies\(\)\.set|setCookie)\("),
         absent=(re.compile(r"(?i)sameSite"),), window=220),
    Rule("A3", re.compile(r"set_cookie\("), includes=PY,
         absent=(re.compile(r"httponly\s*=\s*True"),), window=220),

    # ---- A5 wildcard CORS -------------------------------------------------------
    Rule("A5", re.compile(r"[\"']Access-Control-Allow-Origin[\"']\s*[:,]\s*[\"']\*[\"']")),
    Rule("A5", re.compile(r"origin\s*:\s*[\"']\*[\"']")),
    Rule("A5", re.compile(r"allow_origins\s*=\s*\[\s*[\"']\*[\"']"), includes=PY),
    Rule("A5", re.compile(r"\bcors\(\s*\)")),

    # ---- A6 weak password storage --------------------------------------------------
    Rule("A6", re.compile(r"(?i)(md5|sha1)\s*\(\s*\w*(pass|pwd)")),
    Rule("A6", re.compile(r"(?i)createHash\([\"'](md5|sha1|sha256)[\"']\)[^;]{0,80}(pass|pwd)")),

    # ---- R1 emitted by detectors/project.py -----------------------------------------
    Rule("R1", re.compile(r"^\Z"), predicate=_never),

    # ---- R2 unchecked fetch ------------------------------------------------------------
    Rule("R2", re.compile(r"await\s+fetch\("), includes=JS,
         absent=(re.compile(r"\.ok\b|\.status\b|catch\s*\(|\.catch\("),), window=200),

    # ---- R3 no timeout --------------------------------------------------------------------
    Rule("R3", re.compile(r"\bfetch\("), includes=JS,
         absent=(re.compile(r"signal|AbortController|timeout"),), window=200),
    Rule("R3", re.compile(r"requests\.(get|post|put|delete)\("), includes=PY,
         absent=(re.compile(r"timeout\s*="),), window=160),

    # ---- R5 swallowed errors ------------------------------------------------------------------
    Rule("R5", re.compile(r"catch\s*\([^)]*\)\s*\{\s*\}"), includes=JS),
    Rule("R5", re.compile(r"except[^\n:]*:\s*\n\s*pass\b"), includes=PY),

    # ---- R9 floating promise ----------------------------------------------------------------------
    Rule("R9", re.compile(r"(?m)^\s*(?:supabase|prisma|db)\.[\w.]+\([^\n]*\)\s*;?\s*$"),
         includes=JS, absent=(re.compile(r"await|then|catch"),), window=1),

    # ---- C3 unbounded select -------------------------------------------------------------------------
    Rule("C3", re.compile(r"\.select\(\s*[\"']\*[\"']\s*\)"), includes=JS,
         absent=(re.compile(r"\.limit\(|\.range\(|\.single\(|\.maybeSingle\("),), window=160),
    Rule("C3", re.compile(r"(?i)select\s+\*\s+from\s+\w+"),
         absent=(re.compile(r"(?i)\blimit\b"),), window=200),

    # ---- C4 unbounded loop in a handler ------------------------------------------------------------------
    Rule("C4", re.compile(r"while\s*\(\s*true\s*\)"), includes=JS, predicate=_on_server_path),
    Rule("C4", re.compile(r"while\s+True\s*:"), includes=PY, predicate=_on_server_path),

    # ---- C5 aggressive polling -----------------------------------------------------------------------------
    Rule("C5", re.compile(r"setInterval\([^,]+,\s*(\d+)\s*\)"), includes=JS,
         predicate=lambda m, f: int(m.group(1)) < 30000),

    # ---- C6 no caching --------------------------------------------------------------------------------------
    Rule("C6", re.compile(r"export\s+const\s+dynamic\s*=\s*[\"']force-dynamic[\"']"), includes=JS),
    Rule("C6", re.compile(r"cache\s*:\s*[\"']no-store[\"']"), includes=JS),

    # ---- O1 secrets in logs ------------------------------------------------------------------------------------
    Rule("O1", re.compile(
        r"(?i)(console\.(log|info|warn|error|debug)|logger?\.(info|debug|warn|error)|print)"
        r"\([^)]*\b(password|passwd|token|secret|api[_-]?key|authorization|ssn|credit[_-]?card)\b")),

    # ---- O2 internal error to client ---------------------------------------------------------------------------
    Rule("O2", re.compile(r"(?s)(res|response)\.(status\(\d+\)\.)?(json|send)\([^)]{0,160}"
                          r"(err(or)?\.(stack|message)|traceback|exc_info)")),

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
    Rule("X3", re.compile(r"redirect\(\s*(req|request)\.(query|params|body)\.")),
    Rule("X3", re.compile(r"redirect\(\s*searchParams\.get\(")),

    # ---- C2 emitted by detectors/sqlrls.py --------------------------------------------------------------------------------
    Rule("C2", re.compile(r"^\Z"), predicate=_never),
]
