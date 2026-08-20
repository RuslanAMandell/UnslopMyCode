import json
import re
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"R1", "X1", "X2", "O4", "O5", "T1", "T3"}

ERROR_BOUNDARY_RE = re.compile(
    r"componentDidCatch|getDerivedStateFromError|ErrorBoundary|error\.tsx|error\.jsx|"
    r"errorElement|<ErrorBoundary")
HEADER_RE = re.compile(r"(?i)content-security-policy|strict-transport-security|x-frame-options")
DEBUG_RE = re.compile(r"(?im)^\s*(DEBUG|debug)\s*[:=]\s*(True|true)\s*,?\s*$")
TRACKER_RE = re.compile(r"@sentry|bugsnag|rollbar|datadog|honeybadger|posthog")
HEALTH_RE = re.compile(r"(?i)/(health|healthz|readyz|ping|status)\b")
PLACEHOLDER_TEST_RE = re.compile(r"no test specified|exit 1")
WEB_DEP_RE = re.compile(
    r"\b(next|react|vue|svelte|astro|express|fastify|koa|hapi|nestjs|remix|nuxt|"
    r"fastapi|django|flask|starlette|rails|laravel)\b")
WEB_PATH_RE = re.compile(
    r"(?i)(^|/)(pages|app|routes|api|views|controllers|public|static)/|"
    r"\.(tsx|jsx|vue|svelte|astro)$|(^|/)(server|main|index|wsgi|asgi)\.[jt]s$")


WEB_CONFIG_RE = re.compile(
    r"(?i)^(next|vite|nuxt|svelte|astro|remix|vue|angular|gatsby)\.config\.[jt]s$|"
    r"^(vercel\.json|netlify\.toml|manage\.py|wsgi\.py|asgi\.py|Procfile|"
    r"firebase\.json|serverless\.yml)$")


def _is_web_project(root, files) -> bool:
    """Header, health-check, and error-tracking checks are meaningless for a
    library or a CLI. Only claim they are missing when something is serving."""
    if any(WEB_CONFIG_RE.match(Path(f.rel).name) for f in files):
        return True
    pkg = Path(root) / "package.json"
    if pkg.is_file() and WEB_DEP_RE.search(pkg.read_text(errors="replace")):
        return True
    for marker in ("requirements.txt", "pyproject.toml", "Gemfile", "composer.json"):
        p = Path(root) / marker
        if p.is_file() and WEB_DEP_RE.search(p.read_text(errors="replace")):
            return True
    return any(WEB_PATH_RE.search(f.rel) for f in files)


def _any(files, pattern, suffixes=None):
    for f in files:
        if suffixes and not f.rel.lower().endswith(suffixes):
            continue
        if pattern.search(f.text) or pattern.search(f.rel):
            return f
    return None


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    rels = {f.rel for f in files}
    stack_is_react = any(f.rel.endswith((".tsx", ".jsx")) for f in files)
    is_web = _is_web_project(root, files)
    if not is_web:
        coverage.note("not a web application: security-header, health-check, and "
                      "error-tracking checks (X2, O4, O5) were not applied")

    if stack_is_react and not _any(files, ERROR_BOUNDARY_RE):
        out.append(Finding("R1", "src", 1,
                           "no error boundary, error.tsx, or errorElement anywhere in the tree",
                           confidence="CONFIRMED"))

    if is_web and not _any(files, HEADER_RE,
                           (".js", ".ts", ".mjs", ".json", ".toml", ".yml", ".yaml", ".conf")):
        out.append(Finding("X2", "next.config.js" if "next.config.js" in rels else ".", 1,
                           "no CSP, HSTS, or X-Frame-Options configured anywhere",
                           confidence="CONFIRMED"))

    for f in files:
        if f.rel.lower().endswith((".py", ".env", ".toml", ".yml", ".yaml", ".json")):
            m = DEBUG_RE.search(f.text)
            if m and "example" not in f.rel:
                out.append(Finding("X1", f.rel, f.line_at(m.start()), m.group(0).strip()))

    if is_web and not _any(files, TRACKER_RE):
        out.append(Finding("O4", ".", 1, "no error tracking integration found",
                           confidence="CONFIRMED"))
    if is_web and not _any(files, HEALTH_RE):
        out.append(Finding("O5", ".", 1, "no health check endpoint found",
                           confidence="CONFIRMED"))

    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
        except ValueError:
            data = {}
        script = ((data.get("scripts") or {}).get("test") or "").strip()
        has_tests = any(re.search(r"(?i)(^|/)(tests?|__tests__)/|\.(test|spec)\.[jt]sx?$", r)
                        for r in rels)
        if not has_tests or not script or PLACEHOLDER_TEST_RE.search(script):
            out.append(Finding("T1", "package.json", 1,
                               "test script: %r; test files found: %s" % (script, has_tests),
                               confidence="CONFIRMED"))
    elif not any(r.startswith("tests/") or "test_" in r for r in rels):
        out.append(Finding("T1", ".", 1, "no test files found", confidence="CONFIRMED"))

    if not any(r.startswith(".github/workflows/") or r in (".gitlab-ci.yml", ".circleci/config.yml")
               for r in rels):
        out.append(Finding("T3", ".", 1, "no CI workflow found", confidence="CONFIRMED"))
    return out
