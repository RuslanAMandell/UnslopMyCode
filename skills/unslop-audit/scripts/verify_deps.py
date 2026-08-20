#!/usr/bin/env python3
"""Verify that every declared dependency actually exists. Offline-safe."""
import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from unslop.findings import Coverage, Finding, load, write   # noqa: E402

TIMEOUT = 5
POPULAR = {
    "react", "next", "express", "lodash", "axios", "requests", "numpy", "pandas",
    "typescript", "vite", "zod", "prisma", "supabase", "fastapi", "django", "flask",
    "dotenv", "chalk", "moment", "uuid", "jsonwebtoken", "bcrypt", "stripe",
}


def _edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment).

    Counts an adjacent transposition as one edit, not two: `recat` for `react`
    and `reqeusts` for `requests` are the classic typosquat shapes, and plain
    Levenshtein scores both as 2, which would miss them.
    """
    if abs(len(a) - len(b)) > 2:
        return 99
    prev2 = None
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            best = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if (prev2 is not None and i > 1 and j > 1
                    and ca == b[j - 2] and a[i - 2] == cb):
                best = min(best, prev2[j - 2] + 1)
            cur.append(best)
        prev2, prev = prev, cur
    return prev[-1]


def collect_dependencies(root):
    root = Path(root)
    deps = {}
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
        except ValueError:
            data = {}
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(section) or {}).items():
                if not str(spec).startswith(("file:", "link:", "workspace:", "git+")):
                    deps[name] = "npm"
    req = root / "requirements.txt"
    if req.is_file():
        for line in req.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if m:
                deps[m.group(1)] = "pypi"
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        for m in re.finditer(r"^\s*[\"']?([A-Za-z0-9][A-Za-z0-9._-]{1,})[\"']?\s*[=><~\"']",
                             pyproject.read_text(errors="replace"), re.M):
            name = m.group(1)
            if name not in ("name", "version", "description", "requires-python", "readme"):
                deps.setdefault(name, "pypi")
    return deps


def _default_fetch(name, ecosystem):
    url = ("https://registry.npmjs.org/%s" % name if ecosystem == "npm"
           else "https://pypi.org/pypi/%s/json" % name)
    try:
        with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return False
        raise OSError("registry error %s" % exc.code)


def build_findings(root, fetch=None, return_notes=False):
    fetch = fetch or _default_fetch
    deps = collect_dependencies(root)
    findings, notes = [], []
    manifest = "package.json" if (Path(root) / "package.json").is_file() else "requirements.txt"
    for name, eco in sorted(deps.items()):
        try:
            exists = fetch(name, eco)
        except OSError as exc:
            notes.append("dependency verification skipped (offline or unreachable: %s)" % exc)
            findings = []
            break
        if not exists:
            findings.append(Finding("P1", manifest, 1,
                                    "%s does not exist on the %s registry" % (name, eco),
                                    confidence="CONFIRMED"))
            continue
        for popular in POPULAR:
            if name != popular and _edit_distance(name, popular) == 1:
                findings.append(Finding("P2", manifest, 1,
                                        "%s is one character from %s" % (name, popular)))
                break
    return (findings, notes) if return_notes else findings


def main(argv=None, fetch=None):
    ap = argparse.ArgumentParser(prog="verify_deps.py")
    ap.add_argument("root", nargs="?", default=".")
    ap.add_argument("--out", default=".unslop/findings.json")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve()
    out = Path(args.out)
    if not out.is_absolute():
        out = root / out

    new, notes = build_findings(root, fetch=fetch, return_notes=True)
    if out.is_file():
        existing, data = load(out)
        cov = Coverage(**data.get("coverage", {}))
    else:
        existing, cov = [], Coverage()
    for n in notes:
        cov.note(n)
    write(out, existing + new, cov)
    print("unslop: dependency check added %d finding(s)%s"
          % (len(new), " (%s)" % notes[0] if notes else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
