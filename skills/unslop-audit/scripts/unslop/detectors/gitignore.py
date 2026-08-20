import re
from pathlib import Path
from typing import List

from ..findings import Finding
from . import is_test_path

EMITS = {"S3", "S6"}

SECRET_PATTERNS = (".env", ".env.local", ".env.production", "*.pem", "*.key",
                   "credentials.json", "serviceAccount.json", "service-account.json")
_SOURCEMAP_RE = re.compile(
    r"productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true|GENERATE_SOURCEMAP\s*=\s*true")


def _covered(patterns, name: str) -> bool:
    for pat in patterns:
        if pat == name or (pat.startswith("*") and name.endswith(pat[1:])):
            return True
        if pat.rstrip("/") == name.rstrip("/"):
            return True
    return False


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    gi = root / ".gitignore"
    patterns = []
    if gi.is_file():
        patterns = [ln.strip() for ln in gi.read_text(errors="replace").splitlines()
                    if ln.strip() and not ln.startswith("#")]
    else:
        coverage.note("no .gitignore present")

    present = {f.rel for f in files if not is_test_path(f.rel)}
    for candidate in SECRET_PATTERNS:
        if candidate.startswith("*"):
            hits = [r for r in present if r.endswith(candidate[1:])]
        else:
            hits = [r for r in present if Path(r).name == candidate]
        for rel in hits:
            if not _covered(patterns, Path(rel).name):
                out.append(Finding("S3", rel, 1,
                                   "%s exists and is not matched by .gitignore" % rel,
                                   confidence="CONFIRMED"))

    for f in files:
        if Path(f.rel).name in ("next.config.js", "next.config.mjs", "next.config.ts",
                                "vite.config.js", "vite.config.ts", ".env", ".env.production"):
            m = _SOURCEMAP_RE.search(f.text)
            if m:
                out.append(Finding("S6", f.rel, f.line_at(m.start()),
                                   m.group(0), confidence="CONFIRMED"))
    return out
