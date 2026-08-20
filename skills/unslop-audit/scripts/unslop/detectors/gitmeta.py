import subprocess
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"H1", "S4"}
SECRET_PATHS = (".env", ".env.local", ".env.production", "credentials.json",
                "serviceAccount.json", "id_rsa", "*.pem")


def _git(root, *args, **kwargs):
    timeout = kwargs.get("timeout", 20)
    try:
        r = subprocess.run(["git", "-C", str(root)] + list(args),
                           capture_output=True, timeout=timeout)
        return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    if not (root / ".git").exists():
        out.append(Finding("H1", ".", 1, "no git repository in this directory",
                           confidence="CONFIRMED"))
        coverage.note("no git repository: history checks (S4) could not run")
        return out

    count = _git(root, "rev-list", "--count", "HEAD")
    if count is None:
        coverage.note("git present but unreadable: history checks skipped")
        return out
    n = int(count.strip() or 0)
    if n <= 1:
        out.append(Finding("H1", ".", 1,
                           "repository has %d commit(s): no checkpoints to revert to" % n,
                           confidence="CONFIRMED"))

    for pat in SECRET_PATHS:
        log = _git(root, "log", "--all", "--diff-filter=A", "--name-only",
                   "--pretty=format:", "--", pat)
        if log and log.strip():
            first = sorted(set(log.split()))[0]
            out.append(Finding("S4", first, 1,
                               "%s was committed at some point in history" % first,
                               confidence="CONFIRMED"))
    coverage.note("history scan covered added-file paths only, not full content diffs")
    return out
