import json
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"P3", "P5"}

LOCKFILES = ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb",
             "poetry.lock", "requirements.lock", "uv.lock", "Pipfile.lock")


def detect(root, files, coverage) -> List[Finding]:
    root = Path(root)
    out = []
    manifests = [m for m in ("package.json", "requirements.txt", "pyproject.toml", "Pipfile")
                 if (root / m).is_file()]
    if not manifests:
        coverage.note("no dependency manifest found: supply chain checks limited")
        return out

    locks = [l for l in LOCKFILES if (root / l).is_file()]
    if not locks:
        out.append(Finding("P3", manifests[0], 1,
                           "%s present with no lockfile alongside it" % manifests[0],
                           confidence="CONFIRMED"))

    lock = root / "package-lock.json"
    if lock.is_file():
        try:
            data = json.loads(lock.read_text(errors="replace"))
        except ValueError:
            coverage.note("package-lock.json is not valid JSON: install-script check skipped")
            return out
        for pkg_path, meta in (data.get("packages") or {}).items():
            if isinstance(meta, dict) and meta.get("hasInstallScript"):
                out.append(Finding("P5", "package-lock.json", 1,
                                   "%s runs an install script" % (pkg_path or "root"),
                                   confidence="CONFIRMED"))
    return out
