import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List

IGNORE_DIRS = {
    "node_modules", ".git", ".next", ".nuxt", ".svelte-kit", "dist", "build",
    "out", "coverage", "venv", ".venv", "env", "__pycache__", ".pytest_cache",
    "target", "vendor", ".turbo", ".vercel", ".cache", "Pods", ".terraform",
}
IGNORE_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
    ".gz", ".tar", ".mp4", ".mov", ".mp3", ".woff", ".woff2", ".ttf", ".eot",
    ".lock", ".pyc", ".so", ".dylib", ".dll", ".wasm", ".map",
)
IGNORE_NAME_RE = re.compile(r"\.min\.(js|css)$")


@dataclass
class SourceFile:
    path: Path
    rel: str
    text: str

    @property
    def lines(self) -> List[str]:
        return self.text.splitlines()

    def line_at(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


def _git_files(root: Path):
    try:
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others",
             "--exclude-standard"],
            capture_output=True, timeout=20,
        )
        if out.returncode != 0:
            return None
        return [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
    except (OSError, subprocess.SubprocessError):
        return None


def _os_walk_files(root: Path):
    rels = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS and not d.startswith(".git")]
        for name in filenames:
            rels.append(str(Path(dirpath, name).relative_to(root)))
    return rels


def _ignored(rel: str) -> bool:
    parts = set(Path(rel).parts)
    if parts & IGNORE_DIRS:
        return True
    low = rel.lower()
    return low.endswith(IGNORE_SUFFIXES) or bool(IGNORE_NAME_RE.search(low))


def walk(root, coverage, max_file_bytes=2000000, max_files=20000) -> List[SourceFile]:
    root = Path(root)
    rels = _git_files(root)
    if rels is None:
        rels = _os_walk_files(root)
        coverage.note("not a git repository: used built-in ignore rules instead of .gitignore")
    rels = sorted(r for r in rels if not _ignored(r))

    if len(rels) > max_files:
        coverage.note("file cap reached: scanned %d of %d files" % (max_files, len(rels)))
        rels = rels[:max_files]

    files = []
    for rel in rels:
        p = root / rel
        try:
            if not p.is_file():
                continue
            size = p.stat().st_size
            if size > max_file_bytes:
                coverage.skipped.append("%s (%d bytes, over size cap)" % (rel, size))
                continue
            raw = p.read_bytes()
            if b"\x00" in raw[:4096]:
                coverage.skipped.append("%s (binary)" % rel)
                continue
            files.append(SourceFile(p, rel, raw.decode("utf-8", "replace")))
        except OSError as exc:
            coverage.skipped.append("%s (%s)" % (rel, exc.__class__.__name__))
    coverage.scanned_files = len(files)
    return files


_STACK_DEP_TAGS = {
    "next": "nextjs", "react": "react", "vite": "vite", "express": "express",
    "@supabase/supabase-js": "supabase", "firebase": "firebase",
    "firebase-admin": "firebase", "prisma": "prisma", "@prisma/client": "prisma",
    "drizzle-orm": "drizzle", "fastapi": "fastapi", "django": "django",
}


def detect_stack(root) -> List[str]:
    root = Path(root)
    tags = set()
    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text())
        except ValueError:
            data = {}
        deps = {}
        deps.update(data.get("dependencies") or {})
        deps.update(data.get("devDependencies") or {})
        for name, tag in _STACK_DEP_TAGS.items():
            if name in deps:
                tags.add(tag)
        tags.add("npm")
    for lock, tag in (("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"),
                      ("package-lock.json", "npm"), ("bun.lockb", "bun")):
        if (root / lock).is_file():
            tags.add(tag)
    for marker in ("requirements.txt", "pyproject.toml", "Pipfile"):
        if (root / marker).is_file():
            tags.add("python")
            text = (root / marker).read_text(errors="replace").lower()
            for name, tag in (("fastapi", "fastapi"), ("django", "django")):
                if name in text:
                    tags.add(tag)
    if (root / "supabase").is_dir():
        tags.add("supabase")
    if (root / "vercel.json").is_file() or (root / ".vercel").is_dir():
        tags.add("vercel")
    if (root / "firestore.rules").is_file() or (root / "firebase.json").is_file():
        tags.add("firebase")
    return sorted(tags)
