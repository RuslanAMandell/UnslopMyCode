import re
from typing import List

from ..findings import Finding

EMITS = {"D1", "D2", "D4", "D9", "C2"}

CREATE_TABLE_RE = re.compile(
    r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:\"?(\w+)\"?\.)?\"?(\w+)\"?\s*\(")
ENABLE_RLS_RE = re.compile(
    r"(?is)alter\s+table\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?\s+enable\s+row\s+level\s+security")
POLICY_RE = re.compile(r"(?is)create\s+policy\s+.*?on\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?(.*?);")
PERMISSIVE_RE = re.compile(r"(?is)using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)")
PUBLIC_BUCKET_RE = re.compile(r"(?is)storage\.buckets[^;]*?\btrue\b")
FIREBASE_OPEN_RE = re.compile(r"(?im)^\s*allow\s+[\w,\s]*:\s*if\s+true\s*;")
FROM_RE = re.compile(r"\.from\(\s*[\"'](\w+)[\"']\s*\)((?:\s*\.\w+\([^)]*\))*)")
COL_RE = re.compile(r"\.(?:eq|neq|gt|gte|lt|lte|like|ilike|order)\(\s*[\"'](\w+)[\"']")
CREATE_INDEX_RE = re.compile(
    r"(?is)create\s+(?:unique\s+)?index[^;]*?on\s+(?:\"?\w+\"?\.)?\"?(\w+)\"?\s*\(([^)]*)\)")


def detect(root, files, coverage) -> List[Finding]:
    out = []
    sql_files = [f for f in files if f.rel.lower().endswith(".sql")]
    tables, rls_on, indexed = {}, set(), {}

    for f in sql_files:
        for m in CREATE_TABLE_RE.finditer(f.text):
            name = m.group(2).lower()
            if name.startswith("_") or (m.group(1) or "").lower() in ("auth", "storage", "extensions"):
                continue
            tables[name] = (f.rel, f.line_at(m.start()))
        for m in ENABLE_RLS_RE.finditer(f.text):
            rls_on.add(m.group(1).lower())
        for m in POLICY_RE.finditer(f.text):
            if PERMISSIVE_RE.search(m.group(2) or ""):
                out.append(Finding("D2", f.rel, f.line_at(m.start()),
                                   m.group(0).strip().splitlines()[0], confidence="CONFIRMED"))
        for m in PUBLIC_BUCKET_RE.finditer(f.text):
            out.append(Finding("D4", f.rel, f.line_at(m.start()),
                               m.group(0).strip()[:120], confidence="CONFIRMED"))
        for m in CREATE_INDEX_RE.finditer(f.text):
            cols = {c.strip().strip('"') for c in m.group(2).split(",")}
            indexed.setdefault(m.group(1).lower(), set()).update(cols)

    for name, (rel, line) in sorted(tables.items()):
        if name not in rls_on:
            out.append(Finding("D1", rel, line,
                               "create table %s ... (row level security never enabled)" % name,
                               confidence="CONFIRMED"))

    for f in files:
        if f.rel.lower().endswith(".rules"):
            for m in FIREBASE_OPEN_RE.finditer(f.text):
                out.append(Finding("D9", f.rel, f.line_at(m.start()),
                                   m.group(0).strip(), confidence="CONFIRMED"))

    if tables:
        for f in files:
            for m in FROM_RE.finditer(f.text):
                table = m.group(1).lower()
                if table not in tables:
                    continue
                for col in sorted(set(COL_RE.findall(m.group(2) or ""))):
                    if col == "id" or col in indexed.get(table, set()):
                        continue
                    out.append(Finding("C2", f.rel, f.line_at(m.start()),
                                       "%s.%s filtered or ordered with no index" % (table, col)))
    else:
        coverage.note("no SQL migrations found: RLS and index checks could not run")
    return out
