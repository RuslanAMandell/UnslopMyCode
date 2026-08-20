import os
import re
from collections import defaultdict
from pathlib import Path
from typing import List

from ..findings import Finding

EMITS = {"H2", "H3", "H6", "H7", "H8"}

MAX_LINES = 600
FOSSIL_RE = re.compile(
    r"(?i)[-_. ]?(fixed|new|old|final|copy|backup|bak|v\d+|\d+|updated|temp|tmp|test2)$")
IMPORT_RE = re.compile(
    r"""(?:from\s+["']([^"']+)["']|require\(\s*["']([^"']+)["']\s*\)|import\s+["']([^"']+)["'])""")
PY_IMPORT_RE = re.compile(r"(?m)^\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))")
CODE_COMMENT_RE = re.compile(r"^\s*(?://|#)\s*(.*)$")
CODE_ISH_RE = re.compile(
    r"[;{}()=]|^\s*(?:const|let|var|def|return|if|for|while|class|import|export)\b")
ENTRYPOINT_RE = re.compile(
    r"(?i)(^|/)(page|layout|route|error|loading|not-found|middleware|index|main|app|"
    r"conftest|setup|manage|wsgi|asgi|__init__)\.[jt]sx?$|"
    # Directory-level exemptions are only for dirs whose files are loaded by
    # convention rather than imported. `app/` is deliberately absent: the App
    # Router loads specific filenames, which the rule above already covers, so
    # an ordinary module under app/ that nothing imports really is orphaned.
    r"(^|/)(pages|routes|migrations|supabase|scripts|tests?)/|"
    # Framework config and instrumentation files are loaded by name, never imported.
    r"(^|/)[\w.-]+\.config\.[jt]sx?$|(^|/)(sentry|instrumentation)[\w.]*\.[jt]s$")
MODULE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py")

# Nearly every Vite and Next project maps "@/..." to the source root. Without
# this, every alias-imported module looks orphaned.
ALIAS_RE = re.compile(r"^[@~#$][\w.-]*/")


def _stem_family(rel: str) -> str:
    stem = Path(rel).stem
    prev = None
    while prev != stem:
        prev = stem
        stem = FOSSIL_RE.sub("", stem)
    return (str(Path(rel).parent) + "/" + stem.lower()).lstrip("./")


def _detect_fossils(files) -> List[Finding]:
    groups = defaultdict(list)
    for f in files:
        if f.rel.lower().endswith(MODULE_SUFFIXES):
            groups[_stem_family(f.rel)].append(f.rel)
    out = []
    for family, members in sorted(groups.items()):
        if len(members) < 2:
            continue
        # Anchor on the fossil - the longest name is the one carrying the
        # "-fixed" / "-new" / "-copy" suffix - and name the original in the
        # snippet, so the user opens the file they actually have to judge.
        members = sorted(members, key=lambda r: (len(Path(r).stem), r))
        fossil, original = members[-1], members[0]
        out.append(Finding("H2", fossil, 1,
                           "near-duplicate of %s (family '%s')" % (original, Path(family).name),
                           confidence="CONFIRMED"))
    return out


def _detect_orphans(files) -> List[Finding]:
    modules = {f.rel: f for f in files if f.rel.lower().endswith(MODULE_SUFFIXES)}
    imported = set()
    for f in modules.values():
        specs = [g for m in IMPORT_RE.finditer(f.text) for g in m.groups() if g]
        specs += [g for m in PY_IMPORT_RE.finditer(f.text) for g in m.groups() if g]
        base = Path(f.rel).parent
        for spec in specs:
            if spec.startswith("."):
                # normpath collapses the ".." segments; without it a relative
                # import never matches its target and every module looks orphaned.
                target = os.path.normpath((base / spec).as_posix()).replace(os.sep, "/")
            elif ALIAS_RE.match(spec):
                target = ALIAS_RE.sub("", spec)
            else:
                target = spec.replace(".", "/")
            for cand in modules:
                stem = cand.rsplit(".", 1)[0]
                if stem == target or stem.endswith("/" + target) or stem.endswith(target):
                    imported.add(cand)
    out = []
    for rel in sorted(modules):
        if rel in imported or ENTRYPOINT_RE.search(rel):
            continue
        out.append(Finding("H3", rel, 1, "nothing imports this module",
                           confidence="CONFIRMED"))
    return out


def _detect_comment_blocks(files) -> List[Finding]:
    out = []
    for f in files:
        run_start, run_len = 0, 0
        for i, line in enumerate(f.lines, start=1):
            m = CODE_COMMENT_RE.match(line)
            if m and CODE_ISH_RE.search(m.group(1)):
                run_len += 1
                if not run_start:
                    run_start = i
            else:
                if run_len >= 5:
                    out.append(Finding("H6", f.rel, run_start,
                                       "%d consecutive commented-out code lines" % run_len))
                run_start, run_len = 0, 0
        if run_len >= 5:
            out.append(Finding("H6", f.rel, run_start,
                               "%d consecutive commented-out code lines" % run_len))
    return out


def _detect_size(files) -> List[Finding]:
    return [Finding("H7", f.rel, 1, "%d lines" % len(f.lines))
            for f in files if len(f.lines) > MAX_LINES]


def _detect_clones(files) -> List[Finding]:
    blocks = defaultdict(list)
    for f in files:
        if not f.rel.lower().endswith(MODULE_SUFFIXES):
            continue
        lines = f.lines
        for i in range(len(lines) - 2):
            window = [re.sub(r"\s+", " ", l).strip() for l in lines[i:i + 3]]
            if sum(len(w) for w in window) < 60:
                continue
            blocks["\n".join(window)].append((f.rel, i + 1))
    duplicated = []
    for body, sites in sorted(blocks.items()):
        uniq = sorted(set(sites))
        if len(uniq) >= 3:
            duplicated.append(uniq)
    if not duplicated:
        return []
    # Collapse to a single finding. Component libraries legitimately contain
    # hundreds of near-identical blocks; a finding per block buries the report.
    duplicated.sort(key=lambda sites: -len(sites))
    worst = duplicated[0]
    rel, line = worst[0]
    extra = (" and %d other repeated blocks" % (len(duplicated) - 1)
             if len(duplicated) > 1 else "")
    return [Finding("H8", rel, line,
                    "block repeated %d times (%s)%s"
                    % (len(worst), ", ".join("%s:%d" % s for s in worst[:3]), extra))]


def detect(root, files, coverage) -> List[Finding]:
    return (_detect_fossils(files) + _detect_orphans(files) + _detect_comment_blocks(files)
            + _detect_size(files) + _detect_clones(files))
