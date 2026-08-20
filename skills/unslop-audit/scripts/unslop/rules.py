import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern, Sequence

from .findings import Finding
from .walker import SourceFile

# Prose files. Code-shape rules (an unchecked fetch, an empty catch) do not
# apply to them, but credential rules do - people really do paste live keys
# into a README.
DOC_SUFFIXES = (".md", ".mdx", ".rst", ".txt", ".ipynb", ".adoc")

# Values that are documented dummies rather than live credentials.
KNOWN_EXAMPLE_RE = re.compile(
    r"(?i)example|sample|dummy|placeholder|specimen|your[-_]|xxxx|(.)\1{5,}")


def looks_like_example(value: str) -> bool:
    return bool(KNOWN_EXAMPLE_RE.search(value))


PLACEHOLDER_RE = re.compile(
    r"(?i)(your[-_ ]?|example|placeholder|changeme|dummy|sample|test[-_]?key|"
    r"xxxx|\.\.\.|<[^>]+>|process\.env|os\.environ|import\.meta\.env|\$\{)"
)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in counts.values())


@dataclass
class Rule:
    check_id: str
    pattern: Pattern
    includes: Sequence[str] = ()
    excludes: Sequence[str] = ()
    absent: Sequence[Pattern] = field(default_factory=tuple)
    window: int = 400
    predicate: Optional[Callable] = None
    confidence: str = "SUSPECTED"
    allow_docs: bool = False

    def applies_to(self, f: SourceFile) -> bool:
        rel = f.rel.lower()
        if rel.endswith(DOC_SUFFIXES) and not self.allow_docs:
            return False
        if self.includes and not rel.endswith(tuple(self.includes)):
            return False
        return not any(x in rel for x in self.excludes)


def run(rules_list: List[Rule], files: List[SourceFile]) -> List[Finding]:
    out, seen = [], set()
    for f in files:
        lines = f.lines
        for rule in rules_list:
            if not rule.applies_to(f):
                continue
            for m in rule.pattern.finditer(f.text):
                if rule.predicate and not rule.predicate(m, f):
                    continue
                if rule.absent:
                    tail = f.text[m.end():m.end() + rule.window]
                    if any(a.search(tail) for a in rule.absent):
                        continue
                line = f.line_at(m.start())
                key = (rule.check_id, f.rel, line)
                if key in seen:
                    continue
                seen.add(key)
                snippet = lines[line - 1] if line <= len(lines) else m.group(0)
                out.append(Finding(rule.check_id, f.rel, line, snippet,
                                   confidence=rule.confidence))
    return out
