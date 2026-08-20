import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Tuple

from .catalog import CHECKS

SCHEMA_VERSION = 1
CONFIDENCES = ("CONFIRMED", "SUSPECTED")


@dataclass
class Finding:
    check_id: str
    file: str
    line: int
    snippet: str
    confidence: str = "SUSPECTED"
    evidence: str = ""

    def __post_init__(self):
        if self.check_id not in CHECKS:
            raise ValueError("unknown check id: %s" % self.check_id)
        if self.confidence not in CONFIDENCES:
            raise ValueError("bad confidence: %s" % self.confidence)
        self.snippet = self.snippet.strip()[:240]

    @property
    def check(self):
        return CHECKS[self.check_id]

    def key(self) -> str:
        return "%s:%s:%d" % (self.check_id, self.file, self.line)


@dataclass
class Coverage:
    scanned_files: int = 0
    skipped: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    stack: List[str] = field(default_factory=list)

    def note(self, message: str) -> None:
        if message not in self.notes:
            self.notes.append(message)


def write(path: Path, findings: List[Finding], coverage: Coverage) -> None:
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "coverage": asdict(coverage),
        "findings": [
            dict(asdict(f), severity=f.check.severity, fixClass=f.check.fix_class,
                 title=f.check.title, domain=f.check.domain)
            for f in findings
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def load(path: Path) -> Tuple[List[Finding], Dict]:
    data = json.loads(Path(path).read_text())
    out = []
    for row in data.get("findings", []):
        out.append(Finding(
            check_id=row["check_id"], file=row["file"], line=row["line"],
            snippet=row["snippet"], confidence=row.get("confidence", "SUSPECTED"),
            evidence=row.get("evidence", ""),
        ))
    return out, data
