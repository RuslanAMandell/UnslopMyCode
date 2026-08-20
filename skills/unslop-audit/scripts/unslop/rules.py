import base64
import binascii
import json
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
    r"(?i)(your[-_ ]?|example|placeholder|changeme|dummy|sample|fake|"
    r"\btest\b|test[-_]?key|not[-_]?real|ci[-_]?only|localhost|"
    r"xxxx|\.\.\.|<[^>]+>|process\.env|os\.environ|import\.meta\.env|\$\{|\{\{)"
)

# Values that are plainly not credentials, whatever the variable is called:
# CSS selectors, dotted identifiers, camelCase words, template placeholders.
NOT_A_CREDENTIAL_RE = re.compile(
    # camelCase *words* only: letters, multi-letter segments. A random
    # mixed-case key like hZ9pQ2xL7mR4 must not match this.
    r"^[a-z]{2,}(?:[A-Z][a-z]{2,})+$"       # emailNotConfirmed
    r"|^[\w-]+(?:\.[\w-]+){2,}$"            # verdant.mcp.oauth.token.v1
    r"|[\[\]<>{}()#]"                        # input[name=password], selectors
    r"|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$"      # QA_CANARY_STYLE_CONSTANT
    r"|^https?://"                           # token_uri: "https://oauth2.googleapis.com/token"
    r"|^[\w.+-]+@[\w.-]+\.\w+$"              # an email address
)

# An all-lowercase snake_case value is an enum member or a constant name, not a
# credential: PASSWORD_CHANGE = "password_change".
SNAKE_CONSTANT_RE = re.compile(r"^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$")

# Quoted spans, used to tell "logging a variable called token" (a leak) from
# "logging the word token in a message" (not a leak).
QUOTED_RE = re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`")
SENSITIVE_IDENT_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|token|authorization|ssn|credit[_-]?card)\b")


def jwt_payload(token: str):
    """Decode a JWT payload without verifying it. Returns {} when undecodable."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "replace"))
    except (ValueError, binascii.Error):
        return {}


def is_public_jwt(token: str) -> bool:
    """True for tokens that are meant to ship to the browser.

    A Supabase anon key is a signed JWT with role "anon". It appears in the
    client of every Supabase app by design, and reporting it as a leaked
    credential would bury the service_role key that actually matters.
    """
    return jwt_payload(token).get("role") == "anon"


def looks_like_a_credential(value: str) -> bool:
    """Reject values that are structurally not secrets before scoring entropy."""
    if PLACEHOLDER_RE.search(value) or NOT_A_CREDENTIAL_RE.search(value):
        return False
    if SNAKE_CONSTANT_RE.match(value):
        return False
    return len(set(value)) >= 8 and shannon_entropy(value) >= 3.5


def logs_a_sensitive_value(arg_text: str) -> bool:
    """True when a log call passes a sensitive *variable*, not just the word.

    Skips guarded uses that cannot leak the value itself: `!!token` is a
    boolean and `token.length` is a number.
    """
    bare = QUOTED_RE.sub("''", arg_text)
    for m in SENSITIVE_IDENT_RE.finditer(bare):
        before = bare[max(0, m.start() - 3):m.start()]
        after = bare[m.end():m.end() + 12]
        if "!!" in before or after.lstrip("?").startswith(".length"):
            continue
        if re.match(r"\s*:\s*''", after):
            continue          # password: '[REDACTED]' - the value is not logged
        return True
    return False


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
