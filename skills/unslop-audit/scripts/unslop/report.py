from collections import Counter, defaultdict
from typing import Dict, List

from .catalog import CHECKS
from .findings import Finding

MAX_BLOCKING = 5
SEVERITY_ORDER = ("P0", "P1", "P2", "P3")
DOMAIN_NAMES = {
    "S": "Secrets and configuration", "D": "Data and access control",
    "A": "Authentication and session", "R": "Reliability and the unhappy path",
    "C": "Cost and performance", "P": "Supply chain", "O": "Observability",
    "H": "AI rot", "X": "Deployment", "T": "Tests",
}


def _sev(f: Finding) -> str:
    return CHECKS[f.check_id].severity


def verdict(findings: List[Finding]) -> str:
    sevs = {_sev(f) for f in findings}
    if "P0" in sevs:
        return "DO NOT SHIP"
    if "P1" in sevs:
        return "SHIP WITH CAUTION"
    return "CLEAR"


def fix_plan(findings: List[Finding]) -> Dict[str, int]:
    counts = Counter(CHECKS[f.check_id].fix_class for f in findings)
    return {k: counts.get(k, 0) for k in ("auto", "assisted", "manual")}


def diff(previous: List[Finding], current: List[Finding]) -> Dict[str, List[Finding]]:
    prev = {f.key(): f for f in previous}
    cur = {f.key(): f for f in current}
    return {
        "new": [cur[k] for k in sorted(set(cur) - set(prev))],
        "fixed": [prev[k] for k in sorted(set(prev) - set(cur))],
        "unchanged": [cur[k] for k in sorted(set(cur) & set(prev))],
    }


def _blocking(findings):
    ranked = sorted((f for f in findings if _sev(f) in ("P0", "P1")),
                    key=lambda f: (SEVERITY_ORDER.index(_sev(f)),
                                   f.confidence != "CONFIRMED", f.check_id, f.file))
    return ranked[:MAX_BLOCKING], max(0, len(ranked) - MAX_BLOCKING)


def render(findings: List[Finding], coverage, previous: List[Finding] = None) -> str:
    confirmed = [f for f in findings if f.confidence == "CONFIRMED"]
    suspected = [f for f in findings if f.confidence != "CONFIRMED"]
    lead, extra = _blocking(confirmed)
    lead_keys = {f.key() for f in lead}
    counts = Counter(_sev(f) for f in confirmed)
    plan = fix_plan(confirmed)

    out = ["# unslop audit", "", "**Verdict: %s**" % verdict(confirmed), ""]
    out.append("%d confirmed findings - P0 %d, P1 %d, P2 %d, P3 %d. %d suspected."
               % (len(confirmed), counts.get("P0", 0), counts.get("P1", 0),
                  counts.get("P2", 0), counts.get("P3", 0), len(suspected)))
    out.append("")

    if previous is not None:
        d = diff(previous, findings)
        out += ["Since the last run: %d fixed, %d new, %d unchanged."
                % (len(d["fixed"]), len(d["new"]), len(d["unchanged"])), ""]

    if lead:
        out += ["## Blocking", ""]
        for f in lead:
            chk = CHECKS[f.check_id]
            out += ["### %s - %s" % (f.check_id, chk.title),
                    "",
                    "`%s:%d`" % (f.file, f.line),
                    "",
                    "```",
                    f.snippet,
                    "```",
                    "",
                    "**Why it matters.** %s" % chk.why,
                    "",
                    "**Fix (%s).** %s" % (chk.fix_class, chk.fix),
                    ""]
        if extra:
            out += ["_%d more critical or high findings are listed below._" % extra, ""]
    else:
        out += ["## Blocking", "",
                "Nothing blocking. All %d checks ran." % len(CHECKS), ""]

    grouped = defaultdict(list)
    for f in confirmed:
        if f.key() not in lead_keys:
            grouped[f.check_id[0]].append(f)
    if grouped:
        out += ["## Everything else", ""]
        for dom in sorted(grouped):
            out += ["**%s**" % DOMAIN_NAMES[dom], ""]
            for f in sorted(grouped[dom], key=lambda x: (x.check_id, x.file, x.line)):
                out.append("- `%s` %s - %s:%d" % (f.check_id, CHECKS[f.check_id].title,
                                                  f.file, f.line))
            out.append("")

    out += ["## Fix plan", "",
            "- `auto` - %d fixes apply without further input" % plan["auto"],
            "- `assisted` - %d need one answer each" % plan["assisted"],
            "- `manual` - %d need you (credential rotation, dashboard settings)" % plan["manual"],
            "", "Run `unslop-fix` to apply them.", ""]

    out += ["## Suspected", ""]
    if suspected:
        out += ["Pattern matched but not verified. Confirm before acting.", ""]
        for f in sorted(suspected, key=lambda x: (x.check_id, x.file, x.line)):
            out.append("- `%s` %s - %s:%d" % (f.check_id, CHECKS[f.check_id].title,
                                              f.file, f.line))
    else:
        out.append("None.")
    out.append("")

    out += ["## Coverage", "",
            "Scanned %d files. Ran %d checks." % (coverage.scanned_files, len(CHECKS))]
    if coverage.stack:
        out.append("Detected stack: %s." % ", ".join(coverage.stack))
    out.append("")
    for note in coverage.notes:
        out.append("- %s" % note)
    if coverage.skipped:
        out.append("- Skipped %d files: %s%s"
                   % (len(coverage.skipped), ", ".join(coverage.skipped[:5]),
                      " ..." if len(coverage.skipped) > 5 else ""))
    out.append("")
    return "\n".join(out)
