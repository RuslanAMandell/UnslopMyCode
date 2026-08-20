#!/usr/bin/env python3
"""Regenerate references/check-catalog.md from catalog.py.

catalog.py is the single source of truth. A test fails if the doc drifts.
Usage: python3 scripts/gen_catalog_doc.py > references/check-catalog.md
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unslop.catalog import CHECKS                # noqa: E402
from unslop.report import DOMAIN_NAMES           # noqa: E402

METHOD_NAMES = {
    "static": "pattern scan", "config": "config parse",
    "semantic": "agent reads the code", "net": "registry lookup",
}


def main():
    lines = [
        "# Check catalog", "",
        "%d checks across %d domains. Generated from `scripts/unslop/catalog.py` -"
        % (len(CHECKS), len(DOMAIN_NAMES)),
        "do not edit by hand; run `python3 scripts/gen_catalog_doc.py > references/check-catalog.md`.",
        "",
        "**Severity.** `P0` exploitable now or actively leaking. `P1` exploitable with",
        "effort, or a guaranteed outage or cost event. `P2` breaks at scale. `P3` rot.",
        "",
        "**Fix class.** `auto` applied without asking. `assisted` needs one answer from",
        "you. `manual` needs a human action such as rotating a credential.",
        "",
    ]
    for dom in sorted(DOMAIN_NAMES):
        checks = sorted((c for c in CHECKS.values() if c.domain == dom), key=lambda c: c.id)
        lines += ["## %s - %s" % (dom, DOMAIN_NAMES[dom]), "",
                  "| ID | Check | Severity | Fix | Found by |",
                  "|---|---|---|---|---|"]
        for c in checks:
            lines.append("| `%s` | %s | %s | `%s` | %s |"
                         % (c.id, c.title, c.severity, c.fix_class, METHOD_NAMES[c.method]))
        lines.append("")
        for c in checks:
            lines += ["**%s - %s**" % (c.id, c.title), "", c.why, "",
                      "*Fix:* %s" % c.fix, ""]
    sys.stdout.write("\n".join(lines))


if __name__ == "__main__":
    main()
