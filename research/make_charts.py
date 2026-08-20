#!/usr/bin/env python3
"""Render the corpus results as SVG bar charts, one pair per chart.

SVG rather than mermaid: GitHub's mermaid xychart is still beta and fails on
version mismatch, and a broken diagram in a README is worse than none. SVG is
inert, scales, prints, and needs no renderer. Light and dark variants are
emitted because a static image cannot adapt to the reader's theme; the README
selects between them with <picture> + prefers-color-scheme.

Standard library only, like everything else here.

Usage: python3 research/make_charts.py
"""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "research" / "results"

THEMES = {
    "light": {"text": "#1f2328", "muted": "#59636e", "grid": "#d1d9e0",
              "bar": "#0969da", "hot": "#cf222e", "track": "#eef1f4"},
    "dark":  {"text": "#e6edf3", "muted": "#9198a1", "grid": "#3d444d",
              "bar": "#4493f8", "hot": "#ff7b72", "track": "#20262d"},
}
FONT = ("ui-sans-serif,-apple-system,BlinkMacSystemFont,'Segoe UI',"
        "Helvetica,Arial,sans-serif")


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def nice_max(value):
    """Round an axis maximum up to a readable tick."""
    for cap in (5, 10, 15, 20, 25, 40, 50, 75, 100):
        if value <= cap:
            return cap
    return 100


def bar_chart(rows, theme, title, subtitle, label_w=210, hot_above=None):
    """rows: list of (label, percent, optional_note)."""
    c = THEMES[theme]
    row_h, gap, pad_top = 26, 6, 74
    bar_w = 400
    axis_max = nice_max(max(pct for _, pct, _ in rows))
    width = label_w + bar_w + 76
    height = pad_top + len(rows) * (row_h + gap) + 22

    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
        'viewBox="0 0 %d %d" role="img" aria-label="%s">'
        % (width, height, width, height, esc(title)),
        '<style>text{font-family:%s}</style>' % FONT,
        '<text x="0" y="22" fill="%s" font-size="15" font-weight="600">%s</text>'
        % (c["text"], esc(title)),
        '<text x="0" y="42" fill="%s" font-size="12">%s</text>'
        % (c["muted"], esc(subtitle)),
    ]
    step = next(s for s in (1, 2, 5, 10, 25, 50, 100) if axis_max / float(s) <= 5)
    ticks = [i * step for i in range(int(axis_max / step) + 1)]
    for pct in ticks:
        x = label_w + bar_w * pct / axis_max
        out.append('<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="%s" '
                   'stroke-width="1"/>' % (x, pad_top - 14, x, height - 18, c["grid"]))
        out.append('<text x="%.1f" y="%d" fill="%s" font-size="10" '
                   'text-anchor="middle">%g%%</text>'
                   % (x, pad_top - 20, c["muted"], round(pct, 1)))

    y = pad_top
    for label, pct, note in rows:
        w = max(2.0, bar_w * pct / axis_max)
        color = c["hot"] if (hot_above is not None and pct >= hot_above) else c["bar"]
        out.append('<text x="%d" y="%d" fill="%s" font-size="12" '
                   'text-anchor="end">%s</text>'
                   % (label_w - 12, y + 17, c["text"], esc(label)))
        out.append('<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s"/>'
                   % (label_w, y, bar_w, row_h - 6, c["track"]))
        out.append('<rect x="%d" y="%d" width="%.1f" height="%d" rx="3" fill="%s"/>'
                   % (label_w, y, w, row_h - 6, color))
        out.append('<text x="%.1f" y="%d" fill="%s" font-size="12" '
                   'font-weight="600">%s</text>'
                   % (label_w + w + 8, y + 15, c["text"],
                      esc(note if note else "%.1f%%" % pct)))
        y += row_h + gap
    out.append("</svg>")
    return "\n".join(out) + "\n"


def main():
    agg = json.loads((RESULTS / "aggregate.json").read_text())
    import sys
    sys.path.insert(0, str(ROOT / "skills" / "unslop-audit" / "scripts"))
    from unslop.catalog import CHECKS
    from unslop.report import DOMAIN_NAMES

    n = agg["repos_scanned"]

    domains = [(DOMAIN_NAMES[d], pct, None)
               for d, pct in agg["domain_prevalence_pct"].items()]
    critical = [("%s  %s" % (cid, CHECKS[cid].title), pct, None)
                for cid, pct in agg["critical_prevalence_pct"].items()]

    charts = {
        "domains": (domains,
                    "What %d AI-generated apps are missing" % n,
                    "Share of repositories with at least one finding in the domain",
                    210, None),
        "critical": (critical,
                     "Critical issues, by prevalence",
                     "Share of %d repositories shipping each exploitable defect" % n,
                     320, 10.0),
    }
    for name, (rows, title, sub, label_w, hot) in charts.items():
        for theme in THEMES:
            svg = bar_chart(rows, theme, title, sub, label_w=label_w, hot_above=hot)
            (RESULTS / ("%s-%s.svg" % (name, theme))).write_text(svg)
            print("wrote research/results/%s-%s.svg" % (name, theme))


if __name__ == "__main__":
    main()
