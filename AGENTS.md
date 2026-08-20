# Notes for coding agents working in this repository

Read this before changing anything. It is the short version of
[CONTRIBUTING.md](CONTRIBUTING.md), written for an agent.

## Hard constraints

- Standard library only. Never add a dependency, never suggest one.
- Python 3.9 syntax floor.
- `make check` must pass before you claim anything is done. It runs the unit
  tests and the fixture precision/recall gate.
- Never renumber or reuse a check ID.
- Never weaken a test threshold to make a change pass. If the clean fixture
  reports a finding, that is a real false positive — fix the detector.

## Where things live

| You want to change | Edit |
|---|---|
| A check's severity, wording, or fix class | `skills/unslop-audit/scripts/unslop/catalog.py`, then regenerate the catalog doc |
| A regex-detectable check | `skills/unslop-audit/scripts/unslop/ruleset.py` |
| Something needing file parsing or project state | `skills/unslop-audit/scripts/unslop/detectors/` |
| A check that needs reading intent | `skills/unslop-audit/references/semantic-passes.md` |
| Report wording or structure | `skills/unslop-audit/scripts/unslop/report.py` |

`references/check-catalog.md` is **generated**. Editing it by hand fails a test.

## The two tests that matter most

- `tests/test_fixtures.py::test_p0_recall_is_total` — the scanner must find every
  planted P0. No exceptions, no thresholds.
- `tests/test_fixtures.py::test_clean_fixture_has_no_p0` — a P0 on correct code
  is the worst possible bug in this tool. It teaches users to ignore P0s.

## Writing a `why` field

The `why` is what the user reads and acts on. Write the consequence, concretely.

Bad: "This is an IDOR vulnerability."
Good: "Change 1042 to 1043 in the URL and you read another customer's order,
including their shipping address."
