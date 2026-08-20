# Contributing

## Ground rules

- **Zero runtime dependencies.** Standard library only, in the scanner and in
  the tests. A `pip install` in any code path is a bug, not a tradeoff.
- **Python 3.9 floor.** No `match`, no PEP 604 unions at runtime, no `tomllib`.
- **Check IDs are permanent.** Never renumber and never reuse. A retired check
  is tombstoned in `catalog.py` with a comment.
- **Every finding carries evidence**: file, line, snippet. No exceptions.
- **Coverage is honest.** If something did not run, it goes in the coverage
  block. Silent partial coverage reads as "you're clean" and is the single worst
  failure this tool can have.

## Adding a check

Five things, all required. `make check` enforces four of them:

1. **Catalog entry** in `skills/unslop-audit/scripts/unslop/catalog.py`: id,
   title, severity, fix class, method, a concrete failure scenario in `why`, and
   a real remediation in `fix`. `why` is what the user reads; write what actually
   happens, not the name of the weakness.
2. **A rule or a detector.** Pattern-matchable goes in `ruleset.py`; anything
   needing file parsing or whole-project state goes in `detectors/`. Checks that
   need to read intent are `method="semantic"` and belong in
   `references/semantic-passes.md` instead.
3. **A planted defect** in `tests/fixtures/vulnerable-next-supabase/`, listed in
   `expected.json`.
4. **A clean counterpart** in `tests/fixtures/clean-next-supabase/`: the same
   code, done right. If your check fires there, it is not ready.
5. **A fix recipe** in `skills/unslop-fix/references/fix-recipes.md`.

Then regenerate the catalog doc:

```bash
python3 skills/unslop-audit/scripts/gen_catalog_doc.py > skills/unslop-audit/references/check-catalog.md
make check
```

## Adding a stack adapter

Add `skills/unslop-audit/references/stack-notes/<stack>.md`, and teach
`walker.detect_stack()` to emit the tag. Notes should say what is *specific* to
that stack: the default that bites, the file that holds the real config. Not
generic advice available anywhere.

## False positives are bugs

A false positive costs more trust than a missed P3 costs coverage. If a check
fires on the clean fixture, either the check is wrong or the clean fixture is.
Fix whichever it is; do not raise the threshold.

## Credential-shaped test values

Never commit a contiguous provider-shaped key, even a fake one. It trips secret
scanning for everyone who forks the repo. Concatenate the prefix at runtime, as
`tests/test_ruleset.py` does, or use a generic high-entropy value.
