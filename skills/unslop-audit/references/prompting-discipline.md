# How not to regenerate these findings

Every finding in the report is downstream of how the code was produced. Four
habits prevent most of them. They are not about prompting harder; they are about
giving the model the decisions it would otherwise invent.

## Specify the three things a model always guesses

Before generating a feature, state:

1. **The data shape** - tables, columns, types, and which column identifies the
   owner of a row. Without this the model invents a schema per feature, and that
   is where the unindexed columns and the missing RLS policies come from.
2. **The authorization model** - who can read this, who can write it, and how the
   server knows. Absent an answer, generated routes fetch by id and return the
   row. That is the IDOR in your report.
3. **The error contract** - what happens on invalid input, on an upstream
   failure, on an empty result. Unspecified, you get the happy path only.

## Decompose instead of mega-prompting

Asking for a whole multi-page app in one prompt makes the model drop
requirements, simplify logic, and skip the paths you did not name. One feature
per prompt, with the three items above stated, produces code you can actually
review.

## Checkpoint before each prompt

Commit working code before you prompt again. Without checkpoints your only
recovery from a bad generation is asking the model to patch forward - which is
the next habit.

## Never stack a third patch

When a fix fails twice, revert and re-specify. Do not ask for another patch on
top. Iterative AI patching measurably degrades security with each round: each
pass adds surface without removing the original defect, and the result is code
neither you nor the model can trace. Rewriting a small piece from a clear spec
beats a third patch every time.

The near-duplicate files and competing implementations in the `H` domain of your
report are the fossil record of this happening.
