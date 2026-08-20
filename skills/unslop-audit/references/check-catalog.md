# Check catalog

64 checks across 10 domains. Generated from `scripts/unslop/catalog.py` -
do not edit by hand; run `python3 scripts/gen_catalog_doc.py > references/check-catalog.md`.

**Severity.** `P0` exploitable now or actively leaking. `P1` exploitable with
effort, or a guaranteed outage or cost event. `P2` breaks at scale. `P3` rot.

**Fix class.** `auto` applied without asking. `assisted` needs one answer from
you. `manual` needs a human action such as rotating a credential.

## A - Authentication and session

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `A1` | Mutating endpoint with no authentication | P0 | `assisted` | agent reads the code |
| `A2` | JWT verification disabled, weak, or bypassable | P0 | `assisted` | pattern scan |
| `A3` | Session cookie missing httpOnly, secure, or sameSite | P1 | `auto` | pattern scan |
| `A4` | No rate limit on login, signup, or password reset | P1 | `assisted` | agent reads the code |
| `A5` | Wildcard CORS on an authenticated API | P1 | `auto` | pattern scan |
| `A6` | Password stored without a modern KDF | P0 | `assisted` | pattern scan |

**A1 - Mutating endpoint with no authentication**

Anyone on the internet can POST to it and change your data.

*Fix:* Require and verify a session at the top of the handler; reject before any side effect.

**A2 - JWT verification disabled, weak, or bypassable**

An attacker mints their own token and becomes any user, including an admin.

*Fix:* Verify the signature, pin the algorithm, and load the secret from the environment.

**A3 - Session cookie missing httpOnly, secure, or sameSite**

A single XSS reads the session cookie from JavaScript, or it leaks over plain HTTP or a cross-site request.

*Fix:* Set httpOnly: true, secure: true, sameSite: 'lax' (or 'strict').

**A4 - No rate limit on login, signup, or password reset**

Credential stuffing runs unthrottled, and password reset becomes an email-bombing tool.

*Fix:* Add per-IP and per-account rate limiting on the auth routes.

**A5 - Wildcard CORS on an authenticated API**

Any website can make credentialed requests to your API from a victim's browser.

*Fix:* Set an explicit origin allow-list instead of a wildcard.

**A6 - Password stored without a modern KDF**

A database leak becomes a plaintext password leak, and users reuse those passwords elsewhere.

*Fix:* Hash with bcrypt, scrypt, or argon2id, or delegate auth to a provider.

## C - Cost and performance

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `C1` | Query executed inside a loop (N+1) | P2 | `assisted` | agent reads the code |
| `C2` | Filtered or sorted column with no index | P2 | `auto` | pattern scan |
| `C3` | Unbounded select with no limit | P2 | `assisted` | pattern scan |
| `C4` | Unbounded loop or recursion in a serverless handler | P1 | `assisted` | pattern scan |
| `C5` | Aggressive polling interval | P2 | `assisted` | pattern scan |
| `C6` | Cacheable route with no caching or revalidation | P2 | `assisted` | pattern scan |
| `C7` | Unbounded fan-out with no concurrency cap | P2 | `assisted` | agent reads the code |
| `C8` | Full table read used to compute an aggregate | P2 | `assisted` | agent reads the code |

**C1 - Query executed inside a loop (N+1)**

One page view becomes hundreds of round trips. It is invisible with ten rows of test data and it is your database bill at ten thousand.

*Fix:* Fetch the set in one query with a join or an IN clause.

**C2 - Filtered or sorted column with no index**

Every query is a full table scan. Response times climb linearly with row count and compute is billed per scan.

*Fix:* Add an index on the filtered/joined/ordered columns in a migration.

**C3 - Unbounded select with no limit**

The query returns the whole table, which is fine in development and is an out-of-memory error plus an egress bill in production.

*Fix:* Add an explicit limit and paginate.

**C4 - Unbounded loop or recursion in a serverless handler**

The function runs to its timeout on every invocation, and you are billed for the full duration each time.

*Fix:* Bound the iteration and move long work to a queue or a job.

**C5 - Aggressive polling interval**

Each open tab hits your API on a fixed timer forever. A hundred idle tabs is a sustained load you never see in testing.

*Fix:* Increase the interval, use websockets or server-sent events, or poll only while visible.

**C6 - Cacheable route with no caching or revalidation**

Every visitor triggers full recomputation and a database round trip for content that never changed.

*Fix:* Set cache headers or the framework's revalidation option.

**C7 - Unbounded fan-out with no concurrency cap**

Promise.all over a large array opens every connection at once and trips provider rate limits or connection caps.

*Fix:* Batch the work with a bounded concurrency limit.

**C8 - Full table read used to compute an aggregate**

You transfer every row to count or sum them in application code, paying egress and memory for arithmetic the database does for free.

*Fix:* Push the aggregate into the query.

## D - Data and access control

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `D1` | Table created without row level security | P0 | `assisted` | config parse |
| `D2` | Row level security policy that grants everything | P0 | `assisted` | config parse |
| `D3` | Admin/service_role key reachable from client code | P0 | `assisted` | pattern scan |
| `D4` | Storage bucket is public or has no policy | P0 | `assisted` | config parse |
| `D5` | Record fetched by user-supplied id with no ownership check | P0 | `assisted` | agent reads the code |
| `D6` | Authorization enforced only in client code | P0 | `assisted` | agent reads the code |
| `D7` | Request body written to the database unfiltered | P1 | `assisted` | agent reads the code |
| `D8` | SQL assembled by string interpolation | P0 | `assisted` | pattern scan |
| `D9` | Firebase security rules allow unrestricted access | P0 | `assisted` | config parse |

**D1 - Table created without row level security**

With RLS off, the public anon key reads and writes every row in the table. This is the single most common way vibe-coded apps leak their entire user database.

*Fix:* ALTER TABLE ... ENABLE ROW LEVEL SECURITY and add an explicit per-operation policy.

**D2 - Row level security policy that grants everything**

A USING (true) policy is RLS in name only - every row still matches for every caller.

*Fix:* Scope the policy to the owning user, e.g. USING (auth.uid() = user_id).

**D3 - Admin/service_role key reachable from client code**

The service role key bypasses every RLS policy. Shipped to the browser it is a full database takeover.

*Fix:* Use the anon key in the client, keep the service role key server-side only, and rotate it.

**D4 - Storage bucket is public or has no policy**

Uploaded files - IDs, invoices, private images - are fetchable by anyone who can guess or enumerate a path.

*Fix:* Make the bucket private and serve files through signed URLs.

**D5 - Record fetched by user-supplied id with no ownership check**

Change 1042 to 1043 in the URL and you read someone else's record. This is IDOR, the most common flaw in AI-generated routes.

*Fix:* Add an ownership predicate to the query and return 404 rather than 403 on a miss.

**D6 - Authorization enforced only in client code**

Hiding the admin button does not protect the endpoint. curl reaches it directly.

*Fix:* Enforce the check server-side in the route handler; treat the client check as cosmetic.

**D7 - Request body written to the database unfiltered**

A caller adds a role or credits field to the JSON body and it is persisted straight into the row.

*Fix:* Validate against an explicit schema and write only allow-listed fields.

**D8 - SQL assembled by string interpolation**

A crafted input closes the string and appends its own statement - classic SQL injection.

*Fix:* Use parameterized queries or the query builder's binding API.

**D9 - Firebase security rules allow unrestricted access**

A rule that allows read and write if true means every document is world-readable and world-writable.

*Fix:* Restrict rules to request.auth.uid and validate written shapes.

## H - AI rot

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `H1` | No version control, or the whole codebase in one commit | P1 | `auto` | config parse |
| `H2` | Near-duplicate file left behind by iterative patching | P2 | `assisted` | pattern scan |
| `H3` | Orphan module that nothing imports | P3 | `assisted` | pattern scan |
| `H4` | Competing implementations of the same concern | P2 | `assisted` | agent reads the code |
| `H5` | Mock data or unfinished stub on a production path | P1 | `assisted` | pattern scan |
| `H6` | Large block of commented-out code | P3 | `auto` | pattern scan |
| `H7` | File past the size threshold | P3 | `manual` | pattern scan |
| `H8` | Logic block copy-pasted three or more times | P3 | `assisted` | pattern scan |

**H1 - No version control, or the whole codebase in one commit**

Without checkpoints, the next prompt that breaks working behavior cannot be reverted - you can only ask the model to patch forward.

*Fix:* Initialize git and commit in small, working increments before each prompt.

**H2 - Near-duplicate file left behind by iterative patching**

Two versions of the same module exist and only one is imported. Fixes get applied to the dead one, and the bug never goes away.

*Fix:* Diff the pair, keep one, delete the other.

**H3 - Orphan module that nothing imports**

Dead code is read as real by both you and the model, so future prompts reason about behavior that never executes.

*Fix:* Delete it. Git remembers.

**H4 - Competing implementations of the same concern**

Two auth helpers, two HTTP clients, or two ORMs mean a fix in one leaves the other vulnerable.

*Fix:* Pick one, migrate call sites, delete the rest.

**H5 - Mock data or unfinished stub on a production path**

The demo works because the data is fake. Real users hit the placeholder.

*Fix:* Replace with the real implementation or fail loudly instead of returning fixtures.

**H6 - Large block of commented-out code**

It rots, it misleads, and it pollutes the context the model reads on every future prompt.

*Fix:* Delete it - the history still has it.

**H7 - File past the size threshold**

Neither you nor the model can hold it in context, so edits become guesses and regressions become routine.

*Fix:* Split it along its responsibility boundaries.

**H8 - Logic block copy-pasted three or more times**

A fix applied to one copy leaves the others broken, which is how a bug you already fixed comes back.

*Fix:* Extract a single implementation and call it.

## O - Observability

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `O1` | Secret or personal data written to logs | P0 | `auto` | pattern scan |
| `O2` | Internal error detail returned to the client | P1 | `auto` | pattern scan |
| `O3` | console.log used as production logging | P3 | `assisted` | pattern scan |
| `O4` | No error tracking configured | P2 | `manual` | config parse |
| `O5` | No health check endpoint | P3 | `auto` | config parse |

**O1 - Secret or personal data written to logs**

Tokens and personal data land in a log platform with far broader access than your database, and log retention keeps them for years.

*Fix:* Redact before logging; log an identifier, never the credential.

**O2 - Internal error detail returned to the client**

Stack traces disclose file paths, library versions, and query shapes - a free reconnaissance report.

*Fix:* Return a generic message with a correlation id; log the detail server-side.

**O3 - console.log used as production logging**

Unstructured output cannot be searched, filtered, or alerted on, so the first sign of an incident is a user complaint.

*Fix:* Use a structured logger with levels and a request id.

**O4 - No error tracking configured**

Production exceptions are invisible until someone reports them.

*Fix:* Wire up an error tracking service in the app entrypoint.

**O5 - No health check endpoint**

Your platform cannot tell a hung instance from a healthy one, so it keeps routing traffic to it.

*Fix:* Expose a lightweight endpoint that verifies critical dependencies.

## P - Supply chain

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `P1` | Dependency does not exist on the registry | P0 | `manual` | registry lookup |
| `P2` | Dependency name is one edit from a far more popular package | P1 | `manual` | registry lookup |
| `P3` | Missing or out-of-sync lockfile | P1 | `auto` | config parse |
| `P4` | Dependency with known published vulnerabilities | P1 | `assisted` | registry lookup |
| `P5` | Dependency runs an install script | P2 | `manual` | config parse |

**P1 - Dependency does not exist on the registry**

The model invented the package name. The moment an attacker registers it, your next install pulls their code - this is slopsquatting.

*Fix:* Remove it and replace with a real package you have verified.

**P2 - Dependency name is one edit from a far more popular package**

Typosquats publish install hooks that exfiltrate environment variables during install.

*Fix:* Verify the intended name and repository, then correct it.

**P3 - Missing or out-of-sync lockfile**

Production resolves different versions than your machine, so a transitive update breaks the deploy or silently changes behavior.

*Fix:* Commit the lockfile and install with the frozen/ci flag.

**P4 - Dependency with known published vulnerabilities**

A public CVE with a public exploit is reachable through your dependency tree.

*Fix:* Upgrade to the patched version or replace the dependency.

**P5 - Dependency runs an install script**

A postinstall hook executes arbitrary code on every developer machine and every CI run.

*Fix:* Confirm the package is trusted, or install with scripts disabled.

## R - Reliability and the unhappy path

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `R1` | No error boundary in the component tree | P1 | `auto` | pattern scan |
| `R2` | HTTP response used without checking status | P1 | `assisted` | pattern scan |
| `R3` | Network call with no timeout or abort signal | P1 | `auto` | pattern scan |
| `R4` | No schema validation at a trust boundary | P1 | `assisted` | agent reads the code |
| `R5` | Error swallowed by an empty or log-only catch | P1 | `assisted` | pattern scan |
| `R6` | No rate limiting on public endpoints | P1 | `assisted` | agent reads the code |
| `R7` | Fetch path with no loading or error state | P2 | `assisted` | agent reads the code |
| `R8` | Unbounded list render with no pagination | P2 | `assisted` | agent reads the code |
| `R9` | Floating promise on a critical path | P2 | `auto` | pattern scan |

**R1 - No error boundary in the component tree**

One thrown render error blanks the entire page - users see white, not a message.

*Fix:* Add an error boundary at the route or app level with a recovery affordance.

**R2 - HTTP response used without checking status**

fetch does not throw on 500. The error body is parsed as if it were data and the failure surfaces later as a confusing crash.

*Fix:* Check response.ok and handle the failure path explicitly.

**R3 - Network call with no timeout or abort signal**

A hung upstream holds your request open until the platform kills it, exhausting the connection pool under load.

*Fix:* Attach an AbortController with an explicit timeout.

**R4 - No schema validation at a trust boundary**

Malformed or hostile input reaches business logic and the database, where the failure is expensive.

*Fix:* Parse the request with an explicit schema and reject early with a 400.

**R5 - Error swallowed by an empty or log-only catch**

The operation failed but the code proceeds as if it succeeded, so the user is told everything worked.

*Fix:* Handle it, or rethrow. A catch that only logs is a silent failure.

**R6 - No rate limiting on public endpoints**

One script can drive unbounded traffic into your database and your bill.

*Fix:* Add rate limiting at the edge or in middleware for unauthenticated routes.

**R7 - Fetch path with no loading or error state**

On a slow or failed request the UI shows nothing and the user clicks again, duplicating the write.

*Fix:* Render explicit loading, empty, and error states.

**R8 - Unbounded list render with no pagination**

Fine with 20 rows, unusable at 20,000 - the page freezes and mobile devices run out of memory.

*Fix:* Paginate or virtualize the list and bound the query.

**R9 - Floating promise on a critical path**

The write is never awaited, so failures vanish and ordering is undefined.

*Fix:* Await it, or attach an explicit catch.

## S - Secrets and configuration

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `S1` | Hardcoded provider credential in source | P0 | `manual` | pattern scan |
| `S2` | Secret exposed through a client-visible env prefix | P0 | `assisted` | pattern scan |
| `S3` | Secret file not covered by .gitignore | P0 | `auto` | config parse |
| `S4` | Secret present in git history | P0 | `manual` | pattern scan |
| `S5` | Env var used in code but missing from .env.example | P2 | `auto` | pattern scan |
| `S6` | Source maps published to production | P2 | `auto` | config parse |

**S1 - Hardcoded provider credential in source**

The key is in your git history and in every build artifact. Anyone with repo or bundle access can spend, read, or delete on your account.

*Fix:* Move the value to an environment variable, then rotate the key. Deleting it from HEAD does not un-leak it.

**S2 - Secret exposed through a client-visible env prefix**

Any variable prefixed NEXT_PUBLIC_/VITE_/REACT_APP_ is inlined into the browser bundle. View source reveals it.

*Fix:* Rename without the public prefix and read it only in server code, then rotate.

**S3 - Secret file not covered by .gitignore**

One `git add .` publishes your .env to a public repository, where credential scanners find it within minutes.

*Fix:* Add the pattern to .gitignore; if the file is already tracked, untrack it and rotate everything in it.

**S4 - Secret present in git history**

The credential is still fetchable from any clone even though it is gone from the current files.

*Fix:* Rotate the credential. History rewriting is optional; rotation is not.

**S5 - Env var used in code but missing from .env.example**

The deploy comes up with an undefined value and fails at the first request instead of at build time.

*Fix:* Add the key to .env.example with a placeholder value and validate required env vars at startup.

**S6 - Source maps published to production**

Your original source, comments, and internal endpoint names are downloadable from the live site.

*Fix:* Disable production source map emission, or restrict upload to your error tracker.

## T - Tests

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `T1` | No tests, or a placeholder test script | P2 | `manual` | config parse |
| `T2` | Test file with no assertions | P3 | `manual` | pattern scan |
| `T3` | No continuous integration workflow | P2 | `auto` | config parse |

**T1 - No tests, or a placeholder test script**

Nothing catches the regression when the next prompt rewrites working code.

*Fix:* Add tests for the paths that would cost you money or data if they broke.

**T2 - Test file with no assertions**

It passes whatever the code does, which is worse than no test because it reads as coverage.

*Fix:* Assert on the behavior, not on the absence of a crash.

**T3 - No continuous integration workflow**

Tests only run when someone remembers, which in practice is never.

*Fix:* Add a CI workflow that runs the test suite on every push and pull request.

## X - Deployment

| ID | Check | Severity | Fix | Found by |
|---|---|---|---|---|
| `X1` | Debug mode enabled in a deployed configuration | P1 | `auto` | config parse |
| `X2` | Missing security response headers | P1 | `auto` | config parse |
| `X3` | Redirect target taken from user input | P1 | `assisted` | pattern scan |
| `X4` | Admin or internal route with no guard | P0 | `assisted` | agent reads the code |
| `X5` | Preview or staging deployment with no access protection | P1 | `manual` | config parse |

**X1 - Debug mode enabled in a deployed configuration**

Debug pages expose settings, environment variables, and an interactive console to the public internet.

*Fix:* Drive it from an environment variable that is false in production.

**X2 - Missing security response headers**

Without CSP, HSTS, and frame options the app is one injected script or one clickjacking frame from compromise.

*Fix:* Set CSP, HSTS, X-Frame-Options, and X-Content-Type-Options in the platform config or middleware.

**X3 - Redirect target taken from user input**

Your domain becomes the credible first hop in a phishing chain.

*Fix:* Allow-list redirect destinations, or accept only relative paths.

**X4 - Admin or internal route with no guard**

The admin panel is one guessed URL away for anyone on the internet.

*Fix:* Require an authenticated role check server-side on the route and its API.

**X5 - Preview or staging deployment with no access protection**

Preview URLs are indexed and shared, and they usually point at real data.

*Fix:* Enable deployment protection or password the environment.
