# Fix recipes

One entry per check. `auto` entries are applied without asking; `assisted`
entries lead with the single question to ask; `manual` entries say what only a
person can do.

## A - Authentication and session

### A1 - Mutating endpoint with no authentication  *(assisted)*

Add a session check as the first statement, returning 401 before any side
effect. If the route is genuinely public, record why in the commit message.

### A2 - JWT verification disabled, weak, or bypassable  *(assisted)*

Verify the signature, pin the algorithm explicitly, and read the secret from the
environment. Never accept a token whose header declares the algorithm.

### A3 - Session cookie missing httpOnly, secure, or sameSite  *(auto)*

Add the flags to the cookie options object. Do not change the cookie name or
`maxAge`:

```ts
{ httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/" }
```

### A4 - No rate limit on login, signup, or password reset  *(assisted)*

Add per-IP and per-account limits to the auth routes. **Ask which limiter the
project should use** if none exists - in-memory is fine for one instance and
wrong for several.

### A5 - Wildcard CORS on an authenticated API  *(auto)*

Replace the wildcard with an explicit allow-list read from config:

```ts
const allowed = new Set([process.env.APP_ORIGIN]);
const origin = request.headers.get("origin");
if (origin && allowed.has(origin)) headers.set("Access-Control-Allow-Origin", origin);
```

### A6 - Password stored without a modern KDF  *(assisted)*

Replace the hash with bcrypt, scrypt, or argon2id, or delegate to the auth
provider. Existing hashes cannot be converted: rehash on next successful login,
and add a manual item for the migration window.

## C - Cost and performance

### C1 - Query executed inside a loop (N+1)  *(assisted)*

Replace the loop with a single query using a join or an `IN` clause. Verify the
result shape is still what the caller expects before committing.

### C2 - Filtered or sorted column with no index  *(auto)*

Add an index in a new migration. Never edit an applied migration:

```sql
create index concurrently if not exists orders_user_id_idx on public.orders (user_id);
```

### C3 - Unbounded select with no limit  *(assisted)*

Add an explicit `.limit()` and paginate. **Ask what the maximum sensible page
size is** for this view.

### C4 - Unbounded loop or recursion in a serverless handler  *(assisted)*

Bound the iteration count and move long work to a queue or background job.

### C5 - Aggressive polling interval  *(assisted)*

Raise the interval, or switch to a subscription. At minimum, pause polling when
the document is hidden.

### C6 - Cacheable route with no caching or revalidation  *(assisted)*

Add cache headers or the framework's revalidation option. **Ask how stale this
data is allowed to be** - the answer is the revalidation window.

### C7 - Unbounded fan-out with no concurrency cap  *(assisted)*

Batch the fan-out with a bounded concurrency limit. Ten is a safe default for
database work.

### C8 - Full table read used to compute an aggregate  *(assisted)*

Push the aggregate into the query (`count`, `sum`, `group by`).

## D - Data and access control

### D1 - Table created without row level security  *(assisted)*

**Ask: "Which column on `<table>` identifies the owning user?"**

```sql
alter table public.<table> enable row level security;

create policy "<table>_select_own" on public.<table>
  for select using (auth.uid() = <owner_column>);

create policy "<table>_modify_own" on public.<table>
  for all using (auth.uid() = <owner_column>)
  with check (auth.uid() = <owner_column>);
```

If the table is genuinely public to read (a published catalog), use
`for select using (true)` with writes still scoped, and say so in the commit
message so it is not mistaken for a D2 regression later.

### D2 - Row level security policy that grants everything  *(assisted)*

**Ask: "Who should be able to read and write these rows?"**

Replace `using (true)` with an ownership predicate. Check `with check` too: a
policy that scopes reads but leaves writes open is still wide open.

### D3 - Admin/service_role key reachable from client code  *(assisted)*

**Ask: "Does any browser code need this value?"** (The answer is no.)

Move the client construction to the anon key, put the service key in a module
that starts with `import "server-only"`, and add a manual rotation item.

### D4 - Storage bucket is public or has no policy  *(assisted)*

**Ask: "Should these files be readable by anyone with the URL?"**

If no: set the bucket `public = false` and serve through signed URLs with a
short expiry.

### D5 - Record fetched by user-supplied id with no ownership check  *(assisted)*

**Ask: "Which column links this record to its owner?"**

Add the ownership predicate to the query and return 404 rather than 403 on a
miss - a 403 confirms the record exists, which is itself a leak.

### D6 - Authorization enforced only in client code  *(assisted)*

**Ask: "What is the server-side source of truth for this role?"**

Add the check to the handler. Leave the client check in place as UX; just stop
relying on it.

### D7 - Request body written to the database unfiltered  *(assisted)*

Replace the spread with an explicit allow-list, or write only the parsed output
of a schema. Never both spread and validate - the spread wins.

### D8 - SQL assembled by string interpolation  *(assisted)*

Convert to a parameterized query. For an unavoidable dynamic identifier such as
a sort column, validate it against a hardcoded allow-list; identifiers cannot be
parameterized.

### D9 - Firebase security rules allow unrestricted access  *(assisted)*

**Ask: "Which field on the document identifies its owner?"** Then scope the rule
to `request.auth.uid` and validate the written shape with
`request.resource.data`.

## H - AI rot

### H1 - No version control, or the whole codebase in one commit  *(auto)*

`git init` if there is no repository, then commit in logical increments rather
than one bulk commit. If there is exactly one commit, leave history alone and
tell the user to checkpoint before each future prompt.

### H2 - Near-duplicate file left behind by iterative patching  *(assisted)*

Diff the pair. **Ask which one is live** if the imports do not make it obvious,
then delete the other in its own commit so the deletion is easy to revert.

### H3 - Orphan module that nothing imports  *(assisted)*

Delete the module. Git remembers it. If it is loaded by convention rather than
imported, record that instead and leave it.

### H4 - Competing implementations of the same concern  *(assisted)*

**Ask which implementation should survive.** Migrate call sites in one commit
per site, then delete the loser. Do not leave both while migrating.

### H5 - Mock data or unfinished stub on a production path  *(assisted)*

Replace the mock with the real implementation, or make the stub throw loudly.
Returning fixture data in production is worse than an error, because nobody
notices.

### H6 - Large block of commented-out code  *(auto)*

Delete the block. Git still has it.

### H7 - File past the size threshold  *(manual)*

**Manual.** Split the file along its responsibility boundaries. This is a
judgement call about design, so it is never applied automatically.

### H8 - Logic block copy-pasted three or more times  *(assisted)*

Extract one implementation and call it from each site. Only worth doing when
the copies are genuinely the same logic, not merely similar shapes.

## O - Observability

### O1 - Secret or personal data written to logs  *(auto)*

Remove the credential from the log call and log a non-sensitive identifier
instead. Redact rather than delete the log line - the log is often load-bearing.

### O2 - Internal error detail returned to the client  *(auto)*

Return a generic message plus a correlation id, and log the detail server-side:

```ts
const id = crypto.randomUUID();
logger.error("request failed", { id, message: (err as Error).message });
return Response.json({ error: "something went wrong", id }, { status: 500 });
```

### O3 - console.log used as production logging  *(assisted)*

Use a structured logger with levels and a request id.

### O4 - No error tracking configured  *(manual)*

**Manual.** Add an error tracking service and wire its DSN through the
environment.

### O5 - No health check endpoint  *(auto)*

Add a lightweight endpoint that returns 200 only when critical dependencies
respond. A route that always returns `ok` is worse than none - it tells the
platform to keep sending traffic to a broken instance.

## P - Supply chain

### P1 - Dependency does not exist on the registry  *(manual)*

**Manual.** The package does not exist. Remove it and find the real dependency
the code needs. Do not create the package to make the import resolve.

### P2 - Dependency name is one edit from a far more popular package  *(manual)*

**Manual.** Confirm the intended package by checking its repository and download
count, then correct the name and reinstall.

### P3 - Missing or out-of-sync lockfile  *(auto)*

Generate the lockfile with the project's package manager and commit it. Switch
CI to the frozen install (`npm ci`, `pnpm install --frozen-lockfile`).

### P4 - Dependency with known published vulnerabilities  *(assisted)*

**Manual review.** Upgrade to the patched version. If no patch exists, decide
whether the vulnerable path is reachable from your code before accepting it.

### P5 - Dependency runs an install script  *(manual)*

**Manual.** Confirm the package is trusted. If it is not needed at install time,
install with scripts disabled.

## R - Reliability and the unhappy path

### R1 - No error boundary in the component tree  *(auto)*

Add `app/error.tsx` (App Router) or wrap the tree in an error boundary. It must
render a message and a retry affordance, not `null`.

### R2 - HTTP response used without checking status  *(assisted)*

Check `response.ok` and handle the failure branch explicitly. `fetch` does not
throw on a 500, so a surrounding try/catch does not cover this.

### R3 - Network call with no timeout or abort signal  *(auto)*

Attach an AbortController with an explicit timeout, and clear it in `finally`.
Five seconds is a reasonable default for a server-to-server call.

### R4 - No schema validation at a trust boundary  *(assisted)*

Parse the request with a schema and return 400 on failure. **Ask which
validation library the project already uses** before adding one.

### R5 - Error swallowed by an empty or log-only catch  *(assisted)*

Handle the error or rethrow it. If it is genuinely ignorable, log it at debug
level with a comment saying why - an empty block does not communicate intent.

### R6 - No rate limiting on public endpoints  *(assisted)*

Add rate limiting in middleware for unauthenticated routes. **Ask whether the
platform already provides it** before adding a dependency.

### R7 - Fetch path with no loading or error state  *(assisted)*

Render explicit loading, empty, and error branches. The error branch needs a
retry, not just a message.

### R8 - Unbounded list render with no pagination  *(assisted)*

Bound the query and paginate the render. **Ask what page size the UI expects.**

### R9 - Floating promise on a critical path  *(auto)*

Await the call, or attach `.catch()` with real handling. Do not add an empty
catch - that converts a floating promise into a swallowed error (R5).

## S - Secrets and configuration

### S1 - Hardcoded provider credential in source  *(manual)*

**Manual - rotate first.** Move the value to an environment variable and update
every deploy target, then rotate the credential at the provider. Deleting it
from HEAD does not un-leak it: the value is in history and in every clone.

### S2 - Secret exposed through a client-visible env prefix  *(assisted)*

**Ask: "Is this value safe for the public to read?"**

If no: rename it without the public prefix, move every read into server-only
code, and add a manual rotation item - the old value is already in shipped
bundles. If yes (a URL, a publishable key), leave it and record why.

### S3 - Secret file not covered by .gitignore  *(auto)*

Append the missing pattern to `.gitignore`. Then check whether the file is
already tracked:

```bash
git ls-files --error-unmatch .env 2>/dev/null && git rm --cached .env
```

If it was tracked, add an `S4` manual item: every value in it must be rotated.

### S4 - Secret present in git history  *(manual)*

**Manual - rotation only.** The credential is reachable from any clone.
Rotate it. History rewriting is optional and disruptive; rotation is not
optional.

### S5 - Env var used in code but missing from .env.example  *(auto)*

Add the key to `.env.example` with an empty value. Do not copy the real value
across. If the project validates env vars at startup, add it there too.

### S6 - Source maps published to production  *(auto)*

Set `productionBrowserSourceMaps: false` (Next.js) or `build.sourcemap: false`
(Vite). If the team needs maps for error tracking, upload them to the tracker
instead of serving them.

## T - Tests

### T1 - No tests, or a placeholder test script  *(manual)*

**Manual.** Write tests for the paths that would cost money or data if they
broke. Generated tests that assert nothing are worse than none (T2).

### T2 - Test file with no assertions  *(manual)*

**Manual.** Add real assertions, or delete the test. A test that cannot fail is
a false signal of coverage.

### T3 - No continuous integration workflow  *(auto)*

Add a CI workflow that installs, builds, and runs the test suite on push and
pull request. If there are no tests yet, still add the workflow with the build
step - `T1` covers the missing tests.

## X - Deployment

### X1 - Debug mode enabled in a deployed configuration  *(auto)*

Drive it from an environment variable that is false in production. Never
hardcode `False` - the next person flips it back for a local debug session.

### X2 - Missing security response headers  *(auto)*

Add the four headers in `next.config.js` `headers()`, in middleware, or in the
platform config. Start CSP in report-only mode if the app has inline scripts,
and say so in the commit message so it is not mistaken for a finished fix.

### X3 - Redirect target taken from user input  *(assisted)*

Accept only relative paths, or validate against a hardcoded allow-list of
destinations. Never validate by prefix matching on a hostname.

### X4 - Admin or internal route with no guard  *(assisted)*

Add a server-side role check to the route and to every API it calls. Both, not
either.

### X5 - Preview or staging deployment with no access protection  *(manual)*

**Manual.** Enable deployment protection for preview environments in the hosting
dashboard.
