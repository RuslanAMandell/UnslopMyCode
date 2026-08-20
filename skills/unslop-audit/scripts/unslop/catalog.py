from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    domain: str
    severity: str   # P0 | P1 | P2 | P3
    fix_class: str  # auto | assisted | manual
    method: str     # static | config | semantic | net
    why: str        # concrete production failure, in plain language
    fix: str        # what remediation actually is


def _c(cid, title, sev, fix_class, method, why, fix):
    return Check(cid, title, cid[0], sev, fix_class, method, why, fix)


CHECKS: Dict[str, Check] = {c.id: c for c in [
    # --- S: secrets and configuration -------------------------------------
    _c("S1", "Hardcoded provider credential in source", "P0", "manual", "static",
       "The key is in your git history and in every build artifact. Anyone with repo or bundle access can spend, read, or delete on your account.",
       "Move the value to an environment variable, then rotate the key. Deleting it from HEAD does not un-leak it."),
    _c("S2", "Secret exposed through a client-visible env prefix", "P0", "assisted", "static",
       "Any variable prefixed NEXT_PUBLIC_/VITE_/REACT_APP_ is inlined into the browser bundle. View source reveals it.",
       "Rename without the public prefix and read it only in server code, then rotate."),
    _c("S3", "Secret file not covered by .gitignore", "P0", "auto", "config",
       "One `git add .` publishes your .env to a public repository, where credential scanners find it within minutes.",
       "Add the pattern to .gitignore; if the file is already tracked, untrack it and rotate everything in it."),
    _c("S4", "Secret present in git history", "P0", "manual", "static",
       "The credential is still fetchable from any clone even though it is gone from the current files.",
       "Rotate the credential. History rewriting is optional; rotation is not."),
    _c("S5", "Env var used in code but missing from .env.example", "P2", "auto", "static",
       "The deploy comes up with an undefined value and fails at the first request instead of at build time.",
       "Add the key to .env.example with a placeholder value and validate required env vars at startup."),
    _c("S6", "Source maps published to production", "P2", "auto", "config",
       "Your original source, comments, and internal endpoint names are downloadable from the live site.",
       "Disable production source map emission, or restrict upload to your error tracker."),

    # --- D: data layer and access control ---------------------------------
    _c("D1", "Table created without row level security", "P0", "assisted", "config",
       "With RLS off, the public anon key reads and writes every row in the table. This is the single most common way vibe-coded apps leak their entire user database.",
       "ALTER TABLE ... ENABLE ROW LEVEL SECURITY and add an explicit per-operation policy."),
    _c("D2", "Row level security policy that grants everything", "P0", "assisted", "config",
       "A USING (true) policy is RLS in name only - every row still matches for every caller.",
       "Scope the policy to the owning user, e.g. USING (auth.uid() = user_id)."),
    _c("D3", "Admin/service_role key reachable from client code", "P0", "assisted", "static",
       "The service role key bypasses every RLS policy. Shipped to the browser it is a full database takeover.",
       "Use the anon key in the client, keep the service role key server-side only, and rotate it."),
    _c("D4", "Storage bucket is public or has no policy", "P0", "assisted", "config",
       "Uploaded files - IDs, invoices, private images - are fetchable by anyone who can guess or enumerate a path.",
       "Make the bucket private and serve files through signed URLs."),
    _c("D5", "Record fetched by user-supplied id with no ownership check", "P0", "assisted", "semantic",
       "Change 1042 to 1043 in the URL and you read someone else's record. This is IDOR, the most common flaw in AI-generated routes.",
       "Add an ownership predicate to the query and return 404 rather than 403 on a miss."),
    _c("D6", "Authorization enforced only in client code", "P0", "assisted", "semantic",
       "Hiding the admin button does not protect the endpoint. curl reaches it directly.",
       "Enforce the check server-side in the route handler; treat the client check as cosmetic."),
    _c("D7", "Request body written to the database unfiltered", "P1", "assisted", "semantic",
       "A caller adds a role or credits field to the JSON body and it is persisted straight into the row.",
       "Validate against an explicit schema and write only allow-listed fields."),
    _c("D8", "SQL assembled by string interpolation", "P0", "assisted", "static",
       "A crafted input closes the string and appends its own statement - classic SQL injection.",
       "Use parameterized queries or the query builder's binding API."),
    _c("D9", "Firebase security rules allow unrestricted access", "P0", "assisted", "config",
       "A rule that allows read and write if true means every document is world-readable and world-writable.",
       "Restrict rules to request.auth.uid and validate written shapes."),

    # --- A: authentication and session ------------------------------------
    _c("A1", "Mutating endpoint with no authentication", "P0", "assisted", "semantic",
       "Anyone on the internet can POST to it and change your data.",
       "Require and verify a session at the top of the handler; reject before any side effect."),
    _c("A2", "JWT verification disabled, weak, or bypassable", "P0", "assisted", "static",
       "An attacker mints their own token and becomes any user, including an admin.",
       "Verify the signature, pin the algorithm, and load the secret from the environment."),
    _c("A3", "Session cookie missing httpOnly, secure, or sameSite", "P1", "auto", "static",
       "A single XSS reads the session cookie from JavaScript, or it leaks over plain HTTP or a cross-site request.",
       "Set httpOnly: true, secure: true, sameSite: 'lax' (or 'strict')."),
    _c("A4", "No rate limit on login, signup, or password reset", "P1", "assisted", "semantic",
       "Credential stuffing runs unthrottled, and password reset becomes an email-bombing tool.",
       "Add per-IP and per-account rate limiting on the auth routes."),
    _c("A5", "Wildcard CORS on an authenticated API", "P1", "auto", "static",
       "Any website can make credentialed requests to your API from a victim's browser.",
       "Set an explicit origin allow-list instead of a wildcard."),
    _c("A6", "Password stored without a modern KDF", "P0", "assisted", "static",
       "A database leak becomes a plaintext password leak, and users reuse those passwords elsewhere.",
       "Hash with bcrypt, scrypt, or argon2id, or delegate auth to a provider."),

    # --- R: reliability and the unhappy path ------------------------------
    _c("R1", "No error boundary in the component tree", "P1", "auto", "static",
       "One thrown render error blanks the entire page - users see white, not a message.",
       "Add an error boundary at the route or app level with a recovery affordance."),
    _c("R2", "HTTP response used without checking status", "P1", "assisted", "static",
       "fetch does not throw on 500. The error body is parsed as if it were data and the failure surfaces later as a confusing crash.",
       "Check response.ok and handle the failure path explicitly."),
    _c("R3", "Network call with no timeout or abort signal", "P1", "auto", "static",
       "A hung upstream holds your request open until the platform kills it, exhausting the connection pool under load.",
       "Attach an AbortController with an explicit timeout."),
    _c("R4", "No schema validation at a trust boundary", "P1", "assisted", "semantic",
       "Malformed or hostile input reaches business logic and the database, where the failure is expensive.",
       "Parse the request with an explicit schema and reject early with a 400."),
    _c("R5", "Error swallowed by an empty or log-only catch", "P1", "assisted", "static",
       "The operation failed but the code proceeds as if it succeeded, so the user is told everything worked.",
       "Handle it, or rethrow. A catch that only logs is a silent failure."),
    _c("R6", "No rate limiting on public endpoints", "P1", "assisted", "semantic",
       "One script can drive unbounded traffic into your database and your bill.",
       "Add rate limiting at the edge or in middleware for unauthenticated routes."),
    _c("R7", "Fetch path with no loading or error state", "P2", "assisted", "semantic",
       "On a slow or failed request the UI shows nothing and the user clicks again, duplicating the write.",
       "Render explicit loading, empty, and error states."),
    _c("R8", "Unbounded list render with no pagination", "P2", "assisted", "semantic",
       "Fine with 20 rows, unusable at 20,000 - the page freezes and mobile devices run out of memory.",
       "Paginate or virtualize the list and bound the query."),
    _c("R9", "Floating promise on a critical path", "P2", "auto", "static",
       "The write is never awaited, so failures vanish and ordering is undefined.",
       "Await it, or attach an explicit catch."),

    # --- C: cost and performance ------------------------------------------
    _c("C1", "Query executed inside a loop (N+1)", "P2", "assisted", "semantic",
       "One page view becomes hundreds of round trips. It is invisible with ten rows of test data and it is your database bill at ten thousand.",
       "Fetch the set in one query with a join or an IN clause."),
    _c("C2", "Filtered or sorted column with no index", "P2", "auto", "static",
       "Every query is a full table scan. Response times climb linearly with row count and compute is billed per scan.",
       "Add an index on the filtered/joined/ordered columns in a migration."),
    _c("C3", "Unbounded select with no limit", "P2", "assisted", "static",
       "The query returns the whole table, which is fine in development and is an out-of-memory error plus an egress bill in production.",
       "Add an explicit limit and paginate."),
    _c("C4", "Unbounded loop or recursion in a serverless handler", "P1", "assisted", "static",
       "The function runs to its timeout on every invocation, and you are billed for the full duration each time.",
       "Bound the iteration and move long work to a queue or a job."),
    _c("C5", "Aggressive polling interval", "P2", "assisted", "static",
       "Each open tab hits your API on a fixed timer forever. A hundred idle tabs is a sustained load you never see in testing.",
       "Increase the interval, use websockets or server-sent events, or poll only while visible."),
    _c("C6", "Cacheable route with no caching or revalidation", "P2", "assisted", "static",
       "Every visitor triggers full recomputation and a database round trip for content that never changed.",
       "Set cache headers or the framework's revalidation option."),
    _c("C7", "Unbounded fan-out with no concurrency cap", "P2", "assisted", "semantic",
       "Promise.all over a large array opens every connection at once and trips provider rate limits or connection caps.",
       "Batch the work with a bounded concurrency limit."),
    _c("C8", "Full table read used to compute an aggregate", "P2", "assisted", "semantic",
       "You transfer every row to count or sum them in application code, paying egress and memory for arithmetic the database does for free.",
       "Push the aggregate into the query."),

    # --- P: supply chain ---------------------------------------------------
    _c("P1", "Dependency does not exist on the registry", "P0", "manual", "net",
       "The model invented the package name. The moment an attacker registers it, your next install pulls their code - this is slopsquatting.",
       "Remove it and replace with a real package you have verified."),
    _c("P2", "Dependency name is one edit from a far more popular package", "P1", "manual", "net",
       "Typosquats publish install hooks that exfiltrate environment variables during install.",
       "Verify the intended name and repository, then correct it."),
    _c("P3", "Missing or out-of-sync lockfile", "P1", "auto", "config",
       "Production resolves different versions than your machine, so a transitive update breaks the deploy or silently changes behavior.",
       "Commit the lockfile and install with the frozen/ci flag."),
    _c("P4", "Dependency with known published vulnerabilities", "P1", "assisted", "net",
       "A public CVE with a public exploit is reachable through your dependency tree.",
       "Upgrade to the patched version or replace the dependency."),
    _c("P5", "Dependency runs an install script", "P2", "manual", "config",
       "A postinstall hook executes arbitrary code on every developer machine and every CI run.",
       "Confirm the package is trusted, or install with scripts disabled."),

    # --- O: observability --------------------------------------------------
    _c("O1", "Secret or personal data written to logs", "P0", "auto", "static",
       "Tokens and personal data land in a log platform with far broader access than your database, and log retention keeps them for years.",
       "Redact before logging; log an identifier, never the credential."),
    _c("O2", "Internal error detail returned to the client", "P1", "auto", "static",
       "Stack traces disclose file paths, library versions, and query shapes - a free reconnaissance report.",
       "Return a generic message with a correlation id; log the detail server-side."),
    _c("O3", "console.log used as production logging", "P3", "assisted", "static",
       "Unstructured output cannot be searched, filtered, or alerted on, so the first sign of an incident is a user complaint.",
       "Use a structured logger with levels and a request id."),
    _c("O4", "No error tracking configured", "P2", "manual", "config",
       "Production exceptions are invisible until someone reports them.",
       "Wire up an error tracking service in the app entrypoint."),
    _c("O5", "No health check endpoint", "P3", "auto", "config",
       "Your platform cannot tell a hung instance from a healthy one, so it keeps routing traffic to it.",
       "Expose a lightweight endpoint that verifies critical dependencies."),

    # --- H: AI rot ----------------------------------------------------------
    _c("H1", "No version control, or the whole codebase in one commit", "P1", "auto", "config",
       "Without checkpoints, the next prompt that breaks working behavior cannot be reverted - you can only ask the model to patch forward.",
       "Initialize git and commit in small, working increments before each prompt."),
    _c("H2", "Near-duplicate file left behind by iterative patching", "P2", "assisted", "static",
       "Two versions of the same module exist and only one is imported. Fixes get applied to the dead one, and the bug never goes away.",
       "Diff the pair, keep one, delete the other."),
    _c("H3", "Orphan module that nothing imports", "P3", "assisted", "static",
       "Dead code is read as real by both you and the model, so future prompts reason about behavior that never executes.",
       "Delete it. Git remembers."),
    _c("H4", "Competing implementations of the same concern", "P2", "assisted", "semantic",
       "Two auth helpers, two HTTP clients, or two ORMs mean a fix in one leaves the other vulnerable.",
       "Pick one, migrate call sites, delete the rest."),
    _c("H5", "Mock data or unfinished stub on a production path", "P1", "assisted", "static",
       "The demo works because the data is fake. Real users hit the placeholder.",
       "Replace with the real implementation or fail loudly instead of returning fixtures."),
    _c("H6", "Large block of commented-out code", "P3", "auto", "static",
       "It rots, it misleads, and it pollutes the context the model reads on every future prompt.",
       "Delete it - the history still has it."),
    _c("H7", "File past the size threshold", "P3", "manual", "static",
       "Neither you nor the model can hold it in context, so edits become guesses and regressions become routine.",
       "Split it along its responsibility boundaries."),
    _c("H8", "Logic block copy-pasted three or more times", "P3", "assisted", "static",
       "A fix applied to one copy leaves the others broken, which is how a bug you already fixed comes back.",
       "Extract a single implementation and call it."),

    # --- X: deployment ------------------------------------------------------
    _c("X1", "Debug mode enabled in a deployed configuration", "P1", "auto", "config",
       "Debug pages expose settings, environment variables, and an interactive console to the public internet.",
       "Drive it from an environment variable that is false in production."),
    _c("X2", "Missing security response headers", "P1", "auto", "config",
       "Without CSP, HSTS, and frame options the app is one injected script or one clickjacking frame from compromise.",
       "Set CSP, HSTS, X-Frame-Options, and X-Content-Type-Options in the platform config or middleware."),
    _c("X3", "Redirect target taken from user input", "P1", "assisted", "static",
       "Your domain becomes the credible first hop in a phishing chain.",
       "Allow-list redirect destinations, or accept only relative paths."),
    _c("X4", "Admin or internal route with no guard", "P0", "assisted", "semantic",
       "The admin panel is one guessed URL away for anyone on the internet.",
       "Require an authenticated role check server-side on the route and its API."),
    _c("X5", "Preview or staging deployment with no access protection", "P1", "manual", "config",
       "Preview URLs are indexed and shared, and they usually point at real data.",
       "Enable deployment protection or password the environment."),

    # --- T: tests -----------------------------------------------------------
    _c("T1", "No tests, or a placeholder test script", "P2", "manual", "config",
       "Nothing catches the regression when the next prompt rewrites working code.",
       "Add tests for the paths that would cost you money or data if they broke."),
    _c("T2", "Test file with no assertions", "P3", "manual", "static",
       "It passes whatever the code does, which is worse than no test because it reads as coverage.",
       "Assert on the behavior, not on the absence of a crash."),
    _c("T3", "No continuous integration workflow", "P2", "auto", "config",
       "Tests only run when someone remembers, which in practice is never.",
       "Add a CI workflow that runs the test suite on every push and pull request."),
]}


def by_method(method: str) -> List[Check]:
    return [c for c in CHECKS.values() if c.method == method]


def by_severity(severity: str) -> List[Check]:
    return [c for c in CHECKS.values() if c.severity == severity]
