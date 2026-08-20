# Semantic passes

Fourteen checks cannot be found by pattern matching, because they are about
intent and absence rather than shape. The scanner does not attempt them. You do.

Scope the reading. Do not open the whole tree: read route handlers, server
actions, middleware, data-access modules, and the components that fetch. That is
where every one of these lives.

For each pass: **where to look**, **what confirms it**, **what rules it out**,
and **how to report it**. Report in the user's terms - what an attacker or a
load spike actually does - never the name of the weakness alone.

---

## D5 - Record fetched by user-supplied id with no ownership check

**Where.** Every handler that reads a route parameter, query string, or body
field and passes it to a query: `app/api/**/route.ts`, `pages/api/**`,
`actions.ts`, FastAPI/Django views, Express routers.

**Confirms.** The query filters only on the record's own id, and nothing in the
enclosing scope compares the record's owner to the authenticated user.

**Rules it out.** An ownership predicate in the query
(`.eq('user_id', session.user.id)`, `where: { userId: session.user.id }`); an
RLS policy that scopes the table for the caller's role - verify by reading the
migration, never by assuming; or a preceding authorization helper whose failure
path returns before the query runs.

**Report as.** "GET /api/orders/[id] returns any order by id. Change 1042 to
1043 and you read another customer's order, including their shipping address."

---

## D6 - Authorization enforced only in client code

**Where.** Components that branch on a role or permission (`user.isAdmin &&`,
`if (role !== 'admin') return null`), then the endpoints those components call.

**Confirms.** The client hides the control, and the corresponding server handler
performs the action with no equivalent check.

**Rules it out.** A server-side role check in the handler, in middleware
covering that route, or in an RLS policy on the affected table.

**Report as.** "The admin panel hides the delete button for non-admins, but
`POST /api/users/delete` performs the delete for anyone. curl reaches it
directly."

---

## D7 - Request body written to the database unfiltered

**Where.** Any insert or update whose payload derives from the request body:
`insert({...body})`, `update(req.body)`, `Model(**data)`, `Object.assign(row, body)`.

**Confirms.** The whole parsed body, or a spread of it, reaches the write.

**Rules it out.** An explicit field allow-list, or a schema parse whose output -
not the raw body - is what gets written.

**Report as.** "A caller adds `\"role\": \"admin\"` to the signup JSON and the
field is persisted, because the handler spreads the whole body into the insert."

---

## A1 - Mutating endpoint with no authentication

**Where.** Every non-GET handler, plus GET handlers with side effects.

**Confirms.** No session is read, no token verified, and no middleware covers
the path - check the middleware matcher config, not just the file.

**Rules it out.** Session retrieval with an early return on absence; a framework
guard or decorator; a middleware matcher that provably covers the route.

**Report as.** "Anyone on the internet can POST to /api/orders and create
records. There is no session check in the handler and no middleware covering
/api/*."

---

## A4 - No rate limit on login, signup, or password reset

**Where.** The auth routes specifically, plus any middleware they pass through.

**Confirms.** Nothing counts attempts per IP or per account on those paths.

**Rules it out.** A limiter in the handler or middleware; a platform WAF rule
committed to the repo; an auth provider that rate-limits server-side - name the
provider in the finding if this is why you cleared it.

**Report as.** "Credential stuffing against /api/login runs unthrottled, and
password reset can be used to email-bomb any address."

---

## R4 - No schema validation at a trust boundary

**Where.** The first statement of every handler and server action that consumes
input.

**Confirms.** Fields are destructured straight off the parsed body and used.

**Rules it out.** zod/valibot/yup/pydantic parsing that rejects before use, or
explicit per-field type and range checks.

**Report as.** "POST /api/orders reads `total_cents` from the body with no
validation. A string, a negative number, or a missing field reaches the database
before anything notices."

---

## R6 - No rate limiting on public endpoints

**Where.** Unauthenticated routes, especially anything that queries or calls a
paid API.

**Confirms.** No limiter anywhere in the request path.

**Rules it out.** Edge or middleware rate limiting, or a platform-level rule in
committed config.

**Report as.** "One script pointed at /api/search drives unbounded queries into
your database and unbounded spend on your API bill."

---

## R7 - Fetch path with no loading or error state

**Where.** Components that fetch in an effect or render an async result.

**Confirms.** The component renders only the success shape - no loading
indicator, no error branch, no empty state.

**Rules it out.** Explicit branches, a Suspense boundary plus an error boundary,
or a data library whose `isLoading`/`error` values are actually rendered.

**Report as.** "On a slow network the dashboard renders nothing at all, so users
click Submit again and create a duplicate order."

---

## R8 - Unbounded list render with no pagination

**Where.** `.map()` over data from a query, and the query behind it.

**Confirms.** Neither the query nor the render bounds the row count.

**Rules it out.** `.limit()`/`.range()`/`take:` on the query, pagination
controls, or virtualization.

**Report as.** "The orders page renders every row ever created. Fine at 20 rows;
at 20,000 the tab freezes and mobile browsers kill it."

---

## C1 - Query executed inside a loop (N+1)

**Where.** `for`/`while`/`.map()` bodies containing an awaited query, and
`Promise.all(items.map(async ... query ...))`.

**Confirms.** One query per element of a collection whose size grows with data.

**Rules it out.** A single query with a join or `IN` clause; a bounded loop over
a fixed small set - say so in the finding if that is why you cleared it.

**Report as.** "Loading the dashboard runs one query per order. With 10 test
orders that is 11 queries; with 10,000 it is 10,001, and that is the line item
on your database bill."

---

## C7 - Unbounded fan-out with no concurrency cap

**Where.** `Promise.all` / `asyncio.gather` over an array whose length is data-driven.

**Confirms.** Every element launches concurrently with no batching or limit.

**Rules it out.** A concurrency-limited helper, chunked batches, or a queue.

**Report as.** "Importing a 5,000-row CSV opens 5,000 concurrent connections at
once, which exhausts the connection pool and trips the provider's rate limit."

---

## C8 - Full table read used to compute an aggregate

**Where.** `.length`, `sum`, `reduce`, or manual counting over query results.

**Confirms.** Every row is transferred so the application can compute one number.

**Rules it out.** `count`/`sum` pushed into the query, or a maintained counter.

**Report as.** "The revenue tile downloads every order row to add them up. You
pay egress and memory for arithmetic the database does for free."

---

## H4 - Competing implementations of the same concern

**Where.** Compare modules by responsibility, not by name: auth helpers, HTTP
clients, database clients, state stores, date utilities, validation.

**Confirms.** Two or more implementations of the same concern are each live -
both are imported somewhere.

**Rules it out.** One is dead (report as H3 instead), or the split is
deliberate and documented, such as separate browser and server clients.

**Report as.** "Two auth helpers exist - `lib/auth.ts` and `utils/session.ts` -
and different routes use different ones. A fix applied to one leaves every route
using the other still vulnerable."

---

## X4 - Admin or internal route with no guard

**Where.** Anything under `/admin`, `/internal`, `/debug`, `/_`, plus API routes
performing privileged operations.

**Confirms.** The page or handler renders and acts with no role check.

**Rules it out.** A server-side role check on both the page and the APIs it
calls, or middleware provably covering the prefix.

**Report as.** "/admin/users lists every user's email and lets you delete
accounts. It has no role check, so anyone who guesses the URL has it."

---

## P4 - Known published vulnerabilities

Not a semantic pass, but no dependency-free scanner can do it either. Run the
ecosystem's own auditor and fold the result in:

```bash
npm audit --json          # or: pnpm audit --json / yarn npm audit --json
pip-audit -f json         # Python, if available
```

Report only `high` and `critical` entries, each with the package, the installed
version, and the fixed version. If the command is unavailable, record that in
the coverage section rather than reporting the codebase as clean.
