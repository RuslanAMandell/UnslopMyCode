# Vercel

- **Preview deployments are public by default** on Hobby, and they usually point
  at production data. Deployment Protection is the fix.
- Environment variables are scoped per environment. A variable set only for
  Production means preview builds run with it undefined, which surfaces as a
  runtime crash rather than a build failure.
- Serverless functions bill by duration. An unbounded loop or a missing timeout
  on an upstream call turns one slow dependency into a bill.
- There is no default concurrency cap on fan-out from a function. `Promise.all`
  over a large array will exhaust a database connection pool.
- `vercel.json` `headers` is the other place security headers can live - check
  both it and `next.config.js` before reporting X2.
