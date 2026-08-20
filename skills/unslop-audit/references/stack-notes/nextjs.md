# Next.js

- **App Router.** `app/**/route.ts` handlers are public by default. Middleware
  only protects paths its `matcher` covers - read the matcher, do not assume.
- **Server vs client.** `"use client"` files are shipped to the browser in full,
  including any constant defined in them. An `import "server-only"` module
  cannot be imported into a client component, which makes it the right home for
  privileged keys.
- **Env vars.** Anything prefixed `NEXT_PUBLIC_` is inlined into the bundle at
  build time. Renaming it later does not un-ship the builds already deployed.
- **Server actions** are POST endpoints. They need the same authentication and
  validation as a route handler; they get it far less often.
- `productionBrowserSourceMaps: true` publishes your original source.
- Security headers belong in `headers()` in `next.config.js` or in middleware.
  Neither exists by default.
- `export const dynamic = "force-dynamic"` disables caching for the whole route.
  Sometimes necessary, often pasted in to fix a stale-data bug and never removed.
