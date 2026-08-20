# Express and Node

- `app.use(cors())` with no arguments allows every origin. Combined with cookie
  auth, any site can make credentialed requests from a victim's browser.
- Route ordering matters: an auth middleware registered *after* a route does not
  protect it. Read the registration order, not just the presence of the guard.
- `express.json()` with no `limit` accepts arbitrarily large bodies.
- Error middleware that returns `err.stack` to the client is a reconnaissance
  gift. It is also the default in most generated scaffolds.
- `process.on('uncaughtException')` that logs and continues leaves the process in
  an undefined state.
- Sessions: `httpOnly`, `secure`, and `sameSite` are not defaults. Neither is a
  session store - the default MemoryStore leaks and does not survive a restart.
