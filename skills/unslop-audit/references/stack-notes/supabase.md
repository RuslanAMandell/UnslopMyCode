# Supabase

**RLS is the whole game.** A table without `enable row level security` is
readable and writable by anyone holding the anon key, and the anon key ships in
the browser by design. Read every migration; do not trust the dashboard state
you cannot see.

- Confirm each `create table` has a matching `alter table ... enable row level
  security` **and** at least one policy. RLS enabled with no policy denies
  everything; RLS disabled allows everything. Both are worth reporting, for
  opposite reasons.
- `using (true)` is not a policy. Neither is a policy that only covers `select`
  while `insert`/`update`/`delete` stay open under `for all`.
- The `service_role` key bypasses every policy. It belongs in server-only code
  and never in anything the browser can load. `NEXT_PUBLIC_..._SERVICE_ROLE_KEY`
  is a full database takeover and is not rare.
- Storage buckets default to whatever the migration says. `public = true` means
  every uploaded invoice and ID scan is fetchable by path.
- `auth.uid()` in a policy is per-row; on large tables wrap it as
  `(select auth.uid())` so it is evaluated once rather than per row.
- Edge functions under `supabase/functions/` are server-side - a service key
  there is correct, not a finding.
