# Reduced pass when python3 is unavailable

Run these directly. They cover the highest-severity static checks only. State in
the report's coverage section that the full scan did not run and that the config,
structural, and dependency checks were skipped entirely.

Prefer `rg` (ripgrep) if present; the `grep -rn` forms are equivalents.

```bash
# S1 - hardcoded provider credentials
rg -n 'AKIA[0-9A-Z]{16}|\b(sk|rk)_live_[A-Za-z0-9]{16,}|\bgh[pousr]_[A-Za-z0-9]{30,}|-----BEGIN [A-Z ]*PRIVATE KEY-----' .

# S2 - secrets behind a client-visible prefix
rg -n '(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|TOKEN|API_KEY)' .

# S3 - secret files not ignored
ls -a | rg '^\.env' ; rg -n '^\.env' .gitignore || echo 'MISSING: .env is not in .gitignore'

# D1/D2/D4 - row level security and buckets
rg -n -i 'create table' --glob '*.sql' .
rg -n -i 'enable row level security' --glob '*.sql' .
rg -n -i 'using \(true\)|with check \(true\)' --glob '*.sql' .
rg -n -i 'storage.buckets.*true' --glob '*.sql' .

# D3 - service role key reachable from the client
rg -n -i 'service[_-]?role' --glob '!**/api/**' --glob '*.{ts,tsx,js,jsx}' .

# D8 - SQL built by interpolation
rg -n -i '(select|insert into|update|delete from).*(\$\{|\+ *req\.|f")' .

# A3/A5 - cookie flags and wildcard CORS
rg -n 'res\.cookie|cookies\(\)\.set|setCookie' .
rg -n "Access-Control-Allow-Origin.*\*|origin: *['\"]\*" .

# O1/O2 - secrets in logs, internals returned to the client
rg -n -i 'console\.(log|error|debug)\([^)]*(password|token|secret|api_?key)' .
rg -n '\.stack\b' --glob '*/api/*' .
```

A table appearing in the first SQL command but not the second has no row level
security. That single comparison is the highest-value check in this file.
