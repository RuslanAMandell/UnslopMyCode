# Corpus scan results

Aggregate findings from scanning **280 public AI-generated repositories**.

| | |
|---|---|
| Repositories scanned | 280 (3 failed to clone) |
| Files analyzed | 83,955 |
| Repos with at least one critical (P0) finding | **27.5%** |
| Median findings per repo | 46 |
| Median critical findings per repo | 0 |
| Median scan time per repo | 2.71s |

## Findings by severity

| Severity | Total |
|---|---|
| P0 | 1,610 |
| P1 | 7,096 |
| P2 | 7,383 |
| P3 | 26,280 |

## Prevalence by domain

Share of repositories with at least one finding in the domain.

| Domain | Repos affected |
|---|---|
| Tests | 96.4% |
| AI rot | 88.9% |
| Observability | 77.9% |
| Reliability and the unhappy path | 77.1% |
| Deployment | 71.8% |
| Supply chain | 55.7% |
| Secrets and configuration | 52.1% |
| Cost and performance | 37.1% |
| Authentication and session | 20.7% |
| Data and access control | 14.6% |

## Critical findings (P0)

Share of repositories with at least one of each. These are the ones that are exploitable as they stand.

| Check | | Repos affected |
|---|---|---|
| `S3` | Secret file not covered by .gitignore | **10.7%** |
| `S1` | Hardcoded provider credential in source | **10.4%** |
| `D1` | Table created without row level security | **6.8%** |
| `D8` | SQL assembled by string interpolation | **6.8%** |
| `O1` | Secret or personal data written to logs | **6.1%** |
| `D2` | Row level security policy that grants everything | **5.4%** |
| `D3` | Admin/service_role key reachable from client code | **2.5%** |
| `S2` | Secret exposed through a client-visible env prefix | **2.1%** |
| `D4` | Storage bucket is public or has no policy | **2.1%** |
| `A6` | Password stored without a modern KDF | **1.4%** |
| `A2` | JWT verification disabled, weak, or bypassable | **1.4%** |
| `D9` | Firebase security rules allow unrestricted access | **1.1%** |

## Most common checks

| Check | | Severity | Repos affected |
|---|---|---|---|
| `H7` | File past the size threshold | P3 | 86.8% |
| `T1` | No tests, or a placeholder test script | P2 | 83.6% |
| `H3` | Orphan module that nothing imports | P3 | 79.3% |
| `T3` | No continuous integration workflow | P2 | 78.2% |
| `H8` | Logic block copy-pasted three or more times | P3 | 75.7% |
| `X2` | Missing security response headers | P1 | 71.1% |
| `O5` | No health check endpoint | P3 | 58.6% |
| `R1` | No error boundary in the component tree | P1 | 58.2% |
| `O3` | console.log used as production logging | P3 | 52.5% |
| `S5` | Env var used in code but missing from .env.example | P2 | 49.6% |
| `P5` | Dependency runs an install script | P2 | 49.3% |
| `R3` | Network call with no timeout or abort signal | P1 | 45.4% |
| `R2` | HTTP response used without checking status | P1 | 34.6% |
| `C5` | Aggressive polling interval | P2 | 23.6% |
| `O4` | No error tracking configured | P2 | 20.7% |
| `H6` | Large block of commented-out code | P3 | 18.6% |
| `O2` | Internal error detail returned to the client | P1 | 17.5% |
| `A5` | Wildcard CORS on an authenticated API | P1 | 17.1% |
| `C3` | Unbounded select with no limit | P2 | 16.1% |
| `H2` | Near-duplicate file left behind by iterative patching | P2 | 16.1% |
| `R5` | Error swallowed by an empty or log-only catch | P1 | 13.9% |
| `T2` | Test file with no assertions | P3 | 10.7% |
| `S3` | Secret file not covered by .gitignore | P0 | 10.7% |
| `S1` | Hardcoded provider credential in source | P0 | 10.4% |
| `C2` | Filtered or sorted column with no index | P2 | 9.3% |

## By stack

Checks that only apply to a given stack, measured only against repositories using it.

**supabase** (45 repos, **64.4%** with a critical finding)

| Check | | Severity | Repos affected |
|---|---|---|---|
| `X2` | Missing security response headers | P1 | 86.7% |
| `R1` | No error boundary in the component tree | P1 | 62.2% |
| `R2` | HTTP response used without checking status | P1 | 55.6% |
| `R3` | Network call with no timeout or abort signal | P1 | 55.6% |
| `A5` | Wildcard CORS on an authenticated API | P1 | 42.2% |
| `O2` | Internal error detail returned to the client | P1 | 42.2% |
| `D2` | Row level security policy that grants everything | P0 | 31.1% |
| `D1` | Table created without row level security | P0 | 31.1% |
| `S3` | Secret file not covered by .gitignore | P0 | 24.4% |
| `O1` | Secret or personal data written to logs | P0 | 17.8% |

**nextjs** (64 repos, **25.0%** with a critical finding)

| Check | | Severity | Repos affected |
|---|---|---|---|
| `X2` | Missing security response headers | P1 | 95.3% |
| `R1` | No error boundary in the component tree | P1 | 87.5% |
| `R3` | Network call with no timeout or abort signal | P1 | 56.2% |
| `R2` | HTTP response used without checking status | P1 | 43.8% |
| `O2` | Internal error detail returned to the client | P1 | 28.1% |
| `A5` | Wildcard CORS on an authenticated API | P1 | 12.5% |
| `H5` | Mock data or unfinished stub on a production path | P1 | 9.4% |
| `S1` | Hardcoded provider credential in source | P0 | 9.4% |
| `O1` | Secret or personal data written to logs | P0 | 7.8% |
| `D1` | Table created without row level security | P0 | 7.8% |

**express** (16 repos, **56.2%** with a critical finding)

| Check | | Severity | Repos affected |
|---|---|---|---|
| `R3` | Network call with no timeout or abort signal | P1 | 87.5% |
| `X2` | Missing security response headers | P1 | 81.2% |
| `R2` | HTTP response used without checking status | P1 | 75.0% |
| `A5` | Wildcard CORS on an authenticated API | P1 | 62.5% |
| `R1` | No error boundary in the component tree | P1 | 56.2% |
| `O2` | Internal error detail returned to the client | P1 | 50.0% |
| `S3` | Secret file not covered by .gitignore | P0 | 37.5% |
| `S1` | Hardcoded provider credential in source | P0 | 31.2% |
| `D1` | Table created without row level security | P0 | 25.0% |
| `R5` | Error swallowed by an empty or log-only catch | P1 | 25.0% |

## Stacks detected

| Tag | Repos |
|---|---|
| npm | 194 |
| react | 172 |
| vite | 110 |
| nextjs | 64 |
| bun | 62 |
| pnpm | 57 |
| supabase | 45 |
| vercel | 33 |
| express | 16 |
| drizzle | 12 |
| python | 9 |
| firebase | 9 |

## Method notes

- Shallow clones (`--depth 1`), so the two history-dependent checks (`H1`, `S4`) cannot be measured and are excluded from every number above.
- Counts are raw scanner output. The scanner marks most findings `SUSPECTED` until an agent verifies them by reading the code, so these are upper bounds on a per-check basis.
- Only public repositories. Static analysis only: nothing was executed, no host was contacted, no vulnerability was tested.
- Per-repository results are deliberately not published.
