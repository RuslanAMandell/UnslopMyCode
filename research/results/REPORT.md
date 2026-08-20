# Corpus scan results

Aggregate findings from scanning **281 public AI-generated repositories**.

| | |
|---|---|
| Repositories scanned | 281 (2 failed to clone) |
| Files analyzed | 87,839 |
| Repos with at least one critical (P0) finding | **27.4%** |
| Median findings per repo | 44 |
| Median critical findings per repo | 0 |
| Median scan time per repo | 2.86s |

## Findings by severity

| Severity | Total |
|---|---|
| P0 | 1,866 |
| P1 | 7,456 |
| P2 | 7,629 |
| P3 | 24,852 |

## Prevalence by domain

Share of repositories with at least one finding in the domain.

| Domain | Repos affected |
|---|---|
| Tests | 96.4% |
| AI rot | 82.2% |
| Observability | 77.9% |
| Reliability and the unhappy path | 77.2% |
| Deployment | 71.5% |
| Supply chain | 55.9% |
| Secrets and configuration | 51.6% |
| Cost and performance | 37.4% |
| Authentication and session | 21.0% |
| Data and access control | 14.9% |

## Critical findings (P0)

Share of repositories with at least one of each. These are the ones that are exploitable as they stand.

| Check | | Repos affected |
|---|---|---|
| `S3` | Secret file not covered by .gitignore | **10.7%** |
| `S1` | Hardcoded provider credential in source | **10.3%** |
| `D1` | Table created without row level security | **7.1%** |
| `D8` | SQL assembled by string interpolation | **7.1%** |
| `O1` | Secret or personal data written to logs | **6.0%** |
| `D2` | Row level security policy that grants everything | **5.7%** |
| `D3` | Admin/service_role key reachable from client code | **2.8%** |
| `D4` | Storage bucket is public or has no policy | **2.5%** |
| `S2` | Secret exposed through a client-visible env prefix | **2.1%** |
| `A2` | JWT verification disabled, weak, or bypassable | **1.8%** |
| `A6` | Password stored without a modern KDF | **1.4%** |
| `D9` | Firebase security rules allow unrestricted access | **1.1%** |

## Most common checks

| Check | | Severity | Repos affected |
|---|---|---|---|
| `T1` | No tests, or a placeholder test script | P2 | 83.3% |
| `H3` | Orphan module that nothing imports | P3 | 78.6% |
| `T3` | No continuous integration workflow | P2 | 77.9% |
| `H8` | Logic block copy-pasted three or more times | P3 | 75.4% |
| `X2` | Missing security response headers | P1 | 70.8% |
| `O5` | No health check endpoint | P3 | 58.4% |
| `R1` | No error boundary in the component tree | P1 | 58.0% |
| `H7` | File past the size threshold | P3 | 56.9% |
| `O3` | console.log used as production logging | P3 | 52.7% |
| `P5` | Dependency runs an install script | P2 | 49.5% |
| `S5` | Env var used in code but missing from .env.example | P2 | 49.5% |
| `R3` | Network call with no timeout or abort signal | P1 | 45.6% |
| `R2` | HTTP response used without checking status | P1 | 34.9% |
| `C5` | Aggressive polling interval | P2 | 23.8% |
| `O4` | No error tracking configured | P2 | 20.6% |
| `H6` | Large block of commented-out code | P3 | 18.1% |
| `O2` | Internal error detail returned to the client | P1 | 17.8% |
| `A5` | Wildcard CORS on an authenticated API | P1 | 17.4% |
| `C3` | Unbounded select with no limit | P2 | 16.4% |
| `H2` | Near-duplicate file left behind by iterative patching | P2 | 15.7% |
| `R5` | Error swallowed by an empty or log-only catch | P1 | 14.2% |
| `T2` | Test file with no assertions | P3 | 11.0% |
| `S3` | Secret file not covered by .gitignore | P0 | 10.7% |
| `S1` | Hardcoded provider credential in source | P0 | 10.3% |
| `C2` | Filtered or sorted column with no index | P2 | 9.6% |

## By stack

Checks that only apply to a given stack, measured only against repositories using it.

**supabase** (46 repos, **65.2%** with a critical finding)

| Check | | Severity | Repos affected |
|---|---|---|---|
| `X2` | Missing security response headers | P1 | 84.8% |
| `R1` | No error boundary in the component tree | P1 | 60.9% |
| `R2` | HTTP response used without checking status | P1 | 56.5% |
| `R3` | Network call with no timeout or abort signal | P1 | 56.5% |
| `A5` | Wildcard CORS on an authenticated API | P1 | 43.5% |
| `O2` | Internal error detail returned to the client | P1 | 43.5% |
| `D2` | Row level security policy that grants everything | P0 | 32.6% |
| `D1` | Table created without row level security | P0 | 32.6% |
| `S3` | Secret file not covered by .gitignore | P0 | 23.9% |
| `O1` | Secret or personal data written to logs | P0 | 19.6% |

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
| npm | 195 |
| react | 173 |
| vite | 111 |
| nextjs | 64 |
| bun | 63 |
| pnpm | 57 |
| supabase | 46 |
| vercel | 34 |
| express | 16 |
| drizzle | 12 |
| python | 9 |
| firebase | 9 |

## Method notes

- Shallow clones (`--depth 1`), so the two history-dependent checks (`H1`, `S4`) cannot be measured and are excluded from every number above.
- Counts are raw scanner output. The scanner marks most findings `SUSPECTED` until an agent verifies them by reading the code, so these are upper bounds on a per-check basis.
- Only public repositories. Static analysis only: nothing was executed, no host was contacted, no vulnerability was tested.
- Per-repository results are deliberately not published.
