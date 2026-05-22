# Architecture

Monolithic modular structure — no microservices, no message brokers. Just a Spring Boot app split into focused packages.

## Module breakdown

| Module | Responsibility |
|---|---|
| `auth` | User registration, login, JWT issuance |
| `target` | CRUD for local API targets. Validates that URLs are private IPs only. |
| `scan` | Orchestrates scan jobs. Each scanner is an independent `@Service`. |
| `reports` | Aggregates findings into a report with weighted risk score. |
| `security` | `JwtService`, `JwtAuthFilter`, `SecurityConfig` (stateless session) |
| `shared` | `ApiResponse<T>`, `GlobalExceptionHandler`, `WebClientConfig`, `AsyncConfig` |

## Async scan execution

Scan jobs run asynchronously via `@Async("taskExecutor")`. A bounded `ThreadPoolTaskExecutor` (2 core, 5 max, 25 queue) prevents the scanner from consuming all threads.

The HTTP client (`WebClient`) has per-request timeouts enforced at the Netty layer — connect timeout 5s, read timeout 10s.

```
POST /api/scans
       │
       ├─ save ScanJob(PENDING) → return 202
       │
       └─ @Async ──► ScanService.executeScan()
                         │
                         ├─ RUNNING
                         ├─ HeaderScannerService.scan()
                         ├─ CorsScannerService.scan()
                         ├─ SwaggerDetectorService.scan()
                         ├─ JwtAnalyzerService.scan()
                         ├─ RateLimitTesterService.scan()
                         ├─ ResponseAnalyzerService.scan()
                         ├─ UnauthEndpointScannerService.scan()
                         ├─ saveAll(findings)
                         └─ COMPLETED
```

## Database schema

```
users
  └── targets (owner_id → users.id)
        └── scan_jobs (target_id → targets.id, requested_by → users.id)
              ├── scan_findings (job_id → scan_jobs.id)
              └── reports (job_id → scan_jobs.id, target_id, generated_by)
```

## Risk score calculation

Each finding severity has a weight:

| Severity | Weight |
|---|---|
| CRITICAL | 25 |
| HIGH | 15 |
| MEDIUM | 8 |
| LOW | 3 |
| INFO | 0 |

Score = `min(sum of weights, 100)`.

Risk levels: `INFO` (0–9), `LOW` (10–24), `MEDIUM` (25–49), `HIGH` (50–74), `CRITICAL` (75–100).
