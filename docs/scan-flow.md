# Scan Flow

Detailed breakdown of what each scanner does.

## HeaderScannerService

Makes a single `GET` request to the base URL and checks the response headers.

Checked headers and their severity if missing:

| Header | Severity | Why it matters |
|---|---|---|
| `Strict-Transport-Security` | HIGH | Without HSTS, connections can be downgraded to HTTP |
| `Content-Security-Policy` | MEDIUM | No CSP means XSS is easier to exploit |
| `X-Content-Type-Options` | MEDIUM | Browsers may MIME-sniff and execute unexpected content |
| `X-Frame-Options` | MEDIUM | Missing allows clickjacking via iframe embedding |
| `Referrer-Policy` | LOW | Sensitive URLs may leak via Referer header |
| `Permissions-Policy` | LOW | Browser features like geolocation unrestricted |

Also checks:
- `Server` header exposing version numbers (e.g. `Apache/2.4.51`)
- `X-Powered-By` header disclosing technology stack

## CorsScannerService

Makes three separate probes:

1. **OPTIONS preflight** — checks `Access-Control-Allow-Origin` for `*`
2. **Reflected origin** — sends `Origin: http://evil.example.com`, checks if it's echoed back
3. **Null origin** — sends `Origin: null`, checks if server allows it

## SwaggerDetectorService

Iterates over 15 common paths and checks for HTTP 200:

- Swagger/OpenAPI: `/swagger-ui.html`, `/v3/api-docs`, `/openapi.json`, etc.
- Spring Boot Actuator: `/actuator`, `/actuator/env` (CRITICAL), `/actuator/mappings`, `/actuator/beans`, etc.

## JwtAnalyzerService

1. **Unauthenticated access** — probes 8 common auth-protected paths without a token. Flags 200 responses, records 401/403 as INFO.
2. **`alg=none` acceptance** — sends a JWT with `{"alg":"none"}` header and no signature. If the server responds 200, it's a critical vulnerability.
3. **Expired token** — sends a token with `exp` set 24 hours in the past. Checks if the server accepts it anyway.

The `analyze-token` endpoint (`POST /api/scans/analyze-token`) does client-side decode only — it doesn't verify the signature, just checks structure and flags common issues.

## RateLimitTesterService

Sends up to 12 POST requests to `/api/auth/login` with a delay of 150ms between each. Stops early if:
- HTTP 429 is received
- `X-RateLimit-*` or `RateLimit-*` headers appear

If all 12 requests pass without any throttling signal, flags `RATE_LIMIT / MEDIUM`.

Also makes a single GET to the base URL to check if rate-limit quota headers are present.

## ResponseAnalyzerService

Probes 5 paths designed to trigger error responses:
- `/api/does-not-exist-12345`
- `/api/../etc/passwd`
- `/api/users/99999999`
- `/api/%00`
- `/api/login'`

Checks the response body for:
- Java stack traces (`at com.`, `Exception in thread`, `Caused by:`)
- Database errors (`ORA-`, `MySQL`, `PostgreSQL`, `JDBC`)
- Filesystem paths (`/home/`, `C:\Users\`, `/var/`)
- Sensitive field names (`"password":`, `"secret":`, `"token":`)

## UnauthEndpointScannerService

Probes 13 common sensitive paths without any token:
`/api/admin`, `/api/config`, `/api/logs`, `/api/debug`, `/h2-console`, `/console`, `/graphql`, etc.

- HTTP 200/304 → finding with the path's severity
- HTTP 401/403 → INFO finding (working correctly)
- HTTP 404 → silently skipped
