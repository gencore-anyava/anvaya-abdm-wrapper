# Changes from upstream

Upstream: https://github.com/NHA-ABDM/ABDM-wrapper at `bcc6951` ("Merge pull request #152").
Upstream's README is kept at `docs/UPSTREAM-README.md`. Anvaya-only code lives in
`in.nha.abdm.wrapper.anvaya.*` to keep upstream merges simple.

## 2026-11-16

### 1. Gateway session token handling
Upstream refreshed the gateway token with a 15-minute `@Scheduled` job and fetched the first token
while the app was starting. On Cloud Run, CPU is throttled between requests, so the job may not run
and the token (about 20 minutes) expires. If the gateway was down at boot, startup failed.

- `v1/common/requests/SessionManager.java`: stores the token with its expiry (`expiresIn`, defaulting
  to 15 min). It refreshes on demand once the token is within `SESSION_REFRESH_SKEW_SECONDS` (120s)
  of expiry, with refreshes thread-safe and double-checked. Added `invalidateToken()`. Removed the
  scheduled refresh and the no-op `@Retryable` (retry is not enabled in this app; network retries
  already happen in `retryWhen`). The response body is no longer logged.
- `v3/common/RequestV3Manager.java`: on a gateway 401, drops the rejected token, opens a new session
  and retries once.
- `v3/common/RequestV3Manager.java`, `v1/common/RequestManager.java`: removed the token fetch from the
  WebClient default headers set at startup. Headers are now set per request.

### 3. MongoDB Atlas connection
- `application.properties`: replaced `spring.data.mongodb.host/port` with
  `spring.data.mongodb.uri=${MONGODB_URI}`, so `mongodb+srv://` URIs work. Removed the unused JDBC
  driver line.
- `Dockerfile`: removed the hardcoded `--spring.data.mongodb.host=mongodb`.
- The compose files now set `MONGODB_URI=mongodb://mongodb:27017/abdm_wrapper`.

### 5. Configuration from environment / Secret Manager
Credentials and per-environment URLs are read from environment variables. Defaults match
upstream's sandbox values.

### 6. Facade API authentication
`anvaya/security/FacadeApiKeyFilter`: every request that is not a gateway callback, the HIU data
push endpoint, a health check or a CORS preflight must send `X-API-Key` with one of
`FACADE_API_KEYS`. Rules are deny-by-default, so new upstream endpoints are protected automatically.
Startup fails if auth is enabled and no keys are set.

### 7. Gateway callback verification
`anvaya/security/GatewayJwtFilter`: requests to `/api/v3/**` must carry a gateway JWT. Its signature
is checked against the gateway's JWKS (`GATEWAY_JWKS_URL`, cached by Nimbus) along with its expiry.
The filter can be turned off with `GATEWAY_AUTH_ENABLED=false`, but only for the mock gateway.

## Environment variables

| Variable | Required on Cloud Run | Default | Notes |
|---|---|---|---|
| `ABDM_CLIENT_ID` | yes (secret) | empty | ABDM portal |
| `ABDM_CLIENT_SECRET` | yes (secret) | empty | ABDM portal |
| `ABDM_ENVIRONMENT` | yes | `sbx` | `sbx` or `abdm` (production); sent as `X-CM-ID` |
| `GATEWAY_BASE_URL` | yes | `https://dev.abdm.gov.in/api/hiecm` | prod: `https://apis.abdm.gov.in/api/hiecm` |
| `GATEWAY_JWKS_URL` | yes | `https://dev.abdm.gov.in/api/hiecm/gateway/v3/certs` | **check against current ABDM docs before go-live** |
| `GATEWAY_AUTH_ENABLED` | | `true` | `false` only with the mock gateway |
| `MONGODB_URI` | yes (secret) | `mongodb://localhost:27017/abdm_wrapper` | Atlas `mongodb+srv://...` |
| `MONGODB_DATABASE` | | `abdm_wrapper` | |
| `HIP_BASE_URL` | yes | `http://host.docker.internal:8081` | Anvaya bridge URL |
| `DATA_PUSH_URL` | yes | `http://localhost:8082/v3/transfer/` | public Cloud Run URL + `/v3/transfer/` |
| `FACADE_API_KEYS` | yes (secret) | empty | comma-separated, for rotation |
| `FACADE_AUTH_ENABLED` | | `true` | |
| `SESSION_REFRESH_SKEW_SECONDS` | | `120` | |
| `PORT` | set by Cloud Run | `8082` | |
| `LOG_CURL` | | `false` | keep `false` in prod: it logs headers and request bodies |

## Known gaps / next steps
- The gateway filter checks the signature and expiry only. It does not yet check issuer or audience
  claims; add these once the sandbox shows what ABDM puts in them.
- Under the v1 profile, the v1 gateway callbacks (`/v0.5/...`) would be treated as facade paths and
  need an API key. Anvaya runs v3 only.
- Still to do from the review: discovery runs async after the 202 response (needs Cloud Run CPU
  always allocated), a multi-stage Dockerfile, quieter DEBUG/TRACE logging, and the in-memory
  token-number counter.
