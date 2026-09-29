# PHASE-1 SECURITY TESTS AND CONTROLS

Scope: the Phase-1 attack surface is deliberately small — collector identity/enrollment, the mTLS stream, the HTTP API + sessions, the database boundary, and the logs. Device credentials, plugins, SSRF-prone outbound integrations, SSO, and object storage do not exist yet and therefore cannot be attacked here (they arrive with their own suites in later phases).

## 1. Controls implemented in Phase 1 (inventory)

| Control | Implementation | Where |
|---|---|---|
| Password hashing | Argon2id (m=64 MiB, t=3, p=4), PHC format, per-user salt | `platform/security/argon2.go` |
| Session tokens | 256-bit random, stored SHA-256, httpOnly+SameSite=Lax cookie, 12 h TTL, server-side revoke | identity module |
| CSRF | Double-submit cookie + `X-CSRF-Token` required on unsafe methods (cookie-auth only) | `platform/security/csrf.go`, middleware |
| Login abuse | Per-IP + per-account rate limit (10/min), progressive delay, 429 with `Retry-After` | auth routes |
| Enrollment tokens | 128-bit, prefix-scannable, SHA-256 at rest, TTL ≤ 7 d, single-use, atomic claim | collectors module |
| Enrollment abuse | Per-IP/per-org rate limits; no failure oracle (uniform error); request-id logged reason | enroll_grpc |
| Collector identity | Internal CA (0600 keys), P-256 CSR verification, 90-day leaf, SAN URI binding, SHA-256 fingerprint mapping | collectors/CA |
| Stream auth | mTLS `RequireAndVerifyClientCert` + per-RPC fingerprint→collector status check + cert↔claim assertion | grpcx/auth |
| Revocation | DB status + `revoked_at`; live-stream termination; terminal client behavior | collectors |
| Policy integrity | Ed25519 signature verified against key pinned at enrollment; invalid ⇒ last-good retained | collector/policy |
| Tenant isolation | RLS (`FORCE`) on parents, `SET LOCAL` per tx, app role without BYPASSRLS, 404-not-403 semantics; chunk-level RLS policy on hypertable chunks via migration 000006 (event trigger + backfill); pre-auth lookups via `argus_auth` (BYPASSRLS but granted only organizations/users/sessions) | migrations + database/tenant |
| Input validation | Proto-level bounds, metric allowlist by policy, dim caps, ts window, batch caps | ingest/validate |
| Oversized payloads | gRPC `MaxRecvMsgSize` 16 MiB + batch sample cap 5,000; collector keeps batches ≤ 1 MiB | grpcx, transport |
| Error hygiene | RFC 9457 problem+json; internal errors generic to callers, detailed in logs with request-id | httpx |
| Log hygiene | slog structured; redaction review; test scans logs for token/key/password patterns | M5 + S-08 |
| Secret at rest | Tokens/sessions hashed; CA keys 0600; dev secrets gitignored; gitleaks in CI | repo + CI |
| Dependency hygiene | pinned versions; govulncheck, trivy, npm audit in CI | CI |
| Audit events | enrollment (ok/denied + reason), revoke, policy resync, login failures, isolation violations | audit table (Phase-2 UI; rows written now) |

## 2. Test matrix

| ID | Test | Method | Pass criteria |
|---|---|---|---|
| **S-01** | Invalid enrollment token | Call `Enroll` with random token | Uniform `PERMISSION_DENIED`; no rows created; `result="invalid"` counter; ≤ 10 attempts/min/IP enforced (429-equivalent `RESOURCE_EXHAUSTED` after limit) |
| **S-02** | Expired / already-used token | TTL 2 s wait; reuse valid token | Same uniform error; reason logged server-side only; no timing oracle > 50 ms difference between cases (measured over 100 runs) |
| **S-03** | Client cert from unknown CA | Connect to :8443 with self-signed cert | TLS handshake fails before application layer; no stream logged as established |
| **S-04** | Cert/claim confusion | Valid cert of collector A + `ClientHello.collector_id = B` | Stream closed `CODE_PROTOCOL_ERROR`; security event logged with both IDs; no DB reads |
| **S-05** | Policy tamper | Mutate one byte of `Policy.document`; collect `applied=false`; collector keeps last-good | Ack reports failure; no partial apply; error log; valid re-delivery succeeds |
| **S-06** | Cross-tenant API access | Org B session probing Org A IDs on every Phase-1 endpoint (generated matrix) | 404/403 without existence leakage; zero data returned; audit entries for denied attempts |
| **S-07** | RLS bypass attempts | Unscoped queries; wrong-org inserts; role inspection (`argus_app` has no BYPASSRLS/owner) | 0 rows / `WITH CHECK` violation; extended tests: `SET ROLE argus_owner` unavailable to app DSN |
| **S-08** | Secret leakage | Automated scan of: captured runtime logs (server+collector), API responses (no token echo after creation), DB dumps (only hashes) | Zero matches for token/private-key/password patterns; raw enrollment token appears exactly once (creation response) |
| **S-09** | Login brute force | 15 wrong passwords in 60 s | 429 after threshold; correct password during lockout also 429; unlock after window; counters visible |
| **S-10** | CSRF | POST without `X-CSRF-Token` or with mismatched cookie | 403 `auth.csrf`; no state change |
| **S-11** | Revoked identity | T7 flow | Live stream terminated; reconnect rejected; certificate marked revoked; audit row |
| **S-12** | Oversized / malformed protobuf | Send 32 MiB message; truncated frame; unknown fields; wrong oneof | gRPC size limit rejects cleanly; malformed counted (`argus_grpc_malformed_total`); server/collector stay healthy; no partial DB writes |
| **S-13** | Replay attempts | Replay previously captured batch (T4 flow) and captured enrollment token (S-02 flow) | Batches: `DUPLICATE`, no double rows. Tokens: denied, no new collector |
| **S-14** | Injection attempts | Metric key/dimensions containing `'; DROP TABLE`, `<script>`, `../../etc/passwd`, 4-byte UTF-8, null byte | Stored as inert data (parameterized SQL everywhere); API returns escaped JSON; UI renders as text (Playwright assertion); no path traversal (no file writes from these fields) |
| **S-15** | Rate limiting (ingest) | One collector floods batches (max window × 10) | Server applies flow control/backpressure (`RESOURCE_EXHAUSTED` or credit exhaustion), does not crash, other collectors unaffected (fleet check) |
| **S-16** | Auth endpoint enumeration | Login with unknown vs known-but-wrong email | Identical response shape and timing within tolerance; no user enumeration |

## 3. Explicitly out of scope (with owning phase)

| Area | Why not Phase 1 |
|---|---|
| SSRF (webhooks/diagnostics) | No outbound URLs exist yet (Phase 3+; §24.7 controls already specified) |
| Command injection (SSH/probes) | No process execution in Phase 1 (Phase 5; no-shell rule already specified) |
| Plugin isolation (WASM/subprocess) | No plugins (Phase 2+ per ADR-012) |
| WebAuthn/MFA, OIDC | G10; local auth only |
| Encryption of device credentials (KMS envelope) | No device credentials exist yet (Phase 5; pattern specified in ADR/§24.5) |
| Audit UI / tamper chain | Rows written now; UI + hash chain in Phase 2 (architecture §24.10) |

## 4. Release gate

Phase 1 completes only when S-01…S-16 pass in CI (`make security`, release job) and the automated secret-leak scan (S-08) is green on the final build. Any isolation (S-06/S-07) or identity (S-03/S-04/S-11) failure is Sev-1 and blocks all further milestones.
