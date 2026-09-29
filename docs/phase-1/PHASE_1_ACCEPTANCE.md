# PHASE-1 ACCEPTANCE CRITERIA

Objective, measurable criteria. Every AC maps to at least one automated test (path + ID). "Manual" entries are allowed only where automation is structurally impossible in Phase 1 (noted).

**Global preconditions for the acceptance run:** clean checkout; `make reset && make dev`; pinned versions per SPEC §5; test machine specs recorded (load-related ACs only); time budget ≤ 90 minutes for the full automated run.

| ID | Criterion (measurable) | Verification | Mapping |
|---|---|---|---|
| **AC-01** | A collector with a valid one-time token **enrolls within 10 s** (dev stack) and persists identity + signed policy; collector appears in `GET /v1/collectors` as `pending` then `active`. | `tests/e2e/scenarios_test.go::TestEnrollAndActivate` | S-01, S-04 |
| **AC-02** | Collector receives policy v1 **and verifies its Ed25519 signature**; a policy with an invalid signature is **rejected** (last-good retained, `PolicyAck.applied=false`, error logged). | e2e + unit `collector/policy` | S-05 |
| **AC-03** | Collector establishes the mTLS stream **and is observable as connected** within 15 s; `last_stream_at` advances; server metric `argus_grpc_streams_active == 1`. | e2e; `/metrics` scrape | S-03, S-11 |
| **AC-04** | Collector produces `collector_cpu_percent` at the policy interval (5 s ± 1 s) with value in **[0, 100]**. | e2e sample validation | — |
| **AC-05** | With the server stopped **for 10 minutes**, the collector continues producing at cadence; `spool_records` grows monotonically; **`dropped_records_total == 0`**; collector process RSS growth < 50 MB. | failure suite T2 | T2 |
| **AC-06** | After server restart, **all spooled batches are uploaded and acked within 5 minutes**; `acked_seq == highest_seq`; chart shows **no gaps** for the outage window (gap detection meta reports 0 unexpected gaps). | failure suite T3 + query check | T3 |
| **AC-07** | Every uploaded batch exists exactly once in `ingested_batches` (count of rows == highest_seq); sample counts per batch match `BatchResult.accepted_samples`. | SQL assertions in e2e | T4 |
| **AC-08** | `GET /v1/collectors/{id}/metrics?metric=collector_cpu_percent&from=<t0>&to=<t1>` returns ≥ 95% of expected points for the run window and correct `resolution`; response time p95 **< 300 ms** for 24 h @ 10 s step on the reference dev machine. | integration + timing assert | L-03 |
| **AC-09** | The web chart renders ≥ 50 points for a 5-minute window and shows the last value; chart data matches API response (spot-checked by Playwright via `data-testid` hooks). | Playwright AC-09 | — |
| **AC-10** | Collector detail page shows: status, last heartbeat (≤ 90 s ago when active), version, site, policy version issued == acked, spool stats, metrics received count — all non-null. | Playwright AC-10 | — |
| **AC-11** | `GET /v1/collectors` lists collectors with `status`, `last_heartbeat_at`, `agent_version`, `site`; auto-refresh updates status within 30 s of a state change. | Playwright + API test | — |
| **AC-12** | Login: correct credentials ⇒ session cookie + CSRF cookie; wrong password ⇒ 401 problem+json; la. login rate limit triggers 429 after 10 failures/min; logout revokes session (subsequent call 401). | `tests/integration/security_test.go` + Playwright | S-09, S-10 |
| **AC-13** | Collector restart mid-run: after restart, **no batch_seq is skipped** in `ingested_batches` beyond those never spooled; watermark survives (replayed batches appear as `STATUS_DUPLICATE`, count ≥ 0); **zero sample-level duplicates** in `metric_samples` for `(series_id, ts)`. | T10 + SQL assertion | T10 |
| **AC-14** | Database restart (container kill -9, restart) mid-ingest: no corrupted rows; ingest resumes; **no acked batch is missing** (compare collector `acked_seq` with DB rows); `readyz` 503 during outage, 200 after ≤ 30 s. | T9 | T9 |
| **AC-15** | Tenant isolation: Org B cannot read or affect Org A's collectors, series, samples via API (404/403, no data), SQL under wrong context (0 rows / CHECK violation), or cert identity (`collector_id` mismatch rejected). | `rls_test.go` + `tenant_isolation_test.go` + S-06/S-07 | T8 |
| **AC-16** | Revocation: after `:revoke`, the live stream terminates within 5 s (`Disconnect CODE_REVOKED`), reconnects fail; collector stops retrying permanently and reports it in `doctor`; audit log entry exists. | e2e T7 | T7 |
| **AC-17** | Expired token: enrollment attempt returns the generic denied error; no collector/cert rows created; attempt counted in `argus_enroll_attempts_total{result="expired"}`. | T6 | T6 |
| **AC-18** | Malformed/poison batch: a batch with out-of-range value or timestamp is `STATUS_REJECTED`, is **not retried**, lands in collector `deadletter/`, and never appears in `metric_samples`. | T5 | T5 |
| **AC-19** | No secret leakage: gitleaks clean on repo; runtime log scan (automated test greps captured logs for token/private-key patterns) finds **zero** occurrences; `enrollment_tokens.token_hash` only (never raw) in DB. | S-08 | S-08 |
| **AC-20** | Self-observability: all metrics in SPEC §15 are present and non-zero in a normal run (scripted assertion against `/metrics` for server + collector); `/v1/readyz` reflects DB down/up correctly. | observability snapshot test | — |
| **AC-21** | Load direction (not production proof): L-01 (single stream, 20k samples/s, 10 min) completes with **0 errors**, `ingested_batches` consistent, and a recorded ingestion p95 reported in `LOAD_TEST_REPORT.md`. | L-01 | L-01 |
| **AC-22** | Fleet shape: L-02 (200 collectors × 100 samples/s, 10 min) completes with all 200 streams active at peak, no stream thrash (reconnect count ≤ 5 total), consistent batch accounting. | L-02 | L-02 |

## Failure / security suite roll-ups

| Criterion | Meaning |
|---|---|
| **AC-23** | All failure tests T1–T10 pass in CI (nightly job `failure-suite`) on the pinned stack. |
| **AC-24** | All security tests S-01–S-12 pass (release gate), including oversized payload rejection and replay attempts. |

## Out-of-scope checks (must NOT be claimed in Phase 1)

- Production HA/DR, RPO/RTO (single-node dev topology only).
- SNMP/device metric accuracy (no devices exist yet).
- Multi-region, multi-tenant provisioning UX, billing.
- Long-duration soak (Phase 2 begins soak testing after compression/retention policies land).

## Acceptance run procedure (executed in M6, recorded in `ACCEPTANCE_RUN.md`)

1. `make reset && make dev` on the pinned machine; wait for `--wait` healthy.
2. Run `make e2e` (AC-01…AC-20 subset) — capture JUnit XML.
3. Run failure suite: `make failure` — capture logs + SQL evidence per T#.
4. Run security suite: `make security` — capture report.
5. Run load: `make load L=L01` then `L=L02` (or on the load host) — capture CSV + histograms.
6. Fill `ACCEPTANCE_RUN.md` table: AC ID → status → artifact path → reviewer initials.
7. Any red AC blocks Phase-1 completion; failures are triaged as product bugs, not accepted deviations (unless the spec is amended through the ADR-review process).
