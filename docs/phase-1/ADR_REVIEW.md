# PHASE-1 ADR REVIEW

Review of the ADRs that Phase 1 is intended to validate (per the architecture package), plus required amendments before/during implementation. Format per ADR: **What the skeleton proves · What it does not prove yet · Verdict · Action.**

---

## ADR-005 — Collector architecture (edge collector, outbound-only, spool, HA pair)

**Phase-1 design realizations:**
- Outbound-only connectivity from the collector is structurally enforced: the collector has no listeners except loopback; every connection is dialed to the server (8444 once, 8443 continuously). ✔ assumption confirmed by construction.
- Durable spool with ack-gated deletion validated by design (T2/T3/T10, AC-05/AC-06/AC-13): bounded segments, CRC framing, contiguous ack watermark, replay with idempotent ingest.
- Certificate identity (enroll once, mTLS thereafter) is the identity primitive; 90-day leafs.
- **Deviations registered in the spec:** (1) HA leader-lease pair deferred (G3); (2) certificate renewal RPC deferred (G14); (3) enrollment runs on a separate TLS listener (G4) — a realization detail, not a contradiction.

**What the skeleton does not prove:** leader election/failover semantics; scope-split collectors; self-update; Windows runtime parity; multi-VLAN network position effects; sustained soak with device-grade polling volume.

**Verdict:** ADR-005's core risk (the transport + durability spine) is exercised and falsifiable in Phase 1; the deferred items are orthogonal (scheduling/HA lifecycle), not foundational.

**Action:** add a *Phase-1 implementation note* to ADR-005: two-listener enrollment split (8444 token-gated / 8443 mTLS), single-collector scope, renewal deferred; no change to the decision itself.

---

## ADR-014 — Event bus / queue and collector transport

**Phase-1 design realizations:**
- The **external half** of the decision (gRPC bidi over mTLS with collector-owned spool) is implemented and load-tested. The protocol contract (`collector.proto`) proves schema-driven control+telemetry on one stream, with server-driven flow control and deterministic disconnect semantics.
- The **internal half** (NATS JetStream for async consumers) is deliberately absent (G2). There are no async consumers in Phase 1; ingest commits directly to PostgreSQL; the module boundary that would publish to NATS exists (`ingest` service interface) so the bus is additive later.

**What the skeleton does not prove:** JetStream at-least-once semantics, stream replay, tenant accounts/subject isolation, mTLS `verify_and_map` for internal services, bus failure modes, SSE fanout source. These arrive with the alert engine (Step 7 of the build order), which is the first real async consumer.

**Verdict:** the riskiest half of ADR-014 (edge transport + store-and-forward + idempotent receiver) is validated; the internal bus remains a planned but untested choice — appropriately so, since it has no consumer yet.

**Action:** add a *Phase-1 implementation note* to ADR-014: internal bus deferred to Phase 2 with the first consumer; the ack-after-commit durability rule applies only to storage; NATS publishing will be a post-commit side effect, never a durability dependency (this preserves the architecture's §34.1 consistency model).

---

## Required amendments to other ADRs / architecture (from the Phase-1 gate)

| ADR / section | Amendment | Reason | Status |
|---|---|---|---|
| ADR-004 + architecture §21 (`metric_samples` DDL) | **Add `org_id uuid NOT NULL` to `metric_samples`** (denormalized) and RLS directly on it. | RLS-via-join on a hypertable is slow/fragile; late backfill at scale is a massive migration. Cost: ~16 B/sample pre-compression (compression segments by `series_id`; `org_id` compresses well as ordinal). | **Required before M1** (migration 000003/000005 encode it) |
| ADR-004 | Version note: pin PostgreSQL 18 + TimescaleDB 2.30.1 (`2.30.1-pg18`); ON CONFLICT conflict-handling fixes in 2.30.1 are relied upon for the ingest claim path (G12). | Verified compatibility + relevant upstream fixes | Required before M1 (pins in SPEC §5) |
| ADR-003 | Note: Phase 1 runs a single Timescale image; PostGIS deferred (G7). | No spatial data yet | Informational |
| ADR-011 (multi-tenancy) | **Phase-1 earns the RLS claim with evidence** (T8, S-06/S-07, pooled-connection test). No change; add "Phase-1 validated (RSL + `SET LOCAL` under pooled connections)" note when tests pass. | Supports the ADR's central claim with empirical proof | Update after M1 |
| ADR-001 | Note: Phase 1 keeps all server modules in one process and validates the `ingest` boundary; no extraction trigger fires. | Supporting evidence for the modular monolith | Informational |
| Architecture §22 (API) | Phase-1 API is a strict subset (14 endpoints); `POST /v1/enrollments` gains `Idempotency-Key`; metrics query without CAGGs (documented in SPEC §13). | Scope reality; no semantic conflict | Informational |
| Architecture §27.3 (enrollment) | Two-listener realization documented (same process); token format/exact TTL/atomic claim specified; renewal deferred. | Realization detail | With ADR-005 note |

## New decision candidates (record only; no ADR needed for Phase 1)

| Candidate | When | Note |
|---|---|---|
| ADR-016: "Ingest write path" (array-unnest vs staging+COPY vs Timescale batch tooling) | Phase 2, with L-01/L-02 + soak data | Phase-1 numbers become the evidence baseline; extraction/optimization decided on measured thresholds, not fashion. |
| ADR-017: "Certificate lifecycle service" (renewal, CRL/OCSP, rotation) | Phase 2 (with multi-collector fleets) | Phase-1 defers renewal; revocation is status-check based today. |
| ADR-018: "Collector HA mode selection" (leader-lease vs scope-split defaults by site size) | Build-order step 16 | Phase-1 data (spool behavior, reconnect cost) informs thresholds. |

## Verdict on the gate

The walking skeleton **does validate the Phase-1-targeted ADR assumptions** (ADR-005 spine, ADR-014 external half, ADR-011 RLS claim, ADR-001 boundary discipline) and **honestly defers** what it cannot yet exercise. One schema amendment (G5) is mandatory before M1; three ADRs receive implementation notes; no decision is contradicted. Proceed to implementation.
