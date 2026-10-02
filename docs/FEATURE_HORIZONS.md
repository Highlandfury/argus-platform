# ARGUS — FEATURE HORIZONS MAP

**Purpose.** Map the "top-of-the-line" feature blueprint (the 60-item vision)
onto the canonical, phase-gated plan so the ambition is fully captured without
silently changing scope. **The canonical spec (`argus-platform-spec/`) remains
authoritative.** This document only labels where each item lives, what already
exists, and which items need an explicit decision.

**Legend:** done · current phase (Phase 2) · scheduled in MVP later phases
(Steps 9-18) · **V2** · **V3** · candidate, not in the spec (decision needed) ·
deliberate divergence from the blueprint (decision needed).

**The four questions this product answers.**
- Is it working? - built (edge collectors, polling, checks, status).
- What is happening? - built and being completed (metrics, interfaces, charts,
  dashboards, poll health).
- Why is it happening? - **V2** (correlation, incidents, RCA).
- What should happen next? - **V2** recommendations, **V3** gated automation.

**Eras:** MVP = pilot product (build-order Steps 1-18; Phase 1 = Step 1,
Phase 2 = Steps 3-8, Phase 3 = Steps 9-13, Phase 4 = Steps 14-18). V2 = first
6-12 months after pilot. V3 = bounded autonomy & analytics.

---

## 1. Discovery, inventory, identity

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 1 | Universal discovery (devices, methods, classification, auto profiles) | MVP Step 9 (v1); V2/V3 depth | v1 in Phase 3: seed subnets, gentle ICMP sweep, SNMP classify, ARP/OUI, candidates, promote/merge. WMI/WinRM/gNMI/NETCONF/REST adapters V2+. |
| 30 | Asset management (asset ID, location, warranty, attachments) | MVP inventory; V2 lifecycle | partial: identity/serial/firmware today; warranty/photos/docs V2. |
| 24 | IPAM | V2 | canonical "IPAM full-lite" (V2). |
| 25 | VLAN visibility | MVP Step 10 (v1); V2 management | VLANs via Q-BRIDGE/LLDP with topology; VLAN management UI V2. |
| 41 | Device security posture | V2 | building blocks today (SNMP v2c warning posture); posture checks V2. |
| 43 | Fine-grained RBAC | MVP increment (done); V2 full RBAC-SC | capability + scope bindings built (M7); conditions/enterprise roles V2. |

## 2. Telemetry sources and data core

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 2 | SNMP (v1/v2c/v3, hardware/optics/PoE, MIB/OID browser, custom OIDs, vault) | MVP Step 5; V2 depth | core built: v2c + v3 authPriv, system/IF-MIB/HC counters/CPU, wrap-safe math, tiers, credential vault with per-session encrypted delivery. **SNMP v1 deliberately rejected (canonical: historic/discouraged) - decision D1.** Optics/PoE, vendor packs, MIB/OID browser, custom OIDs V2. |
| 3 | Streaming telemetry (gNMI/OpenConfig/NETCONF/YANG) | V2 adapter family (plugin model) - decision D2 | not MVP; the policy/collector plugin seams are already in place. |
| 4 | Real-time interface monitoring (full counters, utilization, baselines) | MVP Step 6 (done); V2 depth | counters/errors/discards/speed + charts + gaps today; optics/PoE, baseline comparison, heat strips V2. |
| 5 | Traffic flows (NetFlow/sFlow/IPFIX, top talkers/apps) | V3 | canonical V3 "Flow ingestion ... explicit caps/truncation". |
| 6 | Packet capture | V3 | canonical V3, opt-in/forensic - matches "don't PCAP everything". |
| 49 | Time-series engine (cardinality, compression, downsampling, retention) | MVP Step 4 (done, M8) | CAGGs 1m-1d + retention matrix + cardinality guards + measured compression on rollups; raw compression blocked by TimescaleDB x RLS (tracked, ADR-016/M13). |
| 50 | Internal event bus | V2 revalidation | NATS deliberately deferred (G2); revalidate when a second async consumer exists. |
| 51 | Plugin architecture (vendor adapters) | V2+ | adapter model lands with Wi-Fi/integrations; marketplace V3. |
| 52 | Monitoring templates (per-vendor profiles) | MVP core; V2 packs | declarative template engine + core pack built; curated per-vendor packs V2. |
| 53 | Custom monitoring (OID/API/command + thresholds) | V2 | part of the MIB/OID browser and custom-OID work. |

## 3. Reachability, synthetic testing, WAN

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 7 | Active testing (ping, traceroute, TCP/UDP, DNS, HTTP(S), TLS) | MVP Step 12; M9 on-demand (done) | ICMP + on-demand checks built; full diagnostics v1 (traceroute/MTR/DNS/HTTP/TLS with structured evidence) Phase 3 Step 12. |
| 8 | Internet path monitoring (where degradation starts) | V2 | derives from Step 12 traceroute + WAN probes; hop-stability analysis V2. |
| 9 | Multi-WAN intelligence (per-circuit health, explainable score) | MVP Step 13 (v1); V2 depth | WAN v1 in Phase 3: circuits, probe suites, ISP reports; scoring/depth V2. |
| 20 | DNS monitoring | MVP Step 12; V2 depth | DNS checks v1 with diagnostics; resolver health/NXDOMAIN/SERVFAIL/record drift V2. |
| 21 | Website/application monitoring (synthetic transactions) | V2 | HTTP/TLS checks v1 in Step 12; login/search/pay transaction scripts V2. |
| 22 | Wi-Fi monitoring + heatmaps | MVP Step 15 (v1); V2 depth | v1 in Phase 4 (AP inventory, clients, radios, AP<->switch edges); RF depth + measured heatmaps V2. |
| 23 | DHCP monitoring | V2 | pool/lease checks and DHCP visibility V2. |
| 26 | Routing monitoring (OSPF/BGP/VRRP/PCC/SD-WAN) | V2 | neighbor/route basics via Step 10; BGP/MPLS/path-depth V2. |
| 27 | ISP monitoring + SLA | MVP Step 13; V2 | circuits + availability report v1 in Phase 3; SLA math depth V2. |

## 4. Topology, dependency, suppression

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 10 | Automatic topology (LLDP/CDP/ARP/MAC, interactive map) | MVP Step 10 | Phase 3: LLDP/FDB edges with confidence + evidence, MAC->port, site map UI. |
| 11 | Dependency mapping (suppress children, one root cause) | MVP Step 11 | Phase 3; M11 ships only device-down gating until topology exists. |
| 56 | Digital twin / simulation | Horizon | candidate (post-V3 research bet; not in spec) - decision D3. |

## 5. Alerts, incidents, evidence, AI

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 12 | Alerting engine (threshold/state/baseline/anomaly/composite/SLA/capacity/security) | MVP Step 7 (v1) | **M11 next**: threshold/absence/rate, state machine, dedup, storm control, maintenance windows, SMTP/webhook/Slack/Teams, default templates. Composite/baseline/security rules V2. |
| 13 | Noise reduction (dedup/correlation/hysteresis/flapping/dynamic thresholds) | MVP Step 7 + Step 11; V2 | dedup + storm + flapping + hysteresis + maintenance in M11; topology suppression Step 11; baseline/dynamic thresholds V2. |
| 14 | Incident management (timeline, impact, MTTx) | V2 | canonical V2 "RCA v1 + incidents". |
| 15 | AI troubleshooting assistant (evidence-bound) | V3 | canonical V3 AI layer with guardrails; requires V2 evidence bundles first. |
| 19 | Change correlation (config change -> degradation) | V2 | needs config backup/diff (16/17). |
| 55 | Evidence-based RCA (observed/calculated/inferred/unknown + confidence) | MVP discipline (done); V2 engine | discipline applied throughout the evidence docs; the correlation engine is V2. |
| 57 | Smart recommendations with evidence | V2/V3 | candidate growing out of baseline/forecasting. |

## 6. Configuration and automation

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 16 | Configuration management (backup/version/diff) | V2 | canonical V2 (read-only, 4-6 vendors). |
| 17 | Config drift detection | V2 | with 16. |
| 18 | Automation rails (read-only -> propose -> approve -> execute) | V2 (safe) / V3 (mutating) | canonical: notify/diagnose/annotate V2; mutating with blast-radius gates V3. |
| 54 | Troubleshooting workspace | V2 | candidate UI compounding diagnostics + pages + RCA. |
| 58 | NOC wallboard | V2 (small) | candidate; trivial once incidents exist. |

## 7. Platform, operations, scale

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 28 | SLA monitoring | V2 | availability v1 with WAN; SLA reports V2. |
| 29 | Capacity planning/forecasting | V3 | canonical V3. |
| 31 | Geographic/branch views | MVP multi-site; V2 polish | org/site model + site dashboards today; branch roll-ups with later phases. |
| 32 | Multi-tenancy | MVP isolation (done); V2 SaaS GA | RLS tenant isolation built; SaaS quotas/metering V2. |
| 34 | Reporting (PDF/CSV/scheduled) | V2 | canonical V2 reports. |
| 35 | Role-based dashboards | V2 | site dashboard v1 exists; role dashboards V2. |
| 36 | Mobile/PWA | V3 | canonical V3. |
| 37 | Notifications breadth (SMS/WhatsApp/Telegram/Push...) | MVP core; V2 rest | M11: SMTP/webhook/Slack/Teams; SMS/Telegram/PagerDuty V2. |
| 38 | API (REST/webhooks/WebSocket/GraphQL) | REST + SSE built | REST + SSE (M11 alert stream); **GraphQL not spec'd - decision D4**. |
| 39 | Integrations (Grafana/Prometheus/Loki/OTEL/ITSM/K8s/cloud) | V2/V3 | canonical V2/V3. |
| 42 | Audit logs | MVP rows; DB later | structured audit sink today; DB audit table + viewer later. |
| 44 | Secrets management | MVP (done) | envelope vault, write-only API, per-session encrypted delivery, RAM-only. |
| 45 | High availability | MVP Step 16 | Phase 4 (single-node now; HA compose). |
| 46 | Edge collectors | MVP (done) | mTLS, signed policy, spool. |
| 47 | Store-and-forward | MVP (done) | failure-tested (T2/T3/T10). |
| 48 | Retention matrix | MVP (done, M8) | per-class windows + verification job. |

## 8. Commercial (MSP/SaaS)

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 33 | Customer portal / MSP mode | V2 | canonical V2 MSP mode. |
| 59 | Tenant branding | V2 | with 33. |
| 60 | Billing/plans | V2 business decision | not spec'd - decision D5. |

## 9. Security

| # | Blueprint | Where it lives | Status |
|---|---|---|---|
| 40 | Network security monitoring (scans, rogue DHCP, anomalies) | V2/V3 with a clear boundary | partial canonical items (rogue DHCP, unknown devices); keep explicit "not a SIEM/NDR replacement" boundary - decision D6. |

---

## Decisions needed (explicit; nothing changes silently)

| ID | Item | Recommendation |
|---|---|---|
| D1 | SNMP v1 support | Keep the canonical rejection (v2c warns, v3 preferred). |
| D2 | Streaming telemetry (gNMI/NETCONF/YANG) as core vs V2 adapter family | V2 adapter family on the existing plugin seams. |
| D3 | Digital twin/simulation | New R&D bet; candidate for post-V3, not a phase item. |
| D4 | GraphQL | Not spec'd; REST + SSE + webhooks already cover the platform. |
| D5 | Billing/plans; NOC wallboard; troubleshooting workspace | Business/UX calls; recommend V2 candidates. |
| D6 | Security-monitoring depth + NDR boundary | Confirm V2/V3 scope and the stated boundary. |

## Maintenance

Updated at each milestone gate. The canonical spec remains authoritative;
this document records mapping + decisions only and never overrides a phase
gate.
