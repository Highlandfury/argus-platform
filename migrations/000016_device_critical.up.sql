-- 000016_device_critical.up.sql
-- Argus Phase 2 M10-S0 — operator-facing device criticality.
--
-- Canonical: docs/07-discovery-snmp.md §12.3 "device backoff on consecutive
-- failures (doubling to 15 min ceiling; critical devices 5 min ceiling)" and
-- docs/15 §27 (critical ceiling 5 min). M9-S4 implemented the collector-side
-- 5-minute ceiling (`poll.Target.Critical` + AdaptiveBackoff) but left the
-- criticality flag with no operator-facing source (M9_EVIDENCE §14.6.1). This
-- column is that source: the inventory API accepts/returns `critical` and the
-- signed policy bundle carries it to the collector.
--
-- Additive with a NOT NULL default: existing rows and old writers keep working
-- unchanged; the flag is collection/policy metadata, never an identity key.

ALTER TABLE devices ADD COLUMN critical boolean NOT NULL DEFAULT false;
