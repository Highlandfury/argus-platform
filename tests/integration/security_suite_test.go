package integration

import "testing"

// TestSecuritySuite is the canonical M6 security release-gate entry point
// (PHASE_1_SECURITY.md S-01…S-16 direction). It runs the already-automated
// scenarios under canonical S identifiers so CI (release gate job
// `security-suite`, push to main / manual dispatch) has one stable selector:
//
//	go test ./tests/integration/... -run '^TestSecuritySuite$' -count=1 -v
//
// Mapping (all delegated tests are real end-to-end scenarios against the
// containerized database + in-process gRPC control plane; nothing is mocked):
//
//	S-01 invalid enrollment token + per-IP rate limit -> TestM3EnrollmentMatrix,
//	                                                     TestM3EnrollmentRateLimit
//	S-02 expired / already-used token (uniform denial)-> TestM3EnrollmentMatrix
//	S-03 client cert from unknown CA (TLS reject)     -> TestM3UnknownIdentityRejected
//	S-04 cert/claim confusion (hello != cert)          -> TestM3StreamLifecycle
//	S-05 policy verification + acknowledgement         -> TestM3StreamLifecycle
//	      (the collector-side tamper/last-good unit checks live in
//	       internal/modules/collectors TestPolicySigningRoundTrip and the
//	       collector policy package; recorded in ACCEPTANCE_RUN M6d)
//	S-06 cross-tenant API access (404, no oracle)      -> TestTenantIsolationReads,
//	                                                     TestCrossTenantWritesDenied,
//	                                                     TestM4MetricTenantIsolation
//	S-07 RLS bypass attempts / role escalation         -> TestAuthRoleBoundaries,
//	                                                     TestAppCannotEscalateRole,
//	                                                     TestUnscopedAccessSeesNothing
//	S-08 secret leakage (log scan + hashed at rest)    -> TestM5LogScanNoSecretLeakage
//	S-09 login brute force (429 after threshold)       -> TestLoginRateLimitS09
//	S-10 CSRF (double submit enforced)                 -> TestLoginSessionLifecycle
//	S-11 revoked identity (terminal, reconnect fails)  -> TestM3StreamLifecycle
//	S-12 oversized / malformed payload rejection       -> TestM4PoisonBatches
//	      (64 KiB CSR InvalidArgument, 5001-sample batch, 16 MiB gRPC cap via
//	       configuration + argus_grpc_malformed_total; unit-level size matrices
//	       in internal/modules/ingest)
//	S-13 replay attempts (batches + tokens)            -> TestM4DuplicateBatchOriginalWins,
//	                                                     TestM4LostAckReplayedAsDuplicate
//	S-16 auth enumeration uniformity (timing/shape)    -> TestLoginEnumerationUniformS16
//	S-17 inventory authz + cross-tenant probes         -> TestInventoryAuthzS17,
//	                                                     TestInventoryTenantIsolationS17
//	S-18 inventory capability enforcement (P2-D5)      -> TestInventoryCapabilityEnforcement
//	S-19 inventory scope bindings (P2-D5)              -> TestInventoryScopeEnforcement
//	S-20 inventory CSRF still required on mutations    -> TestInventoryCSRFEnforcement
//	S-21 inventory cross-tenant devices/interfaces/    -> TestInventoryCrossTenantS21
//	     groups + enumeration resistance
//	S-22 credential capability enforcement (write-     -> TestCredentialsCapabilityEnforcement
//	     only surface; viewer holds no credential
//	     capability, 401 before 403)
//	S-23 credential CSRF required on mutations        -> TestCredentialsCSRFEnforcement
//	S-24 credential cross-tenant invisibility + RLS   -> TestCredentialsCrossTenantS24
//	     probes + enumeration parity
//	S-25 credential scope restriction (org-wide       -> TestCredentialsScopeRestriction
//	     credential surface)
//
// S-14 (injection): parameterized SQL + dimension canonicalization are
// unit-tested (internal/modules/metrics) and every query is bound-parameter
// based; S-15 (ingest flood): server-driven credit window + collector spool
// backpressure evidence is recorded in LOAD_TEST_REPORT.md. Both are documented
// in ACCEPTANCE_RUN M6d rather than duplicated here.
func TestSecuritySuite(t *testing.T) {
	t.Run("S01_invalid_token_and_rate_limit", func(t *testing.T) {
		t.Run("matrix", TestM3EnrollmentMatrix)
		t.Run("rate_limit", TestM3EnrollmentRateLimit)
	})
	t.Run("S02_expired_and_used_tokens", TestM3EnrollmentMatrix)
	t.Run("S03_unknown_ca_rejected", TestM3UnknownIdentityRejected)
	t.Run("S04_cert_claim_confusion", TestM3StreamLifecycle)
	t.Run("S05_policy_verification", TestM3StreamLifecycle)
	t.Run("S06_cross_tenant_api", func(t *testing.T) {
		t.Run("reads", TestTenantIsolationReads)
		t.Run("writes", TestCrossTenantWritesDenied)
		t.Run("metrics", TestM4MetricTenantIsolation)
	})
	t.Run("S07_rls_bypass_and_escalation", func(t *testing.T) {
		t.Run("auth_role_boundaries", TestAuthRoleBoundaries)
		t.Run("no_escalation", TestAppCannotEscalateRole)
		t.Run("unscoped_sees_nothing", TestUnscopedAccessSeesNothing)
	})
	t.Run("S08_secret_leakage_log_scan", TestM5LogScanNoSecretLeakage)
	t.Run("S09_login_brute_force", TestLoginRateLimitS09)
	t.Run("S10_csrf", TestLoginSessionLifecycle)
	t.Run("S11_revoked_identity", TestM3StreamLifecycle)
	t.Run("S12_oversized_malformed_payloads", TestM4PoisonBatches)
	t.Run("S13_replay_attempts", func(t *testing.T) {
		t.Run("batch_replay", TestM4DuplicateBatchOriginalWins)
		t.Run("lost_ack_replay", TestM4LostAckReplayedAsDuplicate)
	})
	t.Run("S16_enumeration_uniformity", TestLoginEnumerationUniformS16)
	t.Run("S17_inventory_authz_and_isolation", func(t *testing.T) {
		t.Run("authz", TestInventoryAuthzS17)
		t.Run("cross_tenant", TestInventoryTenantIsolationS17)
	})
	t.Run("S18_inventory_capability_enforcement", TestInventoryCapabilityEnforcement)
	t.Run("S19_inventory_scope_bindings", TestInventoryScopeEnforcement)
	t.Run("S20_inventory_csrf_mutations", TestInventoryCSRFEnforcement)
	t.Run("S21_inventory_cross_tenant_surface", TestInventoryCrossTenantS21)
	t.Run("S22_credentials_capability_enforcement", TestCredentialsCapabilityEnforcement)
	t.Run("S23_credentials_csrf_mutations", TestCredentialsCSRFEnforcement)
	t.Run("S24_credentials_cross_tenant_surface", TestCredentialsCrossTenantS24)
	t.Run("S25_credentials_scope_restriction", TestCredentialsScopeRestriction)
}
