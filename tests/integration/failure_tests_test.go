package integration

import "testing"

// TestFailureSuite is the canonical M6 failure-suite entry point
// (PHASE_1_FAILURE_TESTS.md T1–T10). It runs the already-automated scenarios
// under their canonical T identifiers so CI (nightly/release job
// `failure-suite`) has one stable selector:
//
//	go test ./tests/integration/... -run '^TestFailureSuite$' -count=1 -v
//
// Mapping (each T-case remains a real end-to-end scenario against the
// containerized database + in-process gRPC control plane; nothing is mocked):
//
//	T1  normal operation (ingest happy path)          -> TestM4BatchIngestHappyPath
//	T2  server unavailable / collector autonomy       -> TestM4CollectorSpoolSurvivesOutageAndDrains
//	T3  stream interruption + reconnect               -> TestM3StreamLifecycle
//	T4  duplicate batch (idempotency, original wins)  -> TestM4DuplicateBatchOriginalWins
//	T5  malformed / poison metric                     -> TestM4PoisonBatches
//	T6  expired/used/unknown enrollment token         -> TestM3EnrollmentMatrix
//	T7  revoked collector (terminal disconnect)       -> TestM3StreamLifecycle
//	T8  tenant isolation (reads/writes/metric path)   -> TestTenantIsolationReads,
//	                                                     TestCrossTenantWritesDenied,
//	                                                     TestM4MetricTenantIsolation
//	T9  database restart during ingest (no acks lost) -> TestDatabaseRestartRecovery
//	T10 collector restart (spool/watermark survival)  -> TestM4CollectorRestartResumesFromWatermark
//
// Filename note: the file plan lists `failure_tests.go`; Go's build model
// requires `_test.go` for test code (a non-test file cannot reference the
// scenario test functions), so the suite lives here.
func TestFailureSuite(t *testing.T) {
	t.Run("T1_happy_path", TestM4BatchIngestHappyPath)
	t.Run("T2_server_unavailable", TestM4CollectorSpoolSurvivesOutageAndDrains)
	t.Run("T3_stream_interruption", TestM3StreamLifecycle)
	t.Run("T4_duplicate_batch", TestM4DuplicateBatchOriginalWins)
	t.Run("T5_poison_metric", TestM4PoisonBatches)
	t.Run("T6_enrollment_token_failures", TestM3EnrollmentMatrix)
	t.Run("T7_revoked_collector", TestM3StreamLifecycle)
	t.Run("T8_tenant_isolation", func(t *testing.T) {
		t.Run("reads", TestTenantIsolationReads)
		t.Run("writes", TestCrossTenantWritesDenied)
		t.Run("metrics", TestM4MetricTenantIsolation)
	})
	t.Run("T9_database_restart", TestDatabaseRestartRecovery)
	t.Run("T10_collector_restart", TestM4CollectorRestartResumesFromWatermark)
}
