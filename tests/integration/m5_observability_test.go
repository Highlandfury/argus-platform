package integration

import (
	"context"
	"testing"

	"github.com/argus-platform/argus/internal/platform/telemetry"
)

// TestM5CollectorGaugesRefresh proves the §15 DB-derived gauges reflect real
// collector states, including the computed stale status: an "active" row whose
// heartbeat is older than 3x the policy interval must count as stale and never
// as healthy.
func TestM5CollectorGaugesRefresh(t *testing.T) {
	ctx := context.Background()
	_, fresh, _, _ := m4Env(t, "m5-gauge-"+newUUID()[:8])
	_, old, _, _ := m4Env(t, "m5-stale-"+newUUID()[:8])

	_, err := ownerPool.Exec(ctx,
		`UPDATE collectors SET status='active', last_heartbeat_at=now() WHERE id=$1`, fresh.CollectorID)
	must(t, err)
	_, err = ownerPool.Exec(ctx,
		`UPDATE collectors SET status='active', last_heartbeat_at=now() - interval '5 minutes' WHERE id=$1`, old.CollectorID)
	must(t, err)

	reg := telemetry.New("test", "0", "0")
	gauges := telemetry.NewCollectorGauges(appPool, authPool, reg)
	must(t, gauges.Refresh(ctx))

	fams, err := reg.Gather()
	must(t, err)
	var active, stale float64
	ages := map[string]float64{}
	for _, fam := range fams {
		switch fam.GetName() {
		case "argus_collectors":
			for _, m := range fam.GetMetric() {
				labels := map[string]string{}
				for _, lp := range m.GetLabel() {
					labels[lp.GetName()] = lp.GetValue()
				}
				switch labels["status"] {
				case "active":
					active = m.GetGauge().GetValue()
				case "stale":
					stale = m.GetGauge().GetValue()
				}
			}
		case "argus_collector_last_heartbeat_age_seconds":
			for _, m := range fam.GetMetric() {
				for _, lp := range m.GetLabel() {
					if lp.GetName() == "collector_id" {
						ages[lp.GetValue()] = m.GetGauge().GetValue()
					}
				}
			}
		}
	}
	if active < 1 || stale < 1 {
		t.Fatalf("collector gauges: active=%v stale=%v (want both >= 1)", active, stale)
	}
	if age := ages[fresh.CollectorID]; age <= 0 || age > 90 {
		t.Fatalf("fresh collector heartbeat age = %v (want 0<age<=90)", age)
	}
	if age := ages[old.CollectorID]; age < 200 {
		t.Fatalf("stale collector heartbeat age = %v (want >=200)", age)
	}
}
