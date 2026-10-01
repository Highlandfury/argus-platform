package integration

// M10-S2 (Phase 2): SNMP-polled interface data is linked into the inventory
// `interfaces` rows through the real poll -> spool -> stream -> ingest path:
// auto-create on first sight, live attribute updates, first/last-seen
// maintenance, audited ifIndex rebinding (identity preserved; ifIndex never
// identity) and the interface status rollup in the API payloads. VLAN/Q-BRIDGE
// membership is explicitly deferred (evidence §8).

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	collectoridentity "github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/poll"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/modules/inventory"
)

// m10s2Env is m4Env with m3 options (M10-S2 needs the observable audit sink).
func m10s2Env(t *testing.T, slug string, opts ...m3Option) (*m3Env, collectoridentity.Identity, *collectoridentity.Store, string) {
	t.Helper()
	env := startM3Env(t, opts...)
	orgID, siteID, userID := devTenant(t, slug)
	raw, _, _, err := env.svc.CreateEnrollmentToken(context.Background(),
		mustUUID(t, orgID), mustUUID(t, siteID), time.Hour, uuidPtr(mustUUID(t, userID)))
	must(t, err)
	id, store := env.enrollIdentity(t, "collector-"+slug, raw)
	return env, id, store, orgID
}

func toSpoolInterfacesIT(in []poll.InterfaceObservation) []spool.InterfaceObservation {
	out := make([]spool.InterfaceObservation, len(in))
	for i, o := range in {
		out[i] = spool.InterfaceObservation{
			DeviceID: o.DeviceID, IfIndex: o.IfIndex, IfName: o.IfName,
			IfAlias: o.IfAlias, IfType: o.IfType, AdminStatus: o.AdminStatus,
			OperStatus: o.OperStatus, SpeedBPS: o.SpeedBPS, MTU: o.MTU,
			MAC: o.MAC, ObservedAt: o.ObservedAt,
		}
	}
	return out
}

// m10s2Pipeline wires one engine + spool + stream for the interface-linker
// tests, capturing every payload kind the M10-S2 path produces.
type m10s2Pipeline struct {
	engine  *poll.Engine
	sp      *spool.Spool
	rs      *rawBatchStream
	mu      sync.Mutex
	samples []poll.Sample
	health  []poll.Health
	obs     []poll.InterfaceObservation
}

func (p *m10s2Pipeline) take() ([]poll.Sample, []poll.Health, []poll.InterfaceObservation) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, h, o := p.samples, p.health, p.obs
	p.samples, p.health, p.obs = nil, nil, nil
	return s, h, o
}

// m10s2Step runs one scheduled poll and pushes samples + health + observations
// through the durable spool/stream/ingest path.
func m10s2Step(t *testing.T, p *m10s2Pipeline, clock *itClock) {
	t.Helper()
	if n := p.engine.Step(context.Background(), clock.Now()); n != 1 {
		t.Fatalf("probed %d targets, want 1", n)
	}
	ss, hs, obs := p.take()
	if len(hs) != 1 {
		t.Fatalf("health records = %d, want 1", len(hs))
	}
	if len(obs) == 0 {
		t.Fatal("no interface observations captured")
	}
	if len(ss) == 0 {
		t.Fatal("no samples captured")
	}
	if _, err := p.sp.Append(&spool.Batch{
		At: time.Now().UTC(), Samples: toSpoolSamplesIT(ss),
		Health: toSpoolHealthIT(hs), Interfaces: toSpoolInterfacesIT(obs),
	}); err != nil {
		t.Fatalf("spool append: %v", err)
	}
	drainSpoolToStream(t, p.sp, p.rs)
}

type m10InterfaceRow struct {
	ID          uuid.UUID
	IfIndex     int
	IfName      string
	IfAlias     *string
	AdminStatus *string
	OperStatus  *string
	SpeedBPS    *int64
	MTU         *int
	MAC         *string
	IfType      *int
	Role        string
	Monitored   bool
	FirstSeen   time.Time
	LastSeen    *time.Time
}

func m10LoadInterfaces(t *testing.T, orgID, deviceID uuid.UUID) map[string]m10InterfaceRow {
	t.Helper()
	rows, err := ownerPool.Query(context.Background(), `
		SELECT id, if_index, if_name, if_alias, admin_status, oper_status, speed_bps, mtu,
		       mac::text, if_type, role, monitored, first_seen_at, last_seen_at
		FROM interfaces WHERE org_id = $1 AND device_id = $2 ORDER BY if_index`, orgID, deviceID)
	must(t, err)
	defer rows.Close()
	out := map[string]m10InterfaceRow{}
	for rows.Next() {
		var r m10InterfaceRow
		must(t, rows.Scan(&r.ID, &r.IfIndex, &r.IfName, &r.IfAlias, &r.AdminStatus, &r.OperStatus,
			&r.SpeedBPS, &r.MTU, &r.MAC, &r.IfType, &r.Role, &r.Monitored, &r.FirstSeen, &r.LastSeen))
		out[r.IfName] = r
	}
	must(t, rows.Err())
	return out
}

// TestM10S2InterfaceLinkerEndToEnd proves the first SNMP poll auto-creates the
// interface rows with the polled attributes, a second poll only refreshes
// last_seen (no duplicates, no repeated creation audit), and the new
// speed/MTU series ride the normal metric path.
func TestM10S2InterfaceLinkerEndToEnd(t *testing.T) {
	audit := &recordingAudit{}
	env, id, store, orgID := m10s2Env(t, "m10s2-link-"+newUUID()[:8], withInventoryAudit(audit))
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	deviceID := createM9S2Device(t, orgUUID, siteID, "m10s2-switch", "127.0.0.1", "switch", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.Set(deviceID.String(), v2cCreds("switch"))
	clock := &itClock{now: time.Now().UTC()}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 2*time.Second, 1),
		Now:           clock.Now,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	p := &m10s2Pipeline{}
	p.engine = poll.NewEngine(poll.Config{
		Prober:   prober,
		Clock:    clock,
		OnSample: func(s poll.Sample) { p.mu.Lock(); p.samples = append(p.samples, s); p.mu.Unlock() },
		OnHealth: func(h poll.Health) { p.mu.Lock(); p.health = append(p.health, h); p.mu.Unlock() },
		OnInterfaces: func(obs []poll.InterfaceObservation) {
			p.mu.Lock()
			p.obs = append(p.obs, obs...)
			p.mu.Unlock()
		},
	})
	p.engine.ApplyTargets([]poll.Target{{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host), Name: "m10s2-switch",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}})
	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	p.sp = sp
	p.rs = dialBatchStream(t, env, id, store)

	// Poll 1: auto-create.
	m10s2Step(t, p, clock)
	rows := m10LoadInterfaces(t, orgUUID, deviceID)
	if len(rows) != 3 {
		t.Fatalf("interfaces auto-created = %d, want 3 (%+v)", len(rows), rows)
	}
	up := rows["Gi1/0/1"]
	if up.IfIndex != 1 || up.IfAlias == nil || *up.IfAlias != "uplink" {
		t.Fatalf("Gi1/0/1 identity = %+v", up)
	}
	if up.AdminStatus == nil || *up.AdminStatus != "up" || up.OperStatus == nil || *up.OperStatus != "up" {
		t.Fatalf("Gi1/0/1 status = admin %v oper %v, want up/up", up.AdminStatus, up.OperStatus)
	}
	if up.SpeedBPS == nil || *up.SpeedBPS != 1000000000 {
		t.Fatalf("Gi1/0/1 speed = %v, want 1000000000", up.SpeedBPS)
	}
	if up.MTU == nil || *up.MTU != 1500 {
		t.Fatalf("Gi1/0/1 mtu = %v, want 1500", up.MTU)
	}
	if up.MAC == nil || *up.MAC != "02:00:00:00:00:01" {
		t.Fatalf("Gi1/0/1 mac = %v, want 02:00:00:00:00:01", up.MAC)
	}
	if up.IfType == nil || *up.IfType != 6 || up.Role != "unknown" || !up.Monitored {
		t.Fatalf("Gi1/0/1 type/role/monitored = %v/%s/%v", up.IfType, up.Role, up.Monitored)
	}
	if up.LastSeen == nil || up.LastSeen.Before(up.FirstSeen.Add(-time.Second)) {
		t.Fatalf("Gi1/0/1 seen timestamps = first %v last %v", up.FirstSeen, up.LastSeen)
	}
	downIface := rows["Gi1/0/3"]
	if downIface.OperStatus == nil || *downIface.OperStatus != "down" {
		t.Fatalf("Gi1/0/3 oper = %v, want down", downIface.OperStatus)
	}

	// Auto-creation is audited once per new interface, attributed to the
	// authenticated collector, not a user.
	created := audit.find(inventory.ActionInterfaceAutoCreate)
	if len(created) != 3 {
		t.Fatalf("auto_create audit events = %d, want 3", len(created))
	}
	for _, ev := range created {
		if ev.ActorType != "collector" || ev.ActorID.String() != id.CollectorID {
			t.Fatalf("audit actor = %s/%s, want collector/%s", ev.ActorType, ev.ActorID, id.CollectorID)
		}
		if ev.OrgID != orgUUID || ev.ResourceType != "interface" {
			t.Fatalf("audit scope = org %s resource %s", ev.OrgID, ev.ResourceType)
		}
		if ev.Data["source"] != "snmp" || ev.Data["if_name"] == "" {
			t.Fatalf("audit data = %v", ev.Data)
		}
	}
	if rebinds := audit.find(inventory.ActionInterfaceRebind); len(rebinds) != 0 {
		t.Fatalf("first poll emitted %d rebind events", len(rebinds))
	}

	// The M10-S2 template gauges flow through the ordinary metric path.
	var speedSeries, mtuSeries int
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM metric_series
		WHERE org_id = $1 AND device_id = $2 AND metric_key = 'net.if.speed_bps'
		  AND dimensions->>'if_name' = 'Gi1/0/1'`, orgUUID, deviceID).Scan(&speedSeries))
	must(t, ownerPool.QueryRow(context.Background(), `
		SELECT count(*) FROM metric_series
		WHERE org_id = $1 AND device_id = $2 AND metric_key = 'net.if.mtu'
		  AND dimensions->>'if_name' = 'Gi1/0/1'`, orgUUID, deviceID).Scan(&mtuSeries))
	if speedSeries != 1 || mtuSeries != 1 {
		t.Fatalf("speed/mtu series = %d/%d, want 1/1", speedSeries, mtuSeries)
	}

	// Poll 2: refresh only. No new rows, no duplicate audit, last_seen moves.
	firstSeen := up.LastSeen
	clock.Advance(poll.TierInterval(poll.TierStandard))
	m10s2Step(t, p, clock)
	rows2 := m10LoadInterfaces(t, orgUUID, deviceID)
	if len(rows2) != 3 {
		t.Fatalf("re-poll created duplicates: %d rows", len(rows2))
	}
	up2 := rows2["Gi1/0/1"]
	if up2.ID != up.ID {
		t.Fatalf("re-poll replaced the row: %s -> %s", up.ID, up2.ID)
	}
	if up2.LastSeen == nil || !up2.LastSeen.After(*firstSeen) {
		t.Fatalf("last_seen = %v, want advanced past %v", up2.LastSeen, firstSeen)
	}
	if up2.FirstSeen != up.FirstSeen {
		t.Fatalf("first_seen = %v, want unchanged %v", up2.FirstSeen, up.FirstSeen)
	}
	if got := len(audit.find(inventory.ActionInterfaceAutoCreate)); got != 3 {
		t.Fatalf("re-poll emitted %d auto_create events, want 3 total", got)
	}
	if got := len(audit.find(inventory.ActionInterfaceRebind)); got != 0 {
		t.Fatalf("re-poll emitted %d rebind events", got)
	}

	// An observation for a device that does not exist rejects the batch with
	// the same reason device-scoped samples use (no partial write).
	unknown := uuid.New()
	must(t, p.rs.stream.Send(&collectorv1.ClientMessage{
		Msg: &collectorv1.ClientMessage_Batch{Batch: &collectorv1.MetricBatch{
			BatchSeq: 9001,
			Interfaces: []*collectorv1.InterfaceObservation{{
				DeviceId: unknown.String(), IfIndex: 1, IfName: "Gi9/0/1",
				ObservedAt: timestamppb.Now(),
			}},
			CreatedAt: timestamppb.Now(),
		}},
	}))
	res := p.rs.result(t)
	if res.GetStatus() != collectorv1.BatchResult_STATUS_REJECTED || res.GetReason() != "validation.device_not_found" {
		t.Fatalf("unknown-device observation = %v (%s), want rejected/validation.device_not_found", res.GetStatus(), res.GetReason())
	}
}

// TestM10S2IfIndexRebindingAudited proves the M9 AC-16 deferred clause: an
// agent renumbering updates the KNOWN row in place (id and identity preserved)
// and emits one interface.rebind audit event with old/new index.
func TestM10S2IfIndexRebindingAudited(t *testing.T) {
	audit := &recordingAudit{}
	env, id, store, orgID := m10s2Env(t, "m10s2-rebind-"+newUUID()[:8], withInventoryAudit(audit))
	orgUUID := mustUUID(t, orgID)
	siteID := siteIDForOrg(t, orgUUID)
	deviceID := createM9S2Device(t, orgUUID, siteID, "m10s2-rebind", "127.0.0.1", "switch", "standard")
	host, port := snmpsimFixture(t)

	creds := poll.NewStaticCredentialSource()
	creds.Set(deviceID.String(), v2cCreds("switch"))
	clock := &itClock{now: time.Now().UTC()}
	prober := poll.NewSNMPProber(poll.SNMPProberConfig{
		Credentials:   creds,
		ClientFactory: snmpsimFactory(port, 2*time.Second, 1),
		Now:           clock.Now,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	p := &m10s2Pipeline{}
	p.engine = poll.NewEngine(poll.Config{
		Prober:   prober,
		Clock:    clock,
		OnSample: func(s poll.Sample) { p.mu.Lock(); p.samples = append(p.samples, s); p.mu.Unlock() },
		OnHealth: func(h poll.Health) { p.mu.Lock(); p.health = append(p.health, h); p.mu.Unlock() },
		OnInterfaces: func(obs []poll.InterfaceObservation) {
			p.mu.Lock()
			p.obs = append(p.obs, obs...)
			p.mu.Unlock()
		},
	})
	p.engine.ApplyTargets([]poll.Target{{
		DeviceID: deviceID.String(), MgmtIP: netip.MustParseAddr(host), Name: "m10s2-rebind",
		Tier: poll.TierStandard, PollType: poll.PollSNMP, Kind: "switch",
	}})
	sp, err := spool.Open(spool.Options{Dir: t.TempDir(), MaxBytes: 8 << 20, FsyncInterval: 10 * time.Millisecond})
	must(t, err)
	t.Cleanup(func() { _ = sp.Close() })
	p.sp = sp
	p.rs = dialBatchStream(t, env, id, store)

	m10s2Step(t, p, clock)
	before := m10LoadInterfaces(t, orgUUID, deviceID)["Gi1/0/1"]
	if before.IfIndex != 1 || before.MAC == nil || *before.MAC != "02:00:00:00:00:01" {
		t.Fatalf("pre-rebind Gi1/0/1 = %+v", before)
	}

	// Same device, same interface identity, renumbered to ifIndex 4.
	creds.Set(deviceID.String(), v2cCreds("srebind"))
	clock.Advance(poll.TierInterval(poll.TierStandard))
	m10s2Step(t, p, clock)

	after := m10LoadInterfaces(t, orgUUID, deviceID)
	if len(after) != 3 {
		t.Fatalf("rebind created duplicates: %d interfaces", len(after))
	}
	row := after["Gi1/0/1"]
	if row.ID != before.ID {
		t.Fatalf("identity not preserved: %s -> %s", before.ID, row.ID)
	}
	if row.IfIndex != 4 {
		t.Fatalf("if_index = %d, want 4 (rebound)", row.IfIndex)
	}
	if row.MAC == nil || *row.MAC != "02:00:00:00:00:01" {
		t.Fatalf("mac = %v, want the identity MAC preserved", row.MAC)
	}
	if row.SpeedBPS == nil || *row.SpeedBPS != 10000000000 {
		t.Fatalf("speed after rebind = %v, want 10000000000 (ifHighSpeed 10000)", row.SpeedBPS)
	}
	if row.MTU == nil || *row.MTU != 9000 {
		t.Fatalf("mtu after rebind = %v, want 9000", row.MTU)
	}

	rebinds := audit.find(inventory.ActionInterfaceRebind)
	if len(rebinds) != 1 {
		t.Fatalf("rebind audit events = %d, want 1 (%+v)", len(rebinds), rebinds)
	}
	ev := rebinds[0]
	if ev.ResourceID != row.ID || ev.ActorType != "collector" || ev.ActorID.String() != id.CollectorID {
		t.Fatalf("rebind event = %+v", ev)
	}
	if ev.Data["old_index"] != 1 || ev.Data["new_index"] != 4 || ev.Data["if_name"] != "Gi1/0/1" {
		t.Fatalf("rebind data = %v, want old=1 new=4 if_name=Gi1/0/1", ev.Data)
	}
	if got := len(audit.find(inventory.ActionInterfaceAutoCreate)); got != 3 {
		t.Fatalf("auto_create events = %d, want only the first-poll 3", got)
	}
}

// TestM10S2InterfaceStatusPayloadAndAuthz covers the status rollup in the API
// payloads (up/down/unknown from the newest observation + freshness), viewer
// reads, cross-tenant/scope 404 parity and the unchanged enumeration
// resistance.
func TestM10S2InterfaceStatusPayloadAndAuthz(t *testing.T) {
	env := newInventoryEnv(t, "m10s2-status-"+newUUID()[:8])
	deviceID := env.createDevice(t, "m10s2-status-dev", nil)
	res := env.do(t, http.MethodPost, "/v1/devices/"+deviceID+"/interfaces",
		`{"if_index":1,"if_name":"Gi1/0/1","oper_status":"up","speed_bps":1000000000,"mtu":1500,"mac":"AA:BB:CC:00:00:01"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("interface create: %d %v", res.Status, res.Body)
	}
	interfaceID, _ := res.Body["id"].(string)
	if res.Body["status"] != "unknown" {
		t.Fatalf("manual interface (never observed) status = %v, want unknown", res.Body["status"])
	}
	if res.Body["freshness_seconds"] != float64(inventory.InterfaceFreshnessSeconds) {
		t.Fatalf("freshness = %v, want %d", res.Body["freshness_seconds"], inventory.InterfaceFreshnessSeconds)
	}

	// A fresh SNMP observation reporting up => up.
	must(t, execOwner(t, `UPDATE interfaces SET last_seen_at = now(), first_seen_at = now() - interval '1 hour' WHERE id = $1`, mustUUID(t, interfaceID)))
	res = env.do(t, http.MethodGet, "/v1/interfaces/"+interfaceID, "")
	if res.Status != http.StatusOK || res.Body["status"] != "up" {
		t.Fatalf("fresh up interface = %d %v", res.Status, res.Body)
	}
	if res.Body["last_seen_at"] == nil {
		t.Fatalf("live fields missing from payload: %v", res.Body)
	}

	// A fresh non-up observation => down.
	res = env.do(t, http.MethodPatch, "/v1/interfaces/"+interfaceID, `{"oper_status":"lower_layer_down"}`)
	if res.Status != http.StatusOK || res.Body["status"] != "down" {
		t.Fatalf("fresh down interface = %d %v", res.Status, res.Body)
	}

	// Stale observation => unknown, even though the last state was down.
	must(t, execOwner(t, `UPDATE interfaces SET last_seen_at = now() - make_interval(secs => $2::double precision) WHERE id = $1`,
		mustUUID(t, interfaceID), inventory.InterfaceFreshnessSeconds+60))
	res = env.do(t, http.MethodGet, "/v1/interfaces/"+interfaceID, "")
	if res.Status != http.StatusOK || res.Body["status"] != "unknown" {
		t.Fatalf("stale interface = %d %v, want unknown", res.Status, res.Body)
	}

	// The device interfaces list carries the same live fields.
	res = env.do(t, http.MethodGet, "/v1/devices/"+deviceID+"/interfaces", "")
	if res.Status != http.StatusOK {
		t.Fatalf("list interfaces: %d", res.Status)
	}
	items := dataList(t, res.Body)
	if len(items) != 1 || items[0]["status"] != "unknown" || items[0]["freshness_seconds"] != float64(inventory.InterfaceFreshnessSeconds) {
		t.Fatalf("list payload = %v", items)
	}

	// Viewer reads keep working (interface.read) and see the rollup.
	_, viewerEmail := seedUserWithRole(t, env, "viewer")
	viewer, _ := loginAs(t, env, viewerEmail)
	res = doRequest(t, viewer, http.MethodGet, env.srv.URL+"/v1/interfaces/"+interfaceID, "", nil)
	if res.Status != http.StatusOK || res.Body["status"] == nil {
		t.Fatalf("viewer read = %d %v", res.Status, res.Body)
	}

	// Scope: a user bound to another site gets the uniform 404 for this
	// interface, and cross-tenant ids are indistinguishable from unknown ones.
	site2 := createSite(t, env.orgID, "S2-"+env.slug)
	adminID, adminEmail := seedUserWithRole(t, env, "admin")
	bindScope(t, env.orgID, adminID, "site", site2)
	scoped, _ := loginAs(t, env, adminEmail)
	res = doRequest(t, scoped, http.MethodGet, env.srv.URL+"/v1/interfaces/"+interfaceID, "", nil)
	if res.Status != http.StatusNotFound || res.Body["code"] != "interface.not_found" {
		t.Fatalf("out-of-scope interface = %d %v, want 404 interface.not_found", res.Status, res.Body)
	}

	other := newInventoryEnv(t, "m10s2-other-"+newUUID()[:8])
	otherDevice := other.createDevice(t, "m10s2-other-dev", nil)
	res = other.do(t, http.MethodPost, "/v1/devices/"+otherDevice+"/interfaces", `{"if_index":1,"if_name":"Gi1/0/1"}`)
	if res.Status != http.StatusCreated {
		t.Fatalf("other interface create: %d", res.Status)
	}
	otherInterface, _ := res.Body["id"].(string)
	res = env.do(t, http.MethodGet, "/v1/interfaces/"+otherInterface, "")
	if res.Status != http.StatusNotFound || res.Body["code"] != "interface.not_found" {
		t.Fatalf("cross-tenant interface = %d %v, want 404 interface.not_found", res.Status, res.Body)
	}
	for _, path := range []string{"/v1/interfaces/not-a-uuid", "/v1/interfaces/" + newUUID()} {
		res = env.do(t, http.MethodGet, path, "")
		if res.Status != http.StatusNotFound || res.Body["code"] != "interface.not_found" {
			t.Fatalf("malformed/unknown interface %s = %d %v", path, res.Status, res.Body)
		}
	}
}

// execOwner runs one owner-pool statement (RLS bypass) for cross-check setup.
func execOwner(t *testing.T, sql string, args ...any) error {
	t.Helper()
	_, err := ownerPool.Exec(context.Background(), sql, args...)
	return err
}
