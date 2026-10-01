package poll

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"
)

// SNMPProberConfig wires the SNMP prober.
type SNMPProberConfig struct {
	// Credentials resolves per-device material (M9-S3 seam). Required.
	Credentials CredentialSource
	// ClientFactory builds one read-only client per probe. Defaults to
	// NewGosnmpClient; tests inject fakes.
	ClientFactory ClientFactory
	// Templates is the validated pack set. Defaults to the embedded core pack.
	Templates *SNMPTemplateSet
	// Client carries the per-profile RPC tunables (zero values = canonical
	// 2 s / 2 retries / max-repetitions 25).
	Client ClientConfig
	// Logger receives the canonical v2c warning posture.
	Logger *slog.Logger
	// Now is the injectable time source for sample timestamps and counter
	// interval math (defaults to time.Now). The scheduler's Clock drives
	// cadence; this keeps counter math deterministic under tests.
	Now func() time.Time
}

// snmpDeviceState is the collector-side counter state, per device (S4 adds
// persistence and rate budgets; S2 keeps it in memory like scheduler state).
type snmpDeviceState struct {
	sysUpRaw  uint64
	sysUpSeen bool
	rows      map[string]*snmpRowState
}

type snmpRowState struct {
	counters map[string]*counterState
}

// SNMPProber executes one SNMP poll: system group GET, table walks per
// selected template pack, counter normalization and drift/truncation
// classification (P2-AC-15/16/20). No SET is ever issued: it only sees the
// read-only SNMPClient surface.
type SNMPProber struct {
	cfg       SNMPProberConfig
	templates *SNMPTemplateSet
	log       *snmpLogger

	mu      sync.Mutex
	devices map[string]*snmpDeviceState
}

// NewSNMPProber builds the production prober.
func NewSNMPProber(cfg SNMPProberConfig) *SNMPProber {
	if cfg.ClientFactory == nil {
		cfg.ClientFactory = NewGosnmpClient
	}
	if cfg.Templates == nil {
		// The embedded core pack parses at build time; a parse failure here
		// means the binary's own data is broken, so panic is correct (tests
		// and any cmd wiring fail loudly instead of silently polling nothing).
		set, err := CoreTemplateSet()
		if err != nil {
			panic(fmt.Sprintf("poll: embedded core SNMP templates invalid: %v", err))
		}
		cfg.Templates = set
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &SNMPProber{
		cfg:       cfg,
		templates: cfg.Templates,
		log:       newSNMPLogger(cfg.Logger),
		devices:   make(map[string]*snmpDeviceState),
	}
}

// TargetRemoved implements TargetRemovedHook: counter state for a device whose
// last SNMP target disappeared from the policy is dropped.
func (p *SNMPProber) TargetRemoved(deviceID, pollType string) {
	if pollType != "" && NormalizePollType(pollType) != PollSNMP {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.devices, deviceID)
}

// Probe implements Prober.
func (p *SNMPProber) Probe(ctx context.Context, target Target) Result {
	start := time.Now()
	res := Result{PollType: PollSNMP}
	finish := func() Result {
		res.Latency = time.Since(start)
		return res
	}
	// Cancellation is checked before dialing; in-flight RPCs are bounded by
	// the canonical per-RPC timeout/retry budget (docs/07 §12.3).
	if err := ctx.Err(); err != nil {
		res.ErrorClass = ErrorUnreachable
		return finish()
	}

	creds, ok := p.cfg.Credentials.Lookup(target.DeviceID)
	if !ok {
		res.ErrorClass = ErrorCredentialMissing
		if p.log != nil && p.log.log != nil {
			p.log.log.Warn("no SNMP credentials for target (M9-S3 materializes them)",
				"device_id", target.DeviceID)
		}
		return finish()
	}
	if err := creds.Validate(); err != nil {
		res.ErrorClass = ErrorCredentialInvalid
		if p.log != nil && p.log.log != nil {
			p.log.log.Error("invalid SNMP credentials", "device_id", target.DeviceID, "error", err)
		}
		return finish()
	}
	if creds.UsesWarningPosture() {
		p.log.warnV2c(target.DeviceID)
	}

	packs := p.templates.Select(target.Kind)
	client, err := p.cfg.ClientFactory(target.MgmtIP, creds, p.cfg.Client)
	if err != nil {
		res.ErrorClass = classifySNMPErrorClass(err)
		return finish()
	}
	defer func() {
		if cerr := client.Close(); cerr != nil && p.log != nil && p.log.log != nil {
			p.log.log.Debug("snmp client close", "device_id", target.DeviceID, "error", cerr)
		}
	}()

	ts := p.cfg.Now().UTC()
	var firstErr error
	setErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// 1. System scalars (one GET) — also the reboot signal.
	scalarCols := make([]SNMPColumn, 0)
	seenOID := make(map[string]bool)
	for _, pack := range packs {
		for _, col := range pack.Scalars {
			if seenOID[col.OID] {
				continue
			}
			seenOID[col.OID] = true
			scalarCols = append(scalarCols, col)
		}
	}
	scalars := make(map[string]SNMPVarBind, len(scalarCols))
	if len(scalarCols) > 0 {
		oids := make([]string, 0, len(scalarCols))
		for _, col := range scalarCols {
			oids = append(oids, col.OID)
		}
		binds, gerr := client.Get(oids)
		if gerr != nil {
			setErr(gerr)
		} else {
			for _, b := range binds {
				scalars[b.OID] = b
			}
		}
	}

	// Reboot detection from sysUpTime: a drop over half the 2^32 timeticks
	// space is a reboot; all counter baselines reseed (no false spike).
	if upCol, ok := findSysUptimeColumn(packs); ok {
		if b, ok := scalars[upCol.OID]; ok {
			p.observeUptime(target.DeviceID, b.Uint)
		}
	}

	// Emit numeric scalars.
	for _, col := range scalarCols {
		if !col.Emits() {
			continue
		}
		b, ok := scalars[col.OID]
		if !ok {
			continue
		}
		if v, ok := b.Numeric(); ok {
			res.SnmpSamples = append(res.SnmpSamples, Sample{
				MetricKey: col.Key,
				Unit:      col.Unit,
				Value:     v * col.EffectiveScale(),
				Ts:        ts,
				DeviceID:  target.DeviceID,
			})
			res.SnmpMetricsSeen++
		}
	}

	// 2. Table walks, merged per pack by row index.
	walked := make(map[string]map[string]map[string]SNMPVarBind)
	perPackSeen := make(map[string]int)
	for _, pack := range packs {
		packRows := make(map[string]map[string]SNMPVarBind)
		for _, tbl := range pack.Tables {
			rows, ok := walked[tbl.Walk]
			if !ok {
				binds, werr := client.Walk(tbl.Walk)
				if werr != nil {
					setErr(werr)
					walked[tbl.Walk] = nil
					continue
				}
				rows = make(map[string]map[string]SNMPVarBind)
				for _, b := range binds {
					idx := oidIndex(b.OID)
					if idx == "" {
						continue
					}
					if rows[idx] == nil {
						rows[idx] = make(map[string]SNMPVarBind)
					}
					rows[idx][b.OID] = b
				}
				walked[tbl.Walk] = rows
			}
			mergeRowMaps(packRows, rows)
		}
		seen := p.applyPackRows(target, pack, packRows, ts, &res)
		perPackSeen[pack.Name] = seen
		res.SnmpMetricsExpect += len(templateEmittingColumns(pack))
	}

	if firstErr != nil {
		res.ErrorClass = classifySNMPErrorClass(firstErr)
		return finish()
	}
	res.SnmpDone = true
	if pack := driftedPack(packs, perPackSeen); pack != "" {
		res.ErrorClass = ErrorTemplateDrift
		if p.log != nil && p.log.log != nil {
			p.log.log.Warn("SNMP template drift: required pack produced no metrics",
				"device_id", target.DeviceID, "pack", pack)
		}
	}
	return finish()
}

// observeUptime updates the device uptime baseline and reseeds every counter
// when sysUpTime decreased since the previous poll. Any decrease is treated as
// a reboot: a 497-day TimeTicks wrap also reseeds once (one skipped counter
// sample), which is strictly safer than emitting a post-wrap spike, and the
// two cases are indistinguishable within a poll interval without persistent
// boot history (canonical docs/07 §12.3 reboot detection).
func (p *SNMPProber) observeUptime(deviceID string, raw uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.deviceStateLocked(deviceID)
	if st.sysUpSeen && raw < st.sysUpRaw {
		for _, row := range st.rows {
			for _, cs := range row.counters {
				cs.Reseed()
			}
		}
	}
	st.sysUpRaw = raw
	st.sysUpSeen = true
}

// applyPackRows joins one pack's walked rows, resolves identity dimensions,
// feeds the counter state machine and renders samples. Returns the number of
// emitting columns that produced at least one value.
func (p *SNMPProber) applyPackRows(target Target, pack SNMPTemplate, rows map[string]map[string]SNMPVarBind, ts time.Time, res *Result) int {
	cols := templateEmittingColumns(pack)
	if len(cols) == 0 {
		return 0
	}
	seen := make(map[string]bool)

	indexes := make([]string, 0, len(rows))
	for idx := range rows {
		indexes = append(indexes, idx)
	}
	sort.Strings(indexes)

	for _, idx := range indexes {
		row := rows[idx]
		baseDims, ok := resolveIdentity(pack, row, idx)
		if !ok {
			continue // identity-less row: no reliable series identity
		}
		rowKey := dimsKey(baseDims)
		if len(pack.Identity) == 0 {
			rowKey = "idx=" + idx
		}
		p.mu.Lock()
		st := p.deviceStateLocked(target.DeviceID)
		rs := st.rows[rowKey]
		if rs == nil {
			rs = &snmpRowState{counters: make(map[string]*counterState)}
			st.rows[rowKey] = rs
		}
		p.mu.Unlock()

		for _, col := range cols {
			b, ok := row[col.OID+"."+idx]
			if !ok {
				continue
			}
			dims := baseDims
			if col.Dim != "" {
				dims = map[string]string{col.Dim: idx}
			}
			switch col.Type {
			case SNMPMetricGauge, SNMPMetricState:
				v, ok := b.Numeric()
				if !ok {
					continue
				}
				res.SnmpSamples = append(res.SnmpSamples, Sample{
					MetricKey: col.Key, Unit: col.Unit,
					Value: v * col.EffectiveScale(), Ts: ts, DeviceID: target.DeviceID,
					Dimensions: copyDims(dims),
				})
				seen[col.Key] = true
			case SNMPMetricCounter:
				value, width, ok := counterValue(b, col.Width)
				if !ok {
					continue
				}
				cs := rs.counters[col.Key]
				if cs == nil {
					cs = newCounterState(CounterConfig{Width: width, MaxRate: col.MaxRate})
					rs.counters[col.Key] = cs
				}
				out := cs.Update(value, ts, rowDiscontinuity(pack, row, idx))
				if out.Emitted {
					res.SnmpSamples = append(res.SnmpSamples, Sample{
						MetricKey: col.Key, Unit: col.Unit,
						Value: out.Rate, Ts: ts, DeviceID: target.DeviceID,
						Dimensions: copyDims(dims),
					})
					seen[col.Key] = true
				}
			}
		}
	}
	return len(seen)
}

// driftedPack implements the canonical "expected vs seen metrics ratio" for
// required packs (docs/07 §12.7): the device answered but a required pack
// produced none of its emitting metrics (wrong OIDs / firmware drift).
func driftedPack(packs []SNMPTemplate, perPackSeen map[string]int) string {
	for _, pack := range packs {
		if !pack.Required {
			continue
		}
		if len(templateEmittingColumns(pack)) == 0 {
			continue
		}
		if perPackSeen[pack.Name] == 0 {
			return pack.Name
		}
	}
	return ""
}

func findSysUptimeColumn(packs []SNMPTemplate) (SNMPColumn, bool) {
	for _, pack := range packs {
		for _, col := range pack.Scalars {
			if col.Role == SNMPRoleSysUptime {
				return col, true
			}
		}
	}
	return SNMPColumn{}, false
}

func templateEmittingColumns(pack SNMPTemplate) []SNMPColumn {
	var out []SNMPColumn
	for _, col := range pack.Columns {
		if col.Emits() {
			out = append(out, col)
		}
	}
	return out
}

func (p *SNMPProber) deviceStateLocked(deviceID string) *snmpDeviceState {
	st := p.devices[deviceID]
	if st == nil {
		st = &snmpDeviceState{rows: make(map[string]*snmpRowState)}
		p.devices[deviceID] = st
	}
	return st
}

// resolveIdentity picks the first non-empty value of each identity chain and
// reports whether at least one dimension resolved. Rows with no usable
// identity are skipped: ifIndex is never used as identity (docs/07 §12.3).
func resolveIdentity(pack SNMPTemplate, row map[string]SNMPVarBind, idx string) (map[string]string, bool) {
	if len(pack.Identity) == 0 {
		return map[string]string{}, true
	}
	dims := make(map[string]string, len(pack.Identity))
	for _, id := range pack.Identity {
		for _, oid := range id.OIDs {
			if b, ok := row[oid+"."+idx]; ok && b.Str != "" {
				dims[id.Dim] = b.Str
				break
			}
		}
	}
	return dims, len(dims) > 0
}

// rowDiscontinuity returns the ifCounterDiscontinuityTime for a row (nil when
// the pack/agent does not expose it).
func rowDiscontinuity(pack SNMPTemplate, row map[string]SNMPVarBind, idx string) *uint64 {
	for _, col := range pack.Columns {
		if col.Role != SNMPRoleDiscontinuity {
			continue
		}
		b, ok := row[col.OID+"."+idx]
		if !ok {
			continue
		}
		switch b.Kind {
		case ValueUnsigned, ValueCounter64:
			v := b.Uint
			return &v
		case ValueInteger:
			v := uint64(b.Int) // #nosec G115 -- TimeTicks are non-negative
			return &v
		}
	}
	return nil
}

// counterValue extracts the counter value and width. The wire type wins when
// present (an agent answering Counter32 where the template expects Counter64
// must not be scaled as 64-bit); the template width is the fallback.
func counterValue(b SNMPVarBind, templateWidth int) (uint64, int, bool) {
	switch b.Kind {
	case ValueUnsigned:
		return b.Uint, CounterWidth32, true
	case ValueCounter64:
		return b.Uint, CounterWidth64, true
	case ValueInteger:
		if b.Int < 0 {
			return 0, 0, false
		}
		// #nosec G115 -- checked non-negative above.
		return uint64(b.Int), templateWidth, true
	default:
		return 0, 0, false
	}
}

// mergeRowMaps merges src rows into dst (dst wins on conflicts).
func mergeRowMaps(dst, src map[string]map[string]SNMPVarBind) {
	for idx, row := range src {
		if dst[idx] == nil {
			dst[idx] = make(map[string]SNMPVarBind, len(row))
		}
		for oid, b := range row {
			if _, exists := dst[idx][oid]; !exists {
				dst[idx][oid] = b
			}
		}
	}
}

// oidIndex returns the final sub-identifier of a dotted OID (the single-level
// table row index used by the core pack).
func oidIndex(oid string) string {
	i := strings.LastIndex(oid, ".")
	if i < 0 {
		return ""
	}
	return oid[i+1:]
}

func dimsKey(dims map[string]string) string {
	if len(dims) == 0 {
		return ""
	}
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('\x1f')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(dims[k])
	}
	return b.String()
}

func copyDims(dims map[string]string) map[string]string {
	if len(dims) == 0 {
		return nil
	}
	out := make(map[string]string, len(dims))
	for k, v := range dims {
		out[k] = v
	}
	return out
}
