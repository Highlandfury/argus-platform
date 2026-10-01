// Package metrics owns metric series identity: dimension canonicalization,
// dim_hash computation, series resolution/creation under a per-collector
// quota, and TimescaleDB persistence (SPEC §4.3, §7.1, §12.1).
package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Phase-1 series-identity bounds (SPEC §12.1). These are the last line of
// defense: ingest validation rejects earlier with machine-readable reasons.
const (
	// MaxDimensions is the maximum number of dimension keys per sample.
	MaxDimensions = 8
	// MaxDimensionLen is the maximum length of a dimension key or value.
	MaxDimensionLen = 64
	// MaxSeriesPerCollector is the Phase-1 series quota (cardinality abuse
	// control, S-14/S-15 family).
	MaxSeriesPerCollector = 1000
)

// Series-identity errors.
var (
	ErrTooManyDimensions = errors.New("metrics: too many dimensions")
	ErrDimensionTooLong  = errors.New("metrics: dimension key or value too long")
	ErrDimensionInvalid  = errors.New("metrics: dimension key or value invalid")
	ErrSeriesQuota       = errors.New("metrics: series quota exceeded")
	ErrMixedSeriesScope  = errors.New("metrics: mixed org/collector in one series batch")
)

// CanonicalizeDimensions returns the canonical JSON encoding of the
// dimensions (sorted keys, compact) plus its FNV-1a 64 hash.
//
// Canonicalization rules (documented, test-enforced):
//   - ≤ MaxDimensions keys, each key and value valid UTF-8, non-empty key,
//     ≤ MaxDimensionLen bytes;
//   - keys sorted lexicographically for the JSON encoding (Go's map marshal
//     also sorts, giving byte-stable output);
//   - dim_hash = FNV-1a 64 over the canonical JSON bytes.
func CanonicalizeDimensions(dims map[string]string) (canonical []byte, dimHash int64, err error) {
	if len(dims) > MaxDimensions {
		return nil, 0, fmt.Errorf("%w: %d keys", ErrTooManyDimensions, len(dims))
	}
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	normalized := make(map[string]string, len(dims))
	for _, k := range keys {
		v := dims[k]
		if k == "" || !utf8.ValidString(k) || !utf8.ValidString(v) {
			return nil, 0, fmt.Errorf("%w: key %q", ErrDimensionInvalid, k)
		}
		if len(k) > MaxDimensionLen || len(v) > MaxDimensionLen {
			return nil, 0, fmt.Errorf("%w: key %q", ErrDimensionTooLong, k)
		}
		normalized[k] = v
	}
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, 0, fmt.Errorf("metrics: marshal dimensions: %w", err)
	}
	h := fnv.New64a()
	_, _ = h.Write(raw)
	return raw, int64(h.Sum64()), nil //nolint:gosec // unsigned-to-signed reinterpretation for bigint storage (documented)
}

// SeriesSpec is one logical series to resolve or create. All specs in a batch
// must share the same org and collector (validated).
type SeriesSpec struct {
	OrgID       uuid.UUID
	CollectorID uuid.UUID
	MetricKey   string
	Unit        string
	Canonical   []byte // canonical JSON dimensions
	DimHash     int64
}

// Key returns the map key used to correlate specs with resolved series IDs.
func (s SeriesSpec) Key() string {
	return s.MetricKey + "|" + strconv.FormatInt(s.DimHash, 16)
}

// seriesMapKey builds the correlation key from raw row values.
func seriesMapKey(metricKey string, dimHash int64) string {
	return metricKey + "|" + strconv.FormatInt(dimHash, 16)
}

// ensureSeries resolves or creates series rows in one transaction, enforcing
// the per-collector quota before any insert and surfacing quarantined series
// so ingest can drop samples for those series only. Returns a resolution keyed
// by SeriesSpec.Key().
func ensureSeries(ctx context.Context, tx pgx.Tx, specs []SeriesSpec) (SeriesResolution, error) {
	distinct := make(map[string]SeriesSpec, len(specs))
	for _, sp := range specs {
		distinct[sp.Key()] = sp
	}
	res := NewSeriesResolution()
	if len(distinct) == 0 {
		return res, nil
	}
	orgID, collectorID := specs[0].OrgID, specs[0].CollectorID
	for _, sp := range specs {
		if sp.OrgID != orgID || sp.CollectorID != collectorID {
			return res, ErrMixedSeriesScope
		}
	}

	// Existing series for this collector (≤ quota rows; small working set).
	rows, err := tx.Query(ctx,
		`SELECT metric_key, dim_hash, id, quarantined_at IS NOT NULL FROM metric_series
		 WHERE org_id = $1 AND collector_id = $2 AND device_id IS NULL`, orgID, collectorID)
	if err != nil {
		return res, fmt.Errorf("metrics: list series: %w", err)
	}
	for rows.Next() {
		var (
			metricKey   string
			dimHash     int64
			id          int64
			quarantined bool
		)
		if err := rows.Scan(&metricKey, &dimHash, &id, &quarantined); err != nil {
			rows.Close()
			return res, fmt.Errorf("metrics: scan series: %w", err)
		}
		key := seriesMapKey(metricKey, dimHash)
		if _, wanted := distinct[key]; wanted {
			if quarantined {
				res.Quarantined[key] = true
			} else {
				res.IDs[key] = id
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("metrics: iterate series: %w", err)
	}

	missing := make([]SeriesSpec, 0)
	for key, sp := range distinct {
		if _, ok := res.IDs[key]; !ok {
			if res.Quarantined[key] {
				continue // known quarantined series: never re-created
			}
			missing = append(missing, sp)
		}
	}
	if len(missing) == 0 {
		return res, nil
	}

	// Quota: existing rows + new series must fit the Phase-1 budget.
	var existingTotal int64
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM metric_series WHERE org_id = $1 AND collector_id = $2`, orgID, collectorID).
		Scan(&existingTotal); err != nil {
		return res, fmt.Errorf("metrics: series count: %w", err)
	}
	if existingTotal+int64(len(missing)) > MaxSeriesPerCollector {
		return res, fmt.Errorf("%w: %d existing + %d new > %d", ErrSeriesQuota,
			existingTotal, len(missing), MaxSeriesPerCollector)
	}

	keys := make([]string, len(missing))
	dims := make([][]byte, len(missing))
	hashes := make([]int64, len(missing))
	units := make([]string, len(missing))
	for i, sp := range missing {
		keys[i], dims[i], hashes[i], units[i] = sp.MetricKey, sp.Canonical, sp.DimHash, sp.Unit
	}
	inserted, err := tx.Query(ctx,
		`INSERT INTO metric_series (org_id, collector_id, metric_key, dimensions, dim_hash, unit)
		 SELECT $1, $2, key, dims, hash, unit
		 FROM unnest($3::text[], $4::jsonb[], $5::bigint[], $6::text[]) AS t(key, dims, hash, unit)
		 ON CONFLICT (org_id, collector_id, metric_key, dim_hash) WHERE device_id IS NULL
		 DO NOTHING
		 RETURNING metric_key, dim_hash, id`,
		orgID, collectorID, keys, dims, hashes, units)
	if err != nil {
		return res, fmt.Errorf("metrics: upsert series: %w", err)
	}
	created := 0
	for inserted.Next() {
		var (
			metricKey string
			dimHash   int64
			id        int64
		)
		if err := inserted.Scan(&metricKey, &dimHash, &id); err != nil {
			inserted.Close()
			return res, fmt.Errorf("metrics: scan inserted series: %w", err)
		}
		res.IDs[seriesMapKey(metricKey, dimHash)] = id
		created++
	}
	inserted.Close()
	if err := inserted.Err(); err != nil {
		return res, fmt.Errorf("metrics: iterate inserted series: %w", err)
	}
	seriesCreated.Add(float64(created))

	for key := range distinct {
		if _, ok := res.IDs[key]; !ok {
			return res, fmt.Errorf("metrics: series %s unresolved after upsert", key)
		}
	}
	return res, nil
}
