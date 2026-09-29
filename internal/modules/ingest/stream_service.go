package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
)

// MetricDef is the authorization/validation view of one policy metric.
type MetricDef struct {
	Key  string
	Unit string
}

// BatchOutcome is the pipeline result for one batch; it maps 1:1 to
// BatchResult.Status. IngestedAt is set only when the batch is durably known
// (OK after COMMIT; DUPLICATE after the ledger check).
type BatchOutcome struct {
	Status     collectorv1.BatchResult_Status
	Reason     string
	Accepted   uint32
	Rejected   uint32
	IngestedAt time.Time
}

// Ingester is the pipeline surface consumed by the collector stream server.
// The interface lives here so the transport can depend on the pipeline without
// owning its internals.
type Ingester interface {
	IngestBatch(ctx context.Context, orgID, collectorID uuid.UUID, allowlist map[string]MetricDef, batch *collectorv1.MetricBatch) BatchOutcome
}

// AllowlistFromPolicy extracts the metric allowlist from a signed policy
// document (the exact JSON bytes served in Policy.document). A document with
// no usable metrics is an error: a collector without a policy must not ingest.
func AllowlistFromPolicy(document []byte) (map[string]MetricDef, error) {
	var doc struct {
		Metrics []struct {
			Key  string `json:"key"`
			Unit string `json:"unit"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(document, &doc); err != nil {
		return nil, fmt.Errorf("ingest: policy document: %w", err)
	}
	if len(doc.Metrics) == 0 {
		return nil, errors.New("ingest: policy document has no metrics")
	}
	out := make(map[string]MetricDef, len(doc.Metrics))
	for _, m := range doc.Metrics {
		if m.Key == "" {
			return nil, errors.New("ingest: policy metric with empty key")
		}
		out[m.Key] = MetricDef{Key: m.Key, Unit: m.Unit}
	}
	return out, nil
}
