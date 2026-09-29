package metrics

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/httpx"
)

// queryTimeout bounds every metric query server-side (cancellation via context
// propagates to PostgreSQL; a canceled client or slow query is terminated).
const queryTimeout = 5 * time.Second

// HTTP exposes the metric query API.
type HTTP struct {
	Svc *QueryService
}

// QueryCollectorMetric handles GET /v1/collectors/{id}/metrics.
func (h *HTTP) QueryCollectorMetric(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	collectorID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
		return
	}

	query := r.URL.Query()
	metricKey := query.Get("metric")
	if !KnownMetricKeys[metricKey] {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"metric is required and must be a supported metric key")
		return
	}
	from, err := time.Parse(time.RFC3339, query.Get("from"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"from is required and must be RFC3339")
		return
	}
	to, err := time.Parse(time.RFC3339, query.Get("to"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"to is required and must be RFC3339")
		return
	}
	step, err := ParseStep(query.Get("step"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), queryTimeout)
	defer cancel()
	result, err := h.Svc.QueryRange(ctx, RangeQuery{
		OrgID:       p.OrgID,
		CollectorID: collectorID,
		MetricKey:   metricKey,
		From:        from.UTC(),
		To:          to.UTC(),
		Step:        step,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrUnknownCollector):
			httpx.WriteProblem(w, r, http.StatusNotFound, "collector.not_found", "collector not found")
		case errors.Is(err, ErrPointsExceeded):
			httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "query.points_exceeded",
				"query would exceed the 2000-point limit; use a coarser step or a smaller range")
		case errors.Is(err, ErrRangeInvalid):
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", cleanDetail(err))
		case errors.Is(err, context.DeadlineExceeded):
			httpx.WriteProblem(w, r, http.StatusGatewayTimeout, "query.timeout", "query timed out")
		case errors.Is(err, context.Canceled):
			// Client went away; nothing useful to write.
			return
		default:
			// Never leak internal database errors.
			httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "metric query failed")
		}
		return
	}

	payload := map[string]any{
		"metric":     result.Metric,
		"unit":       result.Unit,
		"resolution": result.Resolution,
		"from":       result.From.Format(time.RFC3339),
		"to":         result.To.Format(time.RFC3339),
		"points":     pointsPayload(result.Points),
		"status":     result.Status,
		"meta": map[string]any{
			"expected_points": result.Expected,
			"returned_points": result.Returned,
			"gaps":            result.Gaps,
			"truncated":       false,
			"sample_count":    result.SampleCount,
		},
	}
	if result.Latest != nil {
		payload["latest"] = map[string]any{
			"ts":          result.Latest.Ts.Format(time.RFC3339),
			"value":       result.Latest.Value,
			"age_seconds": result.Latest.AgeSeconds,
			"status":      result.Latest.Status,
		}
	}
	httpx.WriteJSON(w, http.StatusOK, payload)
}

// pointsPayload renders [unix_seconds, value] pairs per the OpenAPI contract.
func pointsPayload(points []Point) [][2]any {
	out := make([][2]any, 0, len(points))
	for _, p := range points {
		out = append(out, [2]any{p.Ts.Unix(), p.Value})
	}
	return out
}

// cleanDetail strips internal error wrapping from our own validation errors.
func cleanDetail(err error) string {
	msg := err.Error()
	for _, prefix := range []string{
		"metrics: invalid time range: ",
		"metrics: query exceeds the point limit: ",
		"metrics: collector not found: ",
	} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}
