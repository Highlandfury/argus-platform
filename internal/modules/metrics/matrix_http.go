package metrics

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/platform/authz"
	"github.com/argus-platform/argus/internal/platform/httpx"
)

// ScopeResolver resolves a caller's server-side scope bindings. The inventory
// service implements it; the metrics handler fails closed when it is nil.
type ScopeResolver interface {
	ScopeFor(ctx context.Context, orgID, userID uuid.UUID) (authz.Scope, error)
}

// maxMatrixBodyBytes bounds POST /v1/metrics/query bodies.
const maxMatrixBodyBytes = 1 << 20

// matrixRequest is the POST body (docs/12 §22.8).
type matrixRequest struct {
	Series []json.RawMessage `json:"series"`
	From   string            `json:"from"`
	To     string            `json:"to"`
	Step   string            `json:"step"`
	Agg    string            `json:"agg"`
	Fill   string            `json:"fill"`
}

// parsedMatrix is the validated request shared by POST and GET.
type parsedMatrix struct {
	SeriesIDs []int64
	Selectors []Selector
	From      time.Time
	To        time.Time
	Step      Step
	Agg       Aggregation
	Fill      FillMode
}

// QueryMetrics handles POST /v1/metrics/query (session + device.read enforced
// by the router; scope enforced in the service).
func (h *HTTP) QueryMetrics(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxMatrixBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req matrixRequest
	if err := dec.Decode(&req); err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "request body must be a JSON metrics query")
		return
	}
	parsed, ok := parseMatrixRequest(w, r, req)
	if !ok {
		return
	}
	h.serveMatrix(w, r, p, parsed, false)
}

// QueryMetricsGet handles GET /v1/metrics/query: the URL-encoded convenience
// form with ETag/If-None-Match caching (docs/08 §13.5).
func (h *HTTP) QueryMetricsGet(w http.ResponseWriter, r *http.Request) {
	p, ok := httpx.PrincipalFrom(r.Context())
	if !ok {
		httpx.WriteProblem(w, r, http.StatusUnauthorized, "auth.unauthenticated", "authentication required")
		return
	}
	parsed, ok := parseMatrixGet(w, r)
	if !ok {
		return
	}
	h.serveMatrix(w, r, p, parsed, true)
}

// serveMatrix resolves scope and runs (or serves from cache) one query.
func (h *HTTP) serveMatrix(w http.ResponseWriter, r *http.Request, p httpx.Principal, parsed parsedMatrix, cached bool) {
	if h.Scope == nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return
	}
	sc, err := h.Scope.ScopeFor(r.Context(), p.OrgID, p.UserID)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "authorization scope lookup failed")
		return
	}
	q := MatrixQuery{
		OrgID:     p.OrgID,
		Scope:     sc,
		SeriesIDs: parsed.SeriesIDs,
		Selectors: parsed.Selectors,
		From:      parsed.From,
		To:        parsed.To,
		Step:      parsed.Step,
		Agg:       parsed.Agg,
		Fill:      parsed.Fill,
	}

	key := ""
	if cached {
		key = matrixCacheKey(p.OrgID, sc, q)
		if body, etag, ok := h.Cache.Get(key); ok {
			w.Header().Set("ETag", etag)
			w.Header().Set("Cache-Control", "private, max-age=15")
			if etagMatches(r.Header.Get("If-None-Match"), etag) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(body)
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), QueryTimeout)
	defer cancel()
	result, err := h.Svc.QueryMatrix(ctx, q)
	if err != nil {
		writeMatrixError(w, r, err)
		return
	}
	payload := matrixPayload(result)
	if !cached {
		httpx.WriteJSON(w, http.StatusOK, payload)
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "metric query failed")
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	h.Cache.Put(key, body, etag)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "private, max-age=15")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// parseMatrixRequest validates a POST body.
func parseMatrixRequest(w http.ResponseWriter, r *http.Request, req matrixRequest) (parsedMatrix, bool) {
	var parsed parsedMatrix
	if len(req.Series) == 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", "series is required and must contain at least one series id or selector")
		return parsedMatrix{}, false
	}
	for i, entry := range req.Series {
		trimmed := strings.TrimSpace(string(entry))
		if strings.HasPrefix(trimmed, `"`) {
			var raw string
			if err := json.Unmarshal(entry, &raw); err != nil {
				httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
					fmt.Sprintf("series[%d] must be a series id string or a selector object", i))
				return parsedMatrix{}, false
			}
			id, err := ParseSeriesID(raw)
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
					"invalid series id",
					httpx.FieldError{Field: fmt.Sprintf("series[%d]", i), Code: "invalid", Message: err.Error()})
				return parsedMatrix{}, false
			}
			parsed.SeriesIDs = append(parsed.SeriesIDs, id)
			continue
		}
		sel, err := decodeSelector(entry)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
				"invalid selector",
				httpx.FieldError{Field: fmt.Sprintf("series[%d]", i), Code: "invalid", Message: err.Error()})
			return parsedMatrix{}, false
		}
		parsed.Selectors = append(parsed.Selectors, sel)
	}

	from, err := time.Parse(time.RFC3339, req.From)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"invalid time range",
			httpx.FieldError{Field: "from", Code: "required", Message: "from is required and must be RFC3339"})
		return parsedMatrix{}, false
	}
	to, err := time.Parse(time.RFC3339, req.To)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"invalid time range",
			httpx.FieldError{Field: "to", Code: "required", Message: "to is required and must be RFC3339"})
		return parsedMatrix{}, false
	}
	parsed.From, parsed.To = from.UTC(), to.UTC()

	step, err := ParseStep(req.Step)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", err.Error())
		return parsedMatrix{}, false
	}
	parsed.Step = step
	agg, err := ParseAggregation(req.Agg)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "query.agg_unsupported", cleanMatrixDetail(err))
		return parsedMatrix{}, false
	}
	parsed.Agg = agg
	fill, err := ParseFill(req.Fill)
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", cleanMatrixDetail(err))
		return parsedMatrix{}, false
	}
	parsed.Fill = fill
	return parsed, true
}

// selectorRequest is the selector object form in `series`.
type selectorRequest struct {
	DeviceID   string         `json:"device_id"`
	MetricKey  string         `json:"metric_key"`
	Dimensions map[string]any `json:"dimensions"`
}

func decodeSelector(raw json.RawMessage) (Selector, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return Selector{}, errors.New("must be a series id string or a selector object")
	}
	for field := range obj {
		switch field {
		case "device_id", "metric_key", "dimensions":
		default:
			return Selector{}, fmt.Errorf("unknown selector field %q", field)
		}
	}
	var req selectorRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return Selector{}, errors.New("selector fields must be valid JSON")
	}
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		return Selector{}, errors.New("selector device_id is required and must be a UUID")
	}
	if strings.TrimSpace(req.MetricKey) == "" || len(req.MetricKey) > 200 {
		return Selector{}, errors.New("selector metric_key is required (max 200 chars)")
	}
	dims := map[string]string{}
	for k, v := range req.Dimensions {
		s, ok := v.(string)
		if !ok {
			return Selector{}, fmt.Errorf("selector dimension %q must be a string", k)
		}
		dims[k] = s
	}
	if _, _, err := CanonicalizeDimensions(dims); err != nil {
		return Selector{}, fmt.Errorf("invalid selector dimensions: %w", err)
	}
	return Selector{DeviceID: deviceID, MetricKey: req.MetricKey, Dimensions: dims}, nil
}

// parseMatrixGet validates the compact URL form: repeated/comma-separated
// `series` ids plus at most one `device_id`/`metric`/`dimensions` selector.
// Dimensions use the compact `k=v,k2=v2` form (values cannot contain commas).
func parseMatrixGet(w http.ResponseWriter, r *http.Request) (parsedMatrix, bool) {
	query := r.URL.Query()
	var parsed parsedMatrix
	for _, raw := range query["series"] {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			id, err := ParseSeriesID(part)
			if err != nil {
				httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
					"invalid series id",
					httpx.FieldError{Field: "series", Code: "invalid", Message: err.Error()})
				return parsedMatrix{}, false
			}
			parsed.SeriesIDs = append(parsed.SeriesIDs, id)
		}
	}
	deviceRaw, metricRaw := query.Get("device_id"), query.Get("metric")
	dimsRaw := query.Get("dimensions")
	if deviceRaw != "" || metricRaw != "" || dimsRaw != "" {
		deviceID, err := uuid.Parse(deviceRaw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
				"invalid selector",
				httpx.FieldError{Field: "device_id", Code: "required", Message: "device_id is required with metric and must be a UUID"})
			return parsedMatrix{}, false
		}
		if strings.TrimSpace(metricRaw) == "" || len(metricRaw) > 200 {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
				"invalid selector",
				httpx.FieldError{Field: "metric", Code: "required", Message: "metric is required with device_id (max 200 chars)"})
			return parsedMatrix{}, false
		}
		dims, err := parseCompactDimensions(dimsRaw)
		if err != nil {
			httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
				"invalid dimensions",
				httpx.FieldError{Field: "dimensions", Code: "invalid", Message: err.Error()})
			return parsedMatrix{}, false
		}
		parsed.Selectors = append(parsed.Selectors, Selector{DeviceID: deviceID, MetricKey: metricRaw, Dimensions: dims})
	}
	if len(parsed.SeriesIDs) == 0 && len(parsed.Selectors) == 0 {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"at least one series id or a device_id+metric selector is required")
		return parsedMatrix{}, false
	}

	from, err := time.Parse(time.RFC3339, query.Get("from"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"invalid time range",
			httpx.FieldError{Field: "from", Code: "required", Message: "from is required and must be RFC3339"})
		return parsedMatrix{}, false
	}
	to, err := time.Parse(time.RFC3339, query.Get("to"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed",
			"invalid time range",
			httpx.FieldError{Field: "to", Code: "required", Message: "to is required and must be RFC3339"})
		return parsedMatrix{}, false
	}
	parsed.From, parsed.To = from.UTC(), to.UTC()

	step, err := ParseStep(query.Get("step"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", err.Error())
		return parsedMatrix{}, false
	}
	parsed.Step = step
	agg, err := ParseAggregation(query.Get("agg"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "query.agg_unsupported", cleanMatrixDetail(err))
		return parsedMatrix{}, false
	}
	parsed.Agg = agg
	fill, err := ParseFill(query.Get("fill"))
	if err != nil {
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", cleanMatrixDetail(err))
		return parsedMatrix{}, false
	}
	parsed.Fill = fill
	return parsed, true
}

// parseCompactDimensions parses `k=v,k2=v2`; an empty value is allowed.
func parseCompactDimensions(raw string) (map[string]string, error) {
	dims := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return dims, nil
	}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("dimension %q must use the key=value form", pair)
		}
		dims[pair[:eq]] = pair[eq+1:]
	}
	if _, _, err := CanonicalizeDimensions(dims); err != nil {
		return nil, err
	}
	return dims, nil
}

// writeMatrixError maps service errors onto the canonical problem set.
func writeMatrixError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrSeriesNotFound):
		// Uniform for missing, foreign and out-of-scope ids (no oracle).
		httpx.WriteProblem(w, r, http.StatusNotFound, "series.not_found", "one or more series were not found")
	case errors.Is(err, ErrPointsExceeded):
		httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "query.points_exceeded",
			"query exceeds the supported scan budget; use a coarser step or a smaller range")
	case errors.Is(err, ErrAggUnsupported):
		httpx.WriteProblem(w, r, http.StatusUnprocessableEntity, "query.agg_unsupported", cleanMatrixDetail(err))
	case errors.Is(err, ErrQueryInvalid), errors.Is(err, ErrRangeInvalid):
		httpx.WriteProblem(w, r, http.StatusBadRequest, "validation.failed", cleanMatrixDetail(err))
	case errors.Is(err, context.DeadlineExceeded):
		httpx.WriteProblem(w, r, http.StatusGatewayTimeout, "query.timeout", "query timed out")
	case errors.Is(err, context.Canceled):
		// Client went away; nothing useful to write.
	default:
		httpx.WriteProblem(w, r, http.StatusInternalServerError, "internal.error", "metric query failed")
	}
}

func cleanMatrixDetail(err error) string {
	msg := err.Error()
	for _, prefix := range []string{
		"metrics: invalid query: ",
		"metrics: invalid time range: ",
		"metrics: unsupported aggregation: ",
	} {
		msg = strings.TrimPrefix(msg, prefix)
	}
	return msg
}

// matrixPayload renders the canonical matrix response (docs/12 §22.8).
func matrixPayload(res MatrixResult) map[string]any {
	series := make([]map[string]any, 0, len(res.Series))
	for _, s := range res.Series {
		points := make([][2]any, 0, len(s.Points))
		for _, p := range s.Points {
			var v any
			if p.Value != nil {
				v = *p.Value
			}
			points = append(points, [2]any{p.Ts.Unix(), v})
		}
		labels := make(map[string]any, len(s.Dimensions)+3)
		for k, v := range s.Dimensions {
			labels[k] = v
		}
		labels["metric"] = s.MetricKey
		labels["unit"] = s.Unit
		if s.DeviceName != nil {
			if _, exists := labels["device"]; !exists {
				labels["device"] = *s.DeviceName
			}
		}
		item := map[string]any{
			"id":           EncodeSeriesID(s.ID),
			"device_id":    uuidStringOrNil(s.DeviceID),
			"collector_id": uuidStringOrNil(s.CollectorID),
			"metric_key":   s.MetricKey,
			"unit":         s.Unit,
			"dimensions":   s.Dimensions,
			"labels":       labels,
			"points":       points,
			"truncated":    s.Truncated,
		}
		series = append(series, item)
	}
	meta := map[string]any{
		"resolution":       ResolutionName(res.Step),
		"partial":          res.Partial,
		"points_truncated": res.PointsTruncated,
		"series_total":     res.SeriesTotal,
		"series_returned":  res.SeriesReturned,
		"raw_fallback":     res.RawFallback,
		"rollup_missing":   res.RollupMissing,
		"expected_points":  res.ExpectedPoints,
		"returned_points":  res.ReturnedPoints,
		"quality": map[string]any{
			"gaps":            res.Gaps,
			"dropped_samples": 0,
		},
	}
	if res.ResolutionWarning != "" {
		meta["resolution_warning"] = res.ResolutionWarning
	}
	return map[string]any{
		"from":   res.From.Format(time.RFC3339),
		"to":     res.To.Format(time.RFC3339),
		"step":   string(res.Step),
		"agg":    string(res.Agg),
		"fill":   string(res.Fill),
		"series": series,
		"meta":   meta,
	}
}

func uuidStringOrNil(id *uuid.UUID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

// matrixCacheKey fingerprints the compiled query plus the tenant and the
// caller's resolved scope so cached bodies are never shared across principals
// that can see different data.
func matrixCacheKey(orgID uuid.UUID, sc authz.Scope, q MatrixQuery) string {
	var b strings.Builder
	b.WriteString(orgID.String())
	b.WriteByte('|')
	if sc.Unrestricted {
		b.WriteString("u")
	} else {
		b.WriteString("s:")
		for _, s := range sortedUUIDs(sc.Sites) {
			b.WriteString(s.String())
			b.WriteByte(',')
		}
		b.WriteString("g:")
		for _, g := range sortedUUIDs(sc.DeviceGroups) {
			b.WriteString(g.String())
			b.WriteByte(',')
		}
	}
	b.WriteByte('|')
	ids := append([]int64(nil), q.SeriesIDs...)
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		b.WriteString(EncodeSeriesID(id))
		b.WriteByte(',')
	}
	sels := append([]Selector(nil), q.Selectors...)
	sort.Slice(sels, func(i, j int) bool {
		if sels[i].DeviceID != sels[j].DeviceID {
			return sels[i].DeviceID.String() < sels[j].DeviceID.String()
		}
		return sels[i].MetricKey < sels[j].MetricKey
	})
	for _, sel := range sels {
		b.WriteString(sel.DeviceID.String())
		b.WriteByte('/')
		b.WriteString(sel.MetricKey)
		b.WriteByte('/')
		b.WriteString(canonicalDimsJSON(sel.Dimensions))
		b.WriteByte(',')
	}
	fmt.Fprintf(&b, "|%d|%d|%s|%s|%s", q.From.UnixNano(), q.To.UnixNano(), q.Step, q.Agg, q.Fill)
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

func sortedUUIDs(ids []uuid.UUID) []uuid.UUID {
	out := append([]uuid.UUID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// etagMatches implements If-None-Match semantics for one or a list of tags.
func etagMatches(header, etag string) bool {
	if header == "" {
		return false
	}
	if strings.TrimSpace(header) == "*" {
		return true
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		part = strings.TrimPrefix(part, "W/")
		if part == etag {
			return true
		}
	}
	return false
}
