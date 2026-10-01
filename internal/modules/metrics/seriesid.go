package metrics

import (
	"errors"
	"fmt"
	"strings"
)

// Opaque series ids (docs/12 §22.1): the API exposes series as opaque `s_…`
// strings, never as the storage-level bigint. The encoding is base62 over the
// unsigned 63-bit id; it is intentionally opaque (no ordering guarantee) and
// stable for the lifetime of a series.
const (
	seriesIDPrefix  = "s_"
	base62Alphabet  = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	base62Base      = int64(len(base62Alphabet))
	maxSeriesIDBits = 63
)

// ErrInvalidSeriesID is returned for malformed opaque series ids.
var ErrInvalidSeriesID = errors.New("metrics: invalid series id")

// EncodeSeriesID renders a storage series id as the canonical opaque string.
func EncodeSeriesID(id int64) string {
	if id <= 0 {
		return seriesIDPrefix + "0"
	}
	var buf [16]byte
	i := len(buf)
	for id > 0 {
		i--
		buf[i] = base62Alphabet[id%base62Base]
		id /= base62Base
	}
	return seriesIDPrefix + string(buf[i:])
}

// ParseSeriesID decodes an opaque API series id back to the storage id.
func ParseSeriesID(raw string) (int64, error) {
	if !strings.HasPrefix(raw, seriesIDPrefix) {
		return 0, fmt.Errorf("%w: %q (expected the s_… form returned by the API)", ErrInvalidSeriesID, raw)
	}
	body := raw[len(seriesIDPrefix):]
	if body == "" {
		return 0, fmt.Errorf("%w: %q", ErrInvalidSeriesID, raw)
	}
	var id int64
	for i := 0; i < len(body); i++ {
		idx := strings.IndexByte(base62Alphabet, body[i])
		if idx < 0 {
			return 0, fmt.Errorf("%w: %q", ErrInvalidSeriesID, raw)
		}
		if id > (1<<maxSeriesIDBits-1-int64(idx))/base62Base {
			return 0, fmt.Errorf("%w: %q (overflow)", ErrInvalidSeriesID, raw)
		}
		id = id*base62Base + int64(idx)
	}
	if id <= 0 {
		return 0, fmt.Errorf("%w: %q (zero id)", ErrInvalidSeriesID, raw)
	}
	return id, nil
}
