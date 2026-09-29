// Package logging provides the single logging constructor used by all binaries.
// Structured JSON via log/slog; correlation identifiers are attached as fields
// (see docs/phase-1/PHASE_1_SPEC.md §15).
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// ParseLevel maps a configuration string to a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q (want debug|info|warn|error)", s)
	}
}

// New builds a JSON logger writing to w at the configured level.
func New(level string, w io.Writer) (*slog.Logger, error) {
	lv, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})), nil
}
