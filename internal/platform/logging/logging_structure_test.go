package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
)

// M5c: representative structured events parse as JSON and carry the required
// correlation fields (SPEC §15). Free-form message wording is not asserted.
func TestStructuredLogSchema(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("collector stream connected",
		"component", "argus-server",
		"operation", "stream.connect",
		"request_id", "abc-123",
		"collector_id", "01a0ee0d-ce03-78af-aa2c-dab4f5da97b4",
	)

	var event map[string]any
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatalf("log line is not JSON: %v", err)
	}
	for _, key := range []string{"time", "level", "msg", "component", "operation", "request_id", "collector_id"} {
		if _, ok := event[key]; !ok {
			t.Fatalf("required field %q missing from %v", key, event)
		}
	}
	if event["level"] != "INFO" {
		t.Fatalf("level = %v", event["level"])
	}

	// Error events keep machine-readable codes verbatim.
	buf.Reset()
	logger.Error("collector stream protocol error",
		"component", "argus-server",
		"request_id", "abc-123",
		"error_code", "CODE_PROTOCOL_ERROR",
		"reason", "duplicate hello",
	)
	event = map[string]any{}
	if err := json.Unmarshal(buf.Bytes(), &event); err != nil {
		t.Fatalf("error line is not JSON: %v", err)
	}
	if event["error_code"] != "CODE_PROTOCOL_ERROR" {
		t.Fatalf("error_code = %v", event["error_code"])
	}
}
