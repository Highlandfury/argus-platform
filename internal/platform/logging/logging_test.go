package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"WARN":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
	}
	for in, want := range cases {
		got, err := ParseLevel(in)
		if err != nil {
			t.Fatalf("ParseLevel(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseLevel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseLevel("nonsense"); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func TestNewEmitsJSON(t *testing.T) {
	var buf bytes.Buffer
	l, err := New("info", &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Info("hello", "request_id", "abc")
	out := buf.String()
	if !strings.Contains(out, `"msg":"hello"`) || !strings.Contains(out, `"request_id":"abc"`) {
		t.Fatalf("unexpected JSON log output: %s", out)
	}
}

func TestNewRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	l, err := New("warn", &buf)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l.Info("suppressed")
	if buf.Len() != 0 {
		t.Fatalf("info log should be suppressed at warn level: %s", buf.String())
	}
	l.Warn("visible")
	if !strings.Contains(buf.String(), "visible") {
		t.Fatalf("warn log should be visible: %s", buf.String())
	}
}
