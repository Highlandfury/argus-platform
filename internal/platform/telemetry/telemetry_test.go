package telemetry

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistryExposesBuildInfo(t *testing.T) {
	reg := New("test", "0.0.1", "abc123")
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var foundBuild, foundGo bool
	for _, f := range families {
		switch f.GetName() {
		case "argus_build_info":
			foundBuild = true
		case "go_goroutines":
			foundGo = true
		}
	}
	if !foundBuild || !foundGo {
		t.Fatalf("missing expected metric families (build=%v go=%v)", foundBuild, foundGo)
	}
}

func TestHandlerServesTextFormat(t *testing.T) {
	reg := New("test", "0.0.1", "abc123")
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "argus_build_info") {
		t.Fatalf("metrics body missing argus_build_info:\n%s", body)
	}
}
