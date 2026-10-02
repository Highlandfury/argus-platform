package integration

// M10-S3b-1 follow-up: GET /v1/devices gained an additive `order` parameter
// (asc default, desc = newest first) because the devices list had grown past
// one cursor page and the ascending default buried freshly created devices.
// The UI now requests order=desc; this test pins the server semantics.

import (
	"net/http"
	"testing"
)

func TestInventoryListNewestFirstOrder(t *testing.T) {
	env := newInventoryEnv(t, "inv-order-"+newUUID()[:8])
	for _, name := range []string{"order-a", "order-b", "order-c"} {
		env.createDevice(t, name, map[string]any{"kind": "switch"})
	}

	// Default (ascending) keeps the historical cursor contract: oldest first.
	res := env.do(t, http.MethodGet, "/v1/devices?limit=2", "")
	if res.Status != http.StatusOK {
		t.Fatalf("asc list: status %d body %v", res.Status, res.Body)
	}
	rows := dataList(t, res.Body)
	if len(rows) != 2 || rows[0]["name"] != "order-a" {
		t.Fatalf("asc first page = %v, want order-a first", rows)
	}

	// order=desc returns the newest first and pages backwards with the cursor.
	res = env.do(t, http.MethodGet, "/v1/devices?limit=2&order=desc", "")
	if res.Status != http.StatusOK {
		t.Fatalf("desc list: status %d body %v", res.Status, res.Body)
	}
	rows = dataList(t, res.Body)
	if len(rows) != 2 || rows[0]["name"] != "order-c" || rows[1]["name"] != "order-b" {
		t.Fatalf("desc first page = %v, want order-c then order-b", rows)
	}
	cursor, _ := res.Body["next_cursor"].(string)
	if cursor == "" {
		t.Fatal("desc first page has no next_cursor")
	}
	res = env.do(t, http.MethodGet, "/v1/devices?limit=2&order=desc&cursor="+cursor, "")
	if res.Status != http.StatusOK {
		t.Fatalf("desc second page: status %d body %v", res.Status, res.Body)
	}
	rows = dataList(t, res.Body)
	if len(rows) != 1 || rows[0]["name"] != "order-a" {
		t.Fatalf("desc second page = %v, want order-a", rows)
	}

	// Invalid order values are a deterministic validation problem.
	res = env.do(t, http.MethodGet, "/v1/devices?order=sideways", "")
	requireProblem(t, res, http.StatusBadRequest, "validation.failed")
}
