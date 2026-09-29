package api

// Route describes one public API endpoint. The registry is the single source
// of truth for mux construction and for the OpenAPI contract test.
type Route struct {
	Method    string
	Path      string
	Protected bool // requires a valid session
	CSRF      bool // requires CSRF verification (implies Protected)
}

var routeTable = []Route{
	{Method: "POST", Path: "/v1/auth/login"},
	{Method: "POST", Path: "/v1/auth/logout", Protected: true, CSRF: true},
	{Method: "GET", Path: "/v1/me", Protected: true},
	{Method: "GET", Path: "/v1/sites", Protected: true},
	{Method: "POST", Path: "/v1/enrollments", Protected: true, CSRF: true},
	{Method: "GET", Path: "/v1/enrollments", Protected: true},
	{Method: "GET", Path: "/v1/collectors", Protected: true},
	{Method: "GET", Path: "/v1/collectors/{id}", Protected: true},
	{Method: "POST", Path: "/v1/collectors/{id}/revoke", Protected: true, CSRF: true},
	{Method: "POST", Path: "/v1/collectors/{id}/policy:resync", Protected: true, CSRF: true},
	{Method: "GET", Path: "/v1/healthz"},
	{Method: "GET", Path: "/v1/readyz"},
}

// Routes returns a copy of the public API route registry.
func Routes() []Route {
	out := make([]Route, len(routeTable))
	copy(out, routeTable)
	return out
}
