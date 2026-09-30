// Command query measures metric-query API latency (M4c Â§12): it logs in and
// runs N iterations of each query shape against one collector, reporting
// p50/p95/max and error counts. It is a baseline tool, not a scalability
// claim: results depend on dataset size and the host.
//
// Usage:
//
//	go run ./tests/load/query -api http://127.0.0.1:8080 \
//	  -collector dev-collector -iterations 40
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"time"
)

type shape struct {
	name   string
	window time.Duration
	step   string
}

var shapes = []shape{
	{"latest-1m", time.Minute, "raw"},
	{"15m-raw", 15 * time.Minute, "raw"},
	{"1h-10s", time.Hour, "10s"},
	{"6h-1m", 6 * time.Hour, "1m"},
	{"24h-5m", 24 * time.Hour, "5m"},
	{"24h-1m", 24 * time.Hour, "1m"},
}

func main() {
	api := flag.String("api", "http://127.0.0.1:8080", "server API base")
	org := flag.String("org", "dev", "org slug")
	email := flag.String("email", "admin@dev.local", "admin email")
	password := flag.String("password", os.Getenv("ARGUS_DEV_ADMIN_PASSWORD"), "admin password")
	collectorName := flag.String("collector", "dev-collector", "collector name to query")
	iterations := flag.Int("iterations", 40, "iterations per query shape")
	flag.Parse()
	if *password == "" {
		*password = "dev-admin-change-me"
	}

	jar, err := cookiejar.New(nil)
	check(err)
	client := &http.Client{Jar: jar, Timeout: 30 * time.Second}
	ctx := context.Background()

	login, _ := json.Marshal(map[string]string{"org_slug": *org, "email": *email, "password": *password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *api+"/v1/auth/login", bytes.NewReader(login))
	check(err)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	check(err)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fatalf("login: status %d", res.StatusCode)
	}

	collectorID, err := resolveCollector(ctx, client, *api, *collectorName)
	check(err)
	fmt.Printf("collector=%s id=%s iterations=%d\n", *collectorName, collectorID, *iterations)

	for _, s := range shapes {
		latencies := make([]time.Duration, 0, *iterations)
		errors := 0
		var lastPoints int
		for i := 0; i < *iterations; i++ {
			to := time.Now().UTC()
			from := to.Add(-s.window)
			u := fmt.Sprintf("%s/v1/collectors/%s/metrics?metric=collector_cpu_percent&from=%s&to=%s&step=%s",
				*api, collectorID,
				url.QueryEscape(from.Format(time.RFC3339)),
				url.QueryEscape(to.Format(time.RFC3339)),
				s.step)
			start := time.Now()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				fatalf("request: %v", err)
			}
			res, err := client.Do(req)
			elapsed := time.Since(start)
			if err != nil {
				errors++
				continue
			}
			if res.StatusCode != http.StatusOK {
				errors++
				_ = res.Body.Close()
				continue
			}
			var body struct {
				Meta struct {
					ReturnedPoints int `json:"returned_points"`
				} `json:"meta"`
			}
			_ = json.NewDecoder(res.Body).Decode(&body)
			_ = res.Body.Close()
			lastPoints = body.Meta.ReturnedPoints
			latencies = append(latencies, elapsed)
		}
		fmt.Printf("%-10s step=%-4s n=%d errors=%d points=%d p50=%s p95=%s max=%s\n",
			s.name, s.step, len(latencies), errors, lastPoints,
			pct(latencies, 50), pct(latencies, 95), pct(latencies, 100))
	}
}

func resolveCollector(ctx context.Context, client *http.Client, api, name string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api+"/v1/collectors?limit=100", nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	var body struct {
		Data []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}
	for _, c := range body.Data {
		if c.Name == name {
			return c.ID, nil
		}
	}
	return "", fmt.Errorf("collector %q not found", name)
}

func pct(latencies []time.Duration, p int) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), latencies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := p * len(sorted) / 100
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func check(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
