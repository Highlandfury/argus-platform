// Command gen is the M4-phase load harness (docs/phase-1/PHASE_1_LOAD_TEST.md).
//
// It uses the real control plane end to end: HTTP login -> enrollment tokens ->
// gRPC Enroll (mTLS identity) -> mTLS metric stream with the production batch
// framing. It reports client-side counters and ack-latency percentiles, which
// is exactly what the load-report template needs.
//
// Modes:
//
//	single-stream  one collector, batch 2000, configurable rate (default 20k/s)
//	fleet          N collectors each at samples-per-sec/N with batch-sized bursts
//
// Examples:
//
//	docker compose cp server:/var/lib/argus/ca/root.pem .dev/ca-root.pem
//	go run ./tests/load/gen -mode single-stream -duration 60s -samples-per-sec 20000
//	go run ./tests/load/gen -mode fleet -collectors 50 -samples-per-sec 5000 -duration 60s
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/argus-platform/argus/gen/go/argus/collector/v1"
	"github.com/argus-platform/argus/internal/collector/enrollclient"
)

const metricKey = "collector_cpu_percent"

type config struct {
	mode          string
	api           string
	caFile        string
	org           string
	email         string
	password      string
	namePrefix    string
	collectors    int
	samplesPerS   int
	batchSize     int
	duration      time.Duration
	ackTimeout    time.Duration
	jsonOut       string
	enrollTimeout time.Duration
}

type stats struct {
	mu            sync.Mutex
	latencies     []time.Duration
	ok            atomic.Int64
	duplicate     atomic.Int64
	rejected      atomic.Int64
	retry         atomic.Int64
	transportErrs atomic.Int64
	reconnects    atomic.Int64
	samplesOK     atomic.Int64
	samplesDup    atomic.Int64
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg := config{}
	flag.StringVar(&cfg.mode, "mode", "single-stream", "single-stream|fleet")
	flag.StringVar(&cfg.api, "api", "http://127.0.0.1:8080", "server HTTP API base")
	flag.StringVar(&cfg.caFile, "ca-file", ".dev/ca-root.pem", "pinned server CA PEM (copy it from the server CA dir)")
	flag.StringVar(&cfg.org, "org", "dev", "org slug")
	flag.StringVar(&cfg.email, "email", "admin@dev.local", "admin email")
	flag.StringVar(&cfg.password, "password", os.Getenv("ARGUS_DEV_ADMIN_PASSWORD"), "admin password (or ARGUS_DEV_ADMIN_PASSWORD)")
	flag.StringVar(&cfg.namePrefix, "name-prefix", "loadgen", "collector name prefix")
	flag.IntVar(&cfg.collectors, "collectors", 1, "collector count (fleet mode)")
	flag.IntVar(&cfg.samplesPerS, "samples-per-sec", 20000, "offered samples/s across all collectors")
	flag.IntVar(&cfg.batchSize, "batch", 2000, "samples per batch")
	flag.DurationVar(&cfg.duration, "duration", 60*time.Second, "run duration")
	flag.DurationVar(&cfg.ackTimeout, "ack-timeout", 15*time.Second, "client-side no-ack stream timeout (default matches the historical harness; raise it to measure capacity without abandoning deep queues)")
	flag.StringVar(&cfg.jsonOut, "json", "", "write the summary JSON to this path")
	flag.DurationVar(&cfg.enrollTimeout, "enroll-timeout", 20*time.Second, "per-enrollment timeout")
	flag.Parse()

	if cfg.password == "" {
		cfg.password = "dev-admin-change-me"
	}
	if cfg.mode == "single-stream" {
		cfg.collectors = 1
	}
	if cfg.mode == "fleet" && cfg.collectors < 1 {
		fmt.Fprintln(os.Stderr, "collectors must be >= 1")
		return 2
	}
	if cfg.batchSize < 1 || cfg.batchSize > 5000 {
		fmt.Fprintln(os.Stderr, "batch must be within [1, 5000]")
		return 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	api, err := login(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "login:", err)
		return 1
	}
	siteID, err := api.sites(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sites:", err)
		return 1
	}

	caPEM, err := os.ReadFile(cfg.caFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read CA file:", err)
		return 1
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		fmt.Fprintln(os.Stderr, "CA file contains no certificates")
		return 1
	}

	start := time.Now()
	fmt.Printf("enrolling %d collector(s) (%s mode, batch %d, target %d samples/s, %s)...\n",
		cfg.collectors, cfg.mode, cfg.batchSize, cfg.samplesPerS, cfg.duration)

	identities := make([]enrollclient.Result, cfg.collectors)
	ennErr := parallelBounded(cfg.collectors, 8, func(i int) error {
		token, err := api.createEnrollmentToken(ctx, siteID)
		if err != nil {
			return err
		}
		enrollCtx, cancelEnroll := context.WithTimeout(ctx, cfg.enrollTimeout)
		defer cancelEnroll()
		res, err := enrollclient.Enroll(enrollCtx, enrollclient.Config{
			EnrollURL:    enrollURL(cfg.api),
			CAFile:       cfg.caFile,
			Token:        token,
			Name:         fmt.Sprintf("%s-%04d", cfg.namePrefix, i),
			AgentVersion: "loadgen",
			Hostname:     "loadgen",
			OS:           "loadgen",
			Timeout:      cfg.enrollTimeout,
		})
		// The per-IP enrollment limiter may throttle large fleets; back off and
		// retry rather than failing the run (the limiter itself is by design).
		for attempt := 0; err != nil && strings.Contains(err.Error(), "ResourceExhausted") && attempt < 240; attempt++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
			enrollCtx2, cancel2 := context.WithTimeout(ctx, cfg.enrollTimeout)
			res, err = enrollclient.Enroll(enrollCtx2, enrollclient.Config{
				EnrollURL:    enrollURL(cfg.api),
				CAFile:       cfg.caFile,
				Token:        token,
				Name:         fmt.Sprintf("%s-%04d", cfg.namePrefix, i),
				AgentVersion: "loadgen",
				Hostname:     "loadgen",
				OS:           "loadgen",
				Timeout:      cfg.enrollTimeout,
			})
			cancel2()
		}
		if err != nil {
			return fmt.Errorf("enroll %d: %w", i, err)
		}
		identities[i] = res
		return nil
	})
	if ennErr != nil {
		fmt.Fprintln(os.Stderr, "enrollment:", ennErr)
		return 1
	}
	fmt.Printf("enrolled in %s; streaming...\n", time.Since(start).Round(time.Millisecond))

	agg := &stats{}
	runEnd := start.Add(cfg.duration)
	var wg sync.WaitGroup
	for i := 0; i < cfg.collectors; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runCollector(ctx, cfg, pool, agg, identities[i], i, runEnd)
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	summary := summarize(cfg, agg, elapsed)
	printSummary(summary)
	if cfg.jsonOut != "" {
		raw, _ := json.MarshalIndent(summary, "", "  ")
		if err := os.WriteFile(cfg.jsonOut, raw, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "write json:", err)
			return 1
		}
		fmt.Println("summary written to", cfg.jsonOut)
	}
	if agg.transportErrs.Load() > 0 || agg.rejected.Load() > 0 {
		fmt.Println("RESULT: errors observed (see counters)")
		return 1
	}
	fmt.Println("RESULT: clean run")
	return 0
}

type apiClient struct {
	base   string
	client *http.Client
	csrf   string
}

func login(ctx context.Context, cfg config) (*apiClient, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	api := &apiClient{base: cfg.api, client: &http.Client{Jar: jar, Timeout: 15 * time.Second}}
	body := fmt.Sprintf(`{"org_slug":%q,"email":%q,"password":%q}`, cfg.org, cfg.email, cfg.password)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.api+"/v1/auth/login", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := api.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == "argus_csrf" {
			api.csrf = c.Value
		}
	}
	if api.csrf == "" {
		return nil, fmt.Errorf("no CSRF cookie in login response")
	}
	return api, nil
}

func (a *apiClient) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.base+path, nil)
	if err != nil {
		return err
	}
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", path, res.StatusCode)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

func (a *apiClient) sites(ctx context.Context) (string, error) {
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := a.get(ctx, "/v1/sites?limit=1", &body); err != nil {
		return "", err
	}
	if len(body.Data) == 0 {
		return "", fmt.Errorf("org has no sites")
	}
	return body.Data[0].ID, nil
}

func (a *apiClient) createEnrollmentToken(ctx context.Context, siteID string) (string, error) {
	body := fmt.Sprintf(`{"site_id":%q,"ttl_seconds":3600}`, siteID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/v1/enrollments", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", a.csrf)
	req.Header.Set("Idempotency-Key", fmt.Sprintf("loadgen-%d", rand.Int63())) //nolint:gosec // non-security unique key
	res, err := a.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("create enrollment: status %d", res.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

func parallelBounded(n, workers int, fn func(i int) error) error {
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := fn(i); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	return firstErr
}

// runCollector owns one stream: connect, hello, batch loop with an in-flight
// window, ack accounting, and bounded reconnects.
func runCollector(ctx context.Context, cfg config, pool *x509.CertPool, agg *stats, identity enrollclient.Result, index int, runEnd time.Time) {
	seq := int64(0)
	const maxInflight = 8

	connCert, err := tls.X509KeyPair(identity.CertPEM, identity.KeyPEM)
	if err != nil {
		agg.transportErrs.Add(1)
		fmt.Fprintf(os.Stderr, "collector %d: keypair: %v\n", index, err)
		return
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{connCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	})

	batchEvery := time.Duration(float64(cfg.batchSize) / float64(cfg.samplesPerS) * float64(time.Second))
	if batchEvery <= 0 {
		batchEvery = time.Millisecond
	}

	for attempt := 0; attempt < 4; attempt++ {
		if ctx.Err() != nil || time.Now().After(runEnd) {
			return
		}
		conn, err := grpc.NewClient(streamTarget(cfg.api), grpc.WithTransportCredentials(creds))
		if err != nil {
			agg.transportErrs.Add(1)
			return
		}
		client := collectorv1.NewCollectorServiceClient(conn)
		gstream, err := client.Stream(ctx)
		if err == nil {
			err = gstream.Send(&collectorv1.ClientMessage{
				Msg: &collectorv1.ClientMessage_Hello{Hello: &collectorv1.ClientHello{
					CollectorId:     identity.CollectorID,
					AgentVersion:    "loadgen",
					ProtocolVersion: 1,
				}},
			})
		}
		if err != nil {
			_ = conn.Close()
			agg.transportErrs.Add(1)
			time.Sleep(time.Second)
			continue
		}

		recvCh := make(chan *collectorv1.ServerMessage, 32)
		recvErr := make(chan error, 1)
		go func() {
			for {
				msg, err := gstream.Recv()
				if err != nil {
					recvErr <- err
					return
				}
				recvCh <- msg
			}
		}()
		// First message: ServerHello.
		if msg := <-recvCh; msg.GetHello() == nil {
			agg.transportErrs.Add(1)
			_ = conn.Close()
			continue
		}

		inflight := make(chan struct{}, maxInflight)
		sentAt := &sync.Map{} // batch_seq -> time.Time
		senderDone := make(chan struct{})
		senderFinished := false
		var sentAll atomic.Bool

		go func() {
			defer close(senderDone)
			ticker := time.NewTicker(batchEvery)
			defer ticker.Stop()
			for time.Now().Before(runEnd) {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
				select {
				case <-ctx.Done():
					return
				case inflight <- struct{}{}:
				}
				seq++
				sendTime := time.Now()
				batch := buildBatch(seq, cfg.batchSize, index, sendTime, batchEvery)
				sentAt.Store(seq, time.Now())
				if err := gstream.Send(&collectorv1.ClientMessage{
					Msg: &collectorv1.ClientMessage_Batch{Batch: batch},
				}); err != nil {
					agg.transportErrs.Add(1)
					<-inflight
					return
				}
			}
			sentAll.Store(true)
		}()

	ackLoop:
		for {
			select {
			case msg := <-recvCh:
				br := msg.GetBatchResult()
				if br == nil {
					continue
				}
				<-inflight
				t0, _ := sentAt.LoadAndDelete(br.GetBatchSeq())
				if ts, ok := t0.(time.Time); ok {
					agg.observeLatency(time.Since(ts))
				}
				switch br.GetStatus() {
				case collectorv1.BatchResult_STATUS_OK:
					agg.ok.Add(1)
					agg.samplesOK.Add(int64(br.GetAcceptedSamples()))
				case collectorv1.BatchResult_STATUS_DUPLICATE:
					agg.duplicate.Add(1)
					agg.samplesDup.Add(int64(br.GetAcceptedSamples()))
				case collectorv1.BatchResult_STATUS_REJECTED:
					agg.rejected.Add(1)
					fmt.Fprintf(os.Stderr, "collector %d: batch %d rejected: %s\n", index, br.GetBatchSeq(), br.GetReason())
				case collectorv1.BatchResult_STATUS_RETRY:
					agg.retry.Add(1)
				}
				if senderFinished && len(inflight) == 0 {
					break ackLoop
				}
			case <-recvErr:
				break ackLoop
			case <-senderDone:
				senderDone = nil // disable this case; drain remaining acks below
				senderFinished = true
				if len(inflight) == 0 {
					break ackLoop
				}
			case <-ctx.Done():
				break ackLoop
			case <-time.After(cfg.ackTimeout):
				agg.transportErrs.Add(1)
				break ackLoop
			}
		}

		_ = conn.Close()
		if sentAll.Load() && len(inflight) == 0 {
			return
		}
		agg.reconnects.Add(1)
		time.Sleep(time.Second)
	}
}

// buildBatch builds one batch whose samples carry distinct, batch-window
// timestamps. Distinct ts per sample is required: the sample-level idempotency
// key is (series_id, ts), so reusing one timestamp would legitimately collapse
// the whole batch into a single row (and does not represent real collectors,
// which timestamp each observation).
func buildBatch(seq int64, size, collectorIndex int, sendTime time.Time, span time.Duration) *collectorv1.MetricBatch {
	spacing := span / time.Duration(size)
	if spacing <= 0 {
		spacing = time.Millisecond
	}
	windowStart := sendTime.Add(-span)
	samples := make([]*collectorv1.MetricSample, size)
	phase := float64(collectorIndex) / 3
	for i := 0; i < size; i++ {
		value := 50 + 50*math.Sin(phase+float64(i)/127.0)
		samples[i] = &collectorv1.MetricSample{
			MetricKey:  metricKey,
			Value:      value,
			Unit:       "percent",
			Dimensions: map[string]string{"cpu": "total"},
			Ts:         timestamppb.New(windowStart.Add(spacing * time.Duration(i+1))),
		}
	}
	createdAt := timestamppb.New(sendTime)
	return &collectorv1.MetricBatch{BatchSeq: seq, Samples: samples, CreatedAt: createdAt}
}

func streamTarget(api string) string {
	return hostOnly(api) + ":8443"
}

func enrollURL(api string) string {
	return "https://" + hostOnly(api) + ":8444"
}

func hostOnly(api string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(api, "http://"), "https://")
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

func (s *stats) observeLatency(d time.Duration) {
	s.mu.Lock()
	s.latencies = append(s.latencies, d)
	s.mu.Unlock()
}

type summary struct {
	Mode                string  `json:"mode"`
	Collectors          int     `json:"collectors"`
	DurationSeconds     float64 `json:"duration_seconds"`
	BatchSize           int     `json:"batch_size"`
	OfferedSamplesPerS  float64 `json:"offered_samples_per_sec"`
	AchievedSamplesPerS float64 `json:"achieved_samples_per_sec"`
	BatchesOK           int64   `json:"batches_ok"`
	BatchesDuplicate    int64   `json:"batches_duplicate"`
	BatchesRejected     int64   `json:"batches_rejected"`
	BatchesRetry        int64   `json:"batches_retry"`
	SamplesAccepted     int64   `json:"samples_accepted"`
	SamplesDuplicate    int64   `json:"samples_duplicate"`
	TransportErrors     int64   `json:"transport_errors"`
	Reconnects          int64   `json:"reconnects"`
	AckP50MS            float64 `json:"ack_p50_ms"`
	AckP95MS            float64 `json:"ack_p95_ms"`
	AckP99MS            float64 `json:"ack_p99_ms"`
}

func summarize(cfg config, agg *stats, elapsed time.Duration) summary {
	agg.mu.Lock()
	lats := append([]time.Duration(nil), agg.latencies...)
	agg.mu.Unlock()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	pct := func(p float64) float64 {
		if len(lats) == 0 {
			return 0
		}
		idx := int(p / 100 * float64(len(lats)))
		if idx >= len(lats) {
			idx = len(lats) - 1
		}
		return float64(lats[idx].Microseconds()) / 1000
	}
	secs := elapsed.Seconds()
	return summary{
		Mode:                cfg.mode,
		Collectors:          cfg.collectors,
		DurationSeconds:     math.Round(secs*100) / 100,
		BatchSize:           cfg.batchSize,
		OfferedSamplesPerS:  float64(cfg.samplesPerS),
		AchievedSamplesPerS: math.Round(float64(agg.samplesOK.Load())/secs*100) / 100,
		BatchesOK:           agg.ok.Load(),
		BatchesDuplicate:    agg.duplicate.Load(),
		BatchesRejected:     agg.rejected.Load(),
		BatchesRetry:        agg.retry.Load(),
		SamplesAccepted:     agg.samplesOK.Load(),
		SamplesDuplicate:    agg.samplesDup.Load(),
		TransportErrors:     agg.transportErrs.Load(),
		Reconnects:          agg.reconnects.Load(),
		AckP50MS:            pct(50),
		AckP95MS:            pct(95),
		AckP99MS:            pct(99),
	}
}

func printSummary(s summary) {
	fmt.Println("----- loadgen summary -----")
	fmt.Printf("mode=%s collectors=%d duration=%.1fs batch=%d\n", s.Mode, s.Collectors, s.DurationSeconds, s.BatchSize)
	fmt.Printf("offered=%.0f samples/s achieved=%.0f samples/s\n", s.OfferedSamplesPerS, s.AchievedSamplesPerS)
	fmt.Printf("batches: ok=%d duplicate=%d rejected=%d retry=%d | samples accepted=%d duplicate=%d\n",
		s.BatchesOK, s.BatchesDuplicate, s.BatchesRejected, s.BatchesRetry, s.SamplesAccepted, s.SamplesDuplicate)
	fmt.Printf("ack latency: p50=%.1fms p95=%.1fms p99=%.1fms | transport_errors=%d reconnects=%d\n",
		s.AckP50MS, s.AckP95MS, s.AckP99MS, s.TransportErrors, s.Reconnects)
}
