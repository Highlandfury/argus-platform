package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/argus-platform/argus/internal/collector"
	"github.com/argus-platform/argus/internal/collector/enrollclient"
	"github.com/argus-platform/argus/internal/collector/identity"
	"github.com/argus-platform/argus/internal/collector/metrics"
	"github.com/argus-platform/argus/internal/collector/policy"
	"github.com/argus-platform/argus/internal/collector/poll"
	"github.com/argus-platform/argus/internal/collector/spool"
	"github.com/argus-platform/argus/internal/collector/stream"
	ctel "github.com/argus-platform/argus/internal/collector/telemetry"
	"github.com/argus-platform/argus/internal/collector/transport"
	"github.com/argus-platform/argus/internal/platform/buildinfo"
	"github.com/argus-platform/argus/internal/platform/config"
	"github.com/argus-platform/argus/internal/platform/logging"
)

// runtimePolicy carries the applied-policy knobs the producer/batcher consult
// on every cycle (policy updates take effect without a restart).
type runtimePolicy struct {
	mu             sync.Mutex
	reportInterval time.Duration
	metricInterval time.Duration
	batchMax       int
}

func newRuntimePolicy() *runtimePolicy {
	return &runtimePolicy{
		reportInterval: 5 * time.Second,
		metricInterval: 5 * time.Second,
		batchMax:       5000,
	}
}

func (p *runtimePolicy) set(doc policy.Document) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if doc.ReportIntervalSeconds > 0 {
		p.reportInterval = time.Duration(doc.ReportIntervalSeconds) * time.Second
	}
	if len(doc.Metrics) > 0 && doc.Metrics[0].IntervalSeconds > 0 {
		p.metricInterval = time.Duration(doc.Metrics[0].IntervalSeconds) * time.Second
	}
	if doc.BatchMaxSamples > 0 {
		p.batchMax = doc.BatchMaxSamples
	}
}

func (p *runtimePolicy) report() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.reportInterval
}

func (p *runtimePolicy) metric() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.metricInterval
}

func (p *runtimePolicy) max() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.batchMax
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, logger, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "data dir:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Startup ordering (SPEC §3.5): identity → spool recovery → transport →
	// producer (never write before recovery completes).
	machine := collector.NewMachine(collector.StateNew, logger)
	idStore := identity.NewStore(cfg.DataDir)
	id, enrolled, err := idStore.Load()
	if err != nil {
		logger.Error("identity load failed", "error", err)
		_ = machine.Transition(collector.StateFailed)
		return 1
	}
	if !enrolled {
		token := loadEnrollToken(cfg)
		if token == "" {
			logger.Warn("no identity and no enrollment token; running idle until provisioned")
			<-ctx.Done()
			return 0
		}
		if err := machine.Transition(collector.StateEnrolling); err != nil {
			logger.Error("state", "error", err)
			return 1
		}
		id, err = enrollWithRetry(ctx, cfg, idStore, token, machine, logger)
		if err != nil {
			logger.Error("enrollment failed", "error", err)
			_ = machine.Transition(collector.StateFailed)
			return 1
		}
		logger.Info("enrolled", "collector_id", id.CollectorID, "cert_not_after", id.CertNotAfter)
	} else {
		logger.Info("identity loaded",
			"collector_id", id.CollectorID,
			"cert_not_after", id.CertNotAfter,
			"policy_version", id.PolicyVersion)
	}

	sp, err := spool.Open(spool.Options{
		Dir:           filepath.Join(cfg.DataDir, "spool"),
		MaxBytes:      cfg.SpoolMaxBytes,
		FsyncInterval: time.Duration(cfg.FsyncIntervalMS) * time.Millisecond,
		Log:           logger,
	})
	if err != nil {
		logger.Error("spool open failed", "error", err)
		_ = machine.Transition(collector.StateFailed)
		return 1
	}
	defer func() {
		if err := sp.Close(); err != nil {
			logger.Error("spool close", "error", err)
		}
	}()
	spoolStats := sp.Stats()
	logger.Info("spool ready",
		"records", spoolStats.Records,
		"bytes", spoolStats.Bytes,
		"acked_seq", spoolStats.AckedSeq,
		"highest_seq", spoolStats.HighestSeq)

	// Collector self-observability (SPEC §15): loopback-only endpoint. A start
	// failure disables the endpoint but never the telemetry transport.
	cmet := ctel.New(sp)
	if err := cmet.Start(cfg.MetricsAddr, logger); err != nil {
		logger.Warn("collector metrics endpoint disabled", "addr", cfg.MetricsAddr, "error", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := cmet.Shutdown(shutdownCtx); err != nil {
			logger.Warn("collector metrics shutdown", "error", err)
		}
	}()

	keyDER, err := base64.StdEncoding.DecodeString(id.PolicyKeyDERB64)
	if err != nil || len(keyDER) == 0 {
		logger.Error("identity is missing the pinned policy signing key")
		return 1
	}
	corrBuf := make([]byte, 8)
	_, _ = rand.Read(corrBuf)
	corrID := hex.EncodeToString(corrBuf)
	logger.Info("collector correlation established",
		"correlation_id", corrID, "collector_id", id.CollectorID)
	certPath, keyPath, _, _ := idStore.Paths()
	policyDir := filepath.Join(cfg.DataDir, "policy")

	rp := newRuntimePolicy()
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun() // idempotent; the explicit shutdown call below still runs first
	sampleCh := make(chan metrics.Sample, 256)
	healthCh := make(chan poll.Health, 256)

	// Poll engine (M9-S1/S2): ICMP + SNMP probers behind one multi-prober and
	// the deterministic tier scheduler. Samples flow through the existing
	// producer channel/batcher/spool; poll health is batched into the same
	// spool so both ride the batch ack/claim path (no new transport).
	healthBatcher := poll.NewHealthBatcher(rp.max, rp.report, func(records []poll.Health) error {
		_, err := sp.Append(&spool.Batch{At: time.Now().UTC(), Health: toSpoolHealth(records)})
		return err
	}, logger)
	bundleCreds := poll.NewBundleCredentialSource(logger)
	snmpProber := poll.NewSNMPProber(poll.SNMPProberConfig{
		// M9-S3 materialized credentials first; the M9-S2 fixture/env source
		// (dev-only) is the fallback so fixture runs keep working.
		Credentials: poll.NewChainCredentialSource(bundleCreds, snmpCredentials(cfg)),
		Logger:      logger,
	})
	pollEngine := poll.NewEngine(poll.Config{
		Prober: poll.NewMultiProber(map[string]poll.Prober{
			poll.PollICMP: poll.NewICMPProber(poll.ICMPConfig{}),
			poll.PollSNMP: snmpProber,
		}).WithLogger(logger),
		Log: logger,
		OnSample: func(s poll.Sample) {
			select {
			case sampleCh <- metrics.Sample{
				MetricKey:  s.MetricKey,
				Unit:       s.Unit,
				Value:      s.Value,
				Ts:         s.Ts,
				Dimensions: s.Dimensions,
				DeviceID:   s.DeviceID,
			}:
			case <-runCtx.Done():
			}
		},
		OnHealth: func(h poll.Health) {
			select {
			case healthCh <- h:
			case <-runCtx.Done():
			}
		},
	})
	if doc, err := policy.LoadAndValidate(policyDir, id.PolicyVersion); err == nil {
		rp.set(doc)
		pollEngine.ApplyTargets(pollTargets(doc, logger))
	} else {
		logger.Warn("policy cache not usable yet; using defaults until the first apply", "error", err)
	}

	sender := transport.NewSender(sp, filepath.Join(cfg.DataDir, "spool", "deadletter"), logger)
	sender.SetSendDurationObserver(cmet.ObserveSendDuration)
	// A fresh enrollment has already moved the machine to RECONNECTING (inside
	// enrollWithRetry); only transitions from other states are needed here.
	if machine.State() != collector.StateReconnecting {
		if err := machine.Transition(collector.StateReconnecting); err != nil {
			logger.Error("state", "error", err)
			return 1
		}
	}
	client := stream.New(stream.Config{
		StreamAddr:     cfg.StreamAddr,
		CAFile:         cfg.CAFile,
		CertFile:       certPath,
		KeyFile:        keyPath,
		CollectorID:    id.CollectorID,
		AgentVersion:   buildinfo.Version,
		PolicyDir:      policyDir,
		Log:            logger,
		AppliedVersion: id.PolicyVersion,
		PolicyKeyDER:   keyDER,
		CorrelationID:  corrID,
		Telemetry:      sender,
		Stats: func() stream.TelemetryStats {
			// Single state source: the same SpoolSnapshot the metrics endpoint
			// reads, so heartbeat and /metrics can never diverge.
			snap := cmet.SpoolSnapshot()
			return stream.TelemetryStats{
				SpoolBytes:          uint64(snap.Bytes),   //nolint:gosec // non-negative by construction
				SpoolRecords:        uint64(snap.Records), //nolint:gosec // non-negative by construction
				HighestSeq:          snap.HighestSeq,
				AckedSeq:            snap.AckedSeq,
				DroppedRecordsTotal: uint64(snap.DroppedTotal), //nolint:gosec // non-negative by construction
				CorruptRecordsTotal: uint64(snap.CorruptTotal), //nolint:gosec // non-negative by construction
			}
		},
		OnStreamState: func(connected bool, backoff time.Duration) {
			cmet.SetStreamConnected(connected)
			cmet.SetBackoff(backoff)
		},
		OnClockSkew: cmet.SetClockSkew,
		Credentials: bundleCreds,
		OnPolicyApplied: func(version int64) {
			if err := idStore.UpdatePolicyVersion(id, version); err != nil {
				logger.Error("persist policy version", "error", err)
			}
			if doc, err := policy.LoadAndValidate(policyDir, version); err == nil {
				rp.set(doc)
				// Targets are applied atomically with the policy: one engine
				// swap, no partial target state.
				pollEngine.ApplyTargets(pollTargets(doc, logger))
				logger.Info("producer policy updated",
					"version", version,
					"report_interval_s", doc.ReportIntervalSeconds,
					"batch_max_samples", doc.BatchMaxSamples,
					"poll_targets", len(doc.Targets))
			}
		},
	}, machine)

	// Producer → batcher → spool pipeline (bounded channel provides
	// backpressure: a full spool parks the producer instead of growing memory).
	var wg sync.WaitGroup
	batcher := metrics.NewBatcher(
		rp.max,
		rp.report,
		func(samples []metrics.Sample) error {
			_, err := sp.Append(&spool.Batch{At: time.Now().UTC(), Samples: toSpoolSamples(samples)})
			return err
		},
		logger,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case s := <-sampleCh:
				if err := batcher.Add(s); err != nil {
					logger.Warn("batcher add", "error", err)
				}
			case <-ticker.C:
				if err := batcher.Tick(); err != nil {
					logger.Warn("batcher flush", "error", err)
				}
			}
		}
	}()
	producer := metrics.NewProducer(
		metrics.NewCPUSource(),
		rp.metric,
		func(s metrics.Sample) {
			// Mirror the produced sample into the collector's own metrics
			// (same measurement; single canonical source).
			cmet.SetCPUPercent(s.Value)
			select {
			case sampleCh <- s:
			case <-runCtx.Done():
			}
		},
		logger,
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		producer.Run(runCtx)
	}()
	logger.Info("producer started",
		"metric", "collector_cpu_percent",
		"interval_s", rp.metric().Seconds(),
		"report_interval_s", rp.report().Seconds())

	// Poll engine + health batcher run alongside the producer; both stop via
	// runCtx and everything buffered is flushed below.
	wg.Add(1)
	go func() {
		defer wg.Done()
		pollEngine.Run(runCtx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case h := <-healthCh:
				if err := healthBatcher.Add(h); err != nil {
					logger.Warn("health batcher add", "error", err)
				}
			case <-ticker.C:
				if err := healthBatcher.Tick(); err != nil {
					logger.Warn("health batcher flush", "error", err)
				}
			}
		}
	}()
	logger.Info("poll engine started", "tier_default", poll.StandardInterval.String())

	runErr := client.Run(ctx)

	// Shutdown ordering (SPEC §3.5): producer stops → buffered samples flush →
	// spool fsync. Any unflushed sample here can only be caused by a spool
	// error, which is logged loudly (never silent).
	cancelRun()
	wg.Wait()
	for {
		select {
		case s := <-sampleCh:
			_ = batcher.Add(s)
			continue
		default:
		}
		break
	}
	for {
		select {
		case h := <-healthCh:
			_ = healthBatcher.Add(h)
			continue
		default:
		}
		break
	}
	if err := batcher.Flush(); err != nil {
		logger.Error("final flush failed; samples could not be spooled", "error", err)
	}
	if err := healthBatcher.Flush(); err != nil {
		logger.Error("final health flush failed; poll health could not be spooled", "error", err)
	}
	if err := sp.ForceSync(); err != nil {
		logger.Error("final spool sync failed", "error", err)
	}
	finalStats := sp.Stats()
	logger.Info("collector stopped",
		"state", machine.State(),
		"spool_records", finalStats.Records,
		"spool_bytes", finalStats.Bytes,
		"acked_seq", finalStats.AckedSeq,
		"highest_seq", finalStats.HighestSeq,
		"dropped", finalStats.DroppedRecordsTotal,
		"corrupt", finalStats.CorruptRecordsTotal,
		"sender", senderStats(sender))

	if runErr != nil {
		logger.Error("stream terminated", "error", runErr)
		_ = machine.Transition(collector.StateFailed)
		return 1
	}
	return 0
}

func senderStats(sender *transport.Sender) string {
	st := sender.Stats()
	return fmt.Sprintf("sent=%d ok=%d dup=%d rejected=%d retried=%d",
		st.BatchesSent, st.BatchesOK, st.BatchesDuplicate, st.BatchesRejected, st.BatchesRetried)
}

func toSpoolSamples(in []metrics.Sample) []spool.Sample {
	out := make([]spool.Sample, len(in))
	for i, s := range in {
		out[i] = spool.Sample{
			MetricKey:  s.MetricKey,
			Unit:       s.Unit,
			Value:      s.Value,
			Ts:         s.Ts,
			DeviceID:   s.DeviceID,
			Dimensions: s.Dimensions,
		}
	}
	return out
}

func toSpoolHealth(in []poll.Health) []spool.Health {
	out := make([]spool.Health, len(in))
	for i, h := range in {
		out[i] = spool.Health{
			DeviceID:            h.DeviceID,
			PollType:            h.PollType,
			LatencyMS:           h.LatencyMS,
			Outcome:             h.Outcome,
			ErrorClass:          h.ErrorClass,
			ConsecutiveFailures: h.ConsecutiveFailures,
			CheckedAt:           h.CheckedAt,
		}
	}
	return out
}

// pollTargets converts signed-policy targets into engine targets. The policy
// validator already guarantees the shape; a malformed entry (impossible unless
// the validator regressed) is dropped with a loud log rather than disabling
// every other target.
func pollTargets(doc policy.Document, logger *slog.Logger) []poll.Target {
	out := make([]poll.Target, 0, len(doc.Targets))
	for _, t := range doc.Targets {
		target, err := poll.TargetFromPolicy(poll.TargetSpec{
			DeviceID: t.DeviceID,
			MgmtIP:   t.MgmtIP,
			Name:     t.Name,
			Tier:     t.Tier,
			PollType: t.PollType,
			Kind:     t.Kind,
		})
		if err != nil {
			logger.Error("policy target dropped", "device_id", t.DeviceID, "error", err)
			continue
		}
		out = append(out, target)
	}
	return out
}

// snmpCredentials builds the M9-S2 fixture credential source from collector
// config; since M9-S3 it is the fallback behind the RAM-only materialized
// bundle source (ChainCredentialSource). v3 authPriv takes precedence over v2c
// (canonical preference order). With no fixture configured every SNMP target
// without materialized credentials reports credential_missing.
func snmpCredentials(cfg config.Collector) poll.CredentialSource {
	src := poll.NewStaticCredentialSource()
	if user := strings.TrimSpace(cfg.SNMPFixtureV3User); user != "" {
		src.SetDefault(poll.SNMPCredentials{
			Version:      poll.SNMPVersionV3,
			Context:      strings.TrimSpace(cfg.SNMPFixtureV3Context),
			Username:     user,
			AuthProtocol: cfg.SNMPFixtureV3AuthProto,
			AuthKey:      cfg.SNMPFixtureV3AuthKey,
			PrivProtocol: cfg.SNMPFixtureV3PrivProto,
			PrivKey:      cfg.SNMPFixtureV3PrivKey,
		})
		return src
	}
	if community := strings.TrimSpace(cfg.SNMPFixtureCommunity); community != "" {
		src.SetDefault(poll.SNMPCredentials{
			Version:   poll.SNMPVersionV2c,
			Community: community,
		})
	}
	return src
}

func cmdEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	tokenFlag := fs.String("token", "", "enrollment token (defaults to ARGUS_ENROLL_TOKEN / token file)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, logger, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		fmt.Fprintln(os.Stderr, "data dir:", err)
		return 1
	}
	machine := collector.NewMachine(collector.StateNew, logger)
	idStore := identity.NewStore(cfg.DataDir)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, enrolled, _ := idStore.Load(); enrolled {
		fmt.Fprintln(os.Stderr, "already enrolled; remove", cfg.DataDir, "to re-enroll (operator flow)")
		return 1
	}
	token := *tokenFlag
	if token == "" {
		token = loadEnrollToken(cfg)
	}
	if token == "" {
		fmt.Fprintln(os.Stderr, "no enrollment token (use -token, ARGUS_ENROLL_TOKEN, or the token file)")
		return 1
	}
	if err := machine.Transition(collector.StateEnrolling); err != nil {
		return 1
	}
	id, err := enrollWithRetry(ctx, cfg, idStore, token, machine, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "enrollment failed:", err)
		return 1
	}
	fmt.Printf("enrolled collector %s (cert expires %s)\n", id.CollectorID, id.CertNotAfter.Format(time.RFC3339))
	return 0
}

func loadConfig() (config.Collector, *slog.Logger, error) {
	cfg, err := config.LoadCollector()
	if err != nil {
		return cfg, nil, fmt.Errorf("config: %w", err)
	}
	logger, err := logging.New(cfg.LogLevel, os.Stdout)
	if err != nil {
		return cfg, nil, fmt.Errorf("logger: %w", err)
	}
	return cfg, logger, nil
}

func loadEnrollToken(cfg config.Collector) string {
	if token := strings.TrimSpace(os.Getenv("ARGUS_ENROLL_TOKEN")); token != "" {
		return token
	}
	if cfg.EnrollTokenFile == "" {
		return ""
	}
	raw, err := os.ReadFile(cfg.EnrollTokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// enrollWithRetry retries transient failures; invalid/expired/used tokens and
// name collisions are terminal and surfaced with distinct messages.
func enrollWithRetry(ctx context.Context, cfg config.Collector, store *identity.Store, token string, machine *collector.Machine, logger *slog.Logger) (identity.Identity, error) {
	backoff := 2 * time.Second
	for attempt := 1; ; attempt++ {
		hostname, _ := os.Hostname()
		res, err := enrollclient.Enroll(ctx, enrollclient.Config{
			EnrollURL:    cfg.EnrollURL,
			CAFile:       cfg.CAFile,
			Token:        token,
			Name:         cfg.Name,
			AgentVersion: buildinfo.Version,
			Hostname:     hostname,
			OS:           "linux",
			Timeout:      20 * time.Second,
		})
		if err == nil {
			id := identity.Identity{
				CollectorID:     res.CollectorID,
				Name:            cfg.Name,
				ServerEnrollURL: cfg.EnrollURL,
				StreamAddr:      cfg.StreamAddr,
				AgentVersion:    buildinfo.Version,
				CertNotAfter:    res.CertNotAfter,
				EnrolledAt:      time.Now().UTC(),
				PolicyVersion:   res.PolicyVersion,
				PolicyKeyDERB64: base64.StdEncoding.EncodeToString(res.PolicyKeyDER),
			}
			if err := store.Save(id, res.CertPEM, res.KeyPEM, res.CAPEM); err != nil {
				return identity.Identity{}, err
			}
			if err := machine.Transition(collector.StateReconnecting); err != nil {
				return identity.Identity{}, err
			}
			return id, nil
		}
		switch status.Code(err) {
		case codes.PermissionDenied:
			return identity.Identity{}, fmt.Errorf("token was rejected (invalid, expired, or already used): %w", err)
		case codes.InvalidArgument, codes.AlreadyExists:
			return identity.Identity{}, err
		}
		if ctx.Err() != nil {
			return identity.Identity{}, ctx.Err()
		}
		if attempt >= 30 {
			return identity.Identity{}, fmt.Errorf("giving up after %d attempts: %w", attempt, err)
		}
		logger.Warn("enrollment attempt failed; retrying", "attempt", attempt, "backoff", backoff, "error", err)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return identity.Identity{}, ctx.Err()
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func dialTCP(addr string) (net.Conn, error) {
	return net.DialTimeout("tcp", addr, 3*time.Second)
}
