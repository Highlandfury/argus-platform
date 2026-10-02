package notify

// M11-S2 adapter unit tests: local httptest receivers for the webhook (HMAC
// signature + replay window + 2xx/timeout paths), Slack and Teams payload
// shapes, and a local SMTP sink exercising the stdlib adapter end to end.

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/argus-platform/argus/internal/modules/alerts"
)

func testMessage(t *testing.T) Message {
	t.Helper()
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	msg := Message{
		DeliveryID:  uuid.New(),
		EventKind:   alerts.EventActivated,
		EventType:   EventFired,
		AlertID:     uuid.New(),
		OrgID:       uuid.New(),
		DeviceID:    uuid.New(),
		SiteID:      uuid.New(),
		Fingerprint: strings.Repeat("a", 64),
		Severity:    SeverityCritical,
		Summary:     "CPU high — value 95 gt 90",
		RuleName:    "CPU high",
		DeviceName:  "sw-1",
		SiteName:    "HQ",
		OccurredAt:  now,
		StartedAt:   now.Add(-time.Minute),
		EvidenceURL: "https://argus.example/alerts/abc",
		AckURL:      "https://argus.example/alerts/abc#ack",
		Subject:     "[CRITICAL] CPU high — value 95 gt 90",
		DedupKey:    strings.Repeat("b", 64),
		SentAt:      now,
	}
	msg.Body = renderText(msg)
	msg.Payload = renderPayload(msg)
	return msg
}

// --- signature / replay window ---------------------------------------------

func TestSignMatchesCanonicalHMAC(t *testing.T) {
	secret, ts, body := "s2-signing-"+uuid.NewString(), "1759400000", []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got := Sign(secret, ts, body); got != want {
		t.Fatalf("Sign = %q, want %q", got, want)
	}
	if strings.HasPrefix(want, "v1=") {
		t.Fatal("Sign digest must not carry the v1= prefix")
	}
}

func TestVerifySignatureAndReplayWindow(t *testing.T) {
	secret := "s2-signing-" + uuid.NewString()
	body := []byte(`{"spec_version":"1"}`)
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	ts := fmt.Sprintf("%d", now.Unix())
	sig := "v1=" + Sign(secret, ts, body)

	if err := VerifySignature(secret, ts, sig, body, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifySignature(secret, ts, sig, append(body, ' '), now); err == nil {
		t.Fatal("tampered body accepted")
	}
	if err := VerifySignature("other-secret", ts, sig, body, now); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if err := VerifySignature(secret, ts, "sha256=deadbeef", body, now); err == nil {
		t.Fatal("non-v1 scheme accepted")
	}
	if err := VerifySignature(secret, "not-a-number", sig, body, now); err == nil {
		t.Fatal("non-numeric timestamp accepted")
	}
	if err := VerifySignature(secret, ts, sig, body, now.Add(ReplayWindow+time.Second)); err == nil {
		t.Fatal("stale timestamp accepted past the replay window")
	}
	future := fmt.Sprintf("%d", now.Add(ReplayWindow+time.Second).Unix())
	if err := VerifySignature(secret, future, "v1="+Sign(secret, future, body), body, now); err == nil {
		t.Fatal("future timestamp accepted past the replay window")
	}
	if err := VerifySignature(secret, ts, sig, body, now.Add(ReplayWindow-time.Second)); err != nil {
		t.Fatalf("timestamp inside the window rejected: %v", err)
	}
}

// --- webhook ----------------------------------------------------------------

type capturedRequest struct {
	Method  string
	Header  http.Header
	Body    []byte
	At      time.Time
	Handled chan struct{}
}

func capture() (*capturedRequest, http.HandlerFunc) {
	c := &capturedRequest{Handled: make(chan struct{})}
	return c, func(w http.ResponseWriter, r *http.Request) {
		defer close(c.Handled)
		raw, _ := io.ReadAll(r.Body)
		c.Method, c.Header, c.Body, c.At = r.Method, r.Header.Clone(), raw, time.Now()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("accepted"))
	}
}

func TestWebhookTransportSignsAndVerifies(t *testing.T) {
	capt, handler := capture()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	secret := "s2-signing-" + uuid.NewString()
	msg := testMessage(t)
	cfg, _ := json.Marshal(WebhookConfig{URL: srv.URL, Payload: PayloadSummary})
	ch := Channel{ID: uuid.New(), Kind: KindWebhook, Name: "hook", Enabled: true, Config: cfg}
	secretJSON, _ := json.Marshal(SigningSecret{SigningSecret: secret})

	code, ex, err := DefaultHTTPTransport().Send(context.Background(), ch, secretJSON, msg)
	if err != nil {
		t.Fatalf("Send: %v (code=%d excerpt=%q)", err, code, ex)
	}
	if code != http.StatusOK || ex != "accepted" {
		t.Fatalf("Send = %d %q, want 200 accepted", code, ex)
	}
	select {
	case <-capt.Handled:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not handle the request")
	}
	if capt.Method != http.MethodPost {
		t.Fatalf("method = %s, want POST", capt.Method)
	}
	if got := capt.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := capt.Header.Get("X-Argus-Event"); got != EventFired {
		t.Fatalf("X-Argus-Event = %q, want %q", got, EventFired)
	}
	if got := capt.Header.Get("X-Argus-Delivery"); got != msg.DeliveryID.String() {
		t.Fatalf("X-Argus-Delivery = %q, want %q", got, msg.DeliveryID)
	}
	if got := capt.Header.Get("X-Argus-Dedup-Key"); got != msg.DedupKey {
		t.Fatalf("X-Argus-Dedup-Key = %q", got)
	}
	ts := capt.Header.Get("X-Argus-Timestamp")
	sent := time.Unix(parseUnix(t, ts), 0).UTC()
	if !sent.Equal(msg.SentAt) {
		t.Fatalf("X-Argus-Timestamp = %s, want SentAt %s", sent, msg.SentAt)
	}
	if err := VerifySignature(secret, ts, capt.Header.Get("X-Argus-Signature"), capt.Body, msg.SentAt); err != nil {
		t.Fatalf("receiver-side verification failed: %v", err)
	}
	// Payload: canonical versioned envelope with the summary data.
	var payload map[string]any
	if err := json.Unmarshal(capt.Body, &payload); err != nil {
		t.Fatalf("payload not JSON: %v", err)
	}
	if payload["spec_version"] != "1" || payload["event"] != EventFired {
		t.Fatalf("payload envelope = %v", payload)
	}
	data, _ := payload["data"].(map[string]any)
	if data["alert_id"] != msg.AlertID.String() || data["evidence_ref"] != msg.EvidenceURL {
		t.Fatalf("payload data = %v", data)
	}
}

func TestWebhookIDsPayloadOmitsSummary(t *testing.T) {
	capt, handler := capture()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	msg := testMessage(t)
	cfg, _ := json.Marshal(WebhookConfig{URL: srv.URL, Payload: PayloadIDs})
	secretJSON, _ := json.Marshal(SigningSecret{SigningSecret: "s2-signing-" + uuid.NewString()})
	ch := Channel{ID: uuid.New(), Kind: KindWebhook, Config: cfg}

	if _, _, err := DefaultHTTPTransport().Send(context.Background(), ch, secretJSON, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case <-capt.Handled:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not handle the request")
	}
	var payload map[string]any
	mustJSON(t, capt.Body, &payload)
	data, _ := payload["data"].(map[string]any)
	if data["alert_id"] != msg.AlertID.String() {
		t.Fatalf("ids payload data = %v", data)
	}
	if _, ok := data["summary"]; ok {
		t.Fatalf("ids payload must not carry the summary: %v", data)
	}
}

func TestWebhookNon2xxIsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("receiver down"))
	}))
	defer srv.Close()

	cfg, _ := json.Marshal(WebhookConfig{URL: srv.URL, Payload: PayloadSummary})
	ch := Channel{ID: uuid.New(), Kind: KindWebhook, Config: cfg}
	code, ex, err := DefaultHTTPTransport().Send(context.Background(), ch, nil, testMessage(t))
	if err == nil {
		t.Fatal("503 receiver accepted as success")
	}
	if code != http.StatusServiceUnavailable || !strings.Contains(ex, "receiver down") {
		t.Fatalf("failure = code %d excerpt %q", code, ex)
	}
}

func TestWebhookRespectsConfiguredTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(block)

	cfg, _ := json.Marshal(WebhookConfig{URL: srv.URL, Payload: PayloadSummary, TimeoutMS: 100})
	ch := Channel{ID: uuid.New(), Kind: KindWebhook, Config: cfg}
	start := time.Now()
	_, _, err := DefaultHTTPTransport().Send(context.Background(), ch, nil, testMessage(t))
	if err == nil {
		t.Fatal("slow receiver did not time out")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("configured 100ms timeout took %s", elapsed)
	}
}

func parseUnix(t *testing.T, raw string) int64 {
	t.Helper()
	var sec int64
	if _, err := fmt.Sscanf(raw, "%d", &sec); err != nil {
		t.Fatalf("timestamp %q not Unix seconds: %v", raw, err)
	}
	return sec
}

func mustJSON(t *testing.T, raw []byte, dst any) {
	t.Helper()
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("JSON decode: %v (raw=%s)", err, raw)
	}
}

// --- Slack / Teams ----------------------------------------------------------

func TestSlackPayloadShape(t *testing.T) {
	capt, handler := capture()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	msg := testMessage(t)
	secretJSON, _ := json.Marshal(WebhookURLSecret{WebhookURL: srv.URL})
	ch := Channel{ID: uuid.New(), Kind: KindSlack, Config: []byte(`{"channel":"#ops"}`)}
	code, _, err := DefaultHTTPTransport().Send(context.Background(), ch, secretJSON, msg)
	if err != nil || code != http.StatusOK {
		t.Fatalf("Send = %d err=%v", code, err)
	}
	<-capt.Handled
	var payload map[string]any
	mustJSON(t, capt.Body, &payload)
	text, _ := payload["text"].(string)
	if !strings.Contains(text, msg.Subject) || !strings.Contains(text, "Severity: critical") {
		t.Fatalf("slack text = %q", text)
	}
}

func TestTeamsPayloadShape(t *testing.T) {
	capt, handler := capture()
	srv := httptest.NewServer(handler)
	defer srv.Close()

	msg := testMessage(t)
	secretJSON, _ := json.Marshal(WebhookURLSecret{WebhookURL: srv.URL})
	ch := Channel{ID: uuid.New(), Kind: KindTeams, Config: []byte("{}")}
	if _, _, err := DefaultHTTPTransport().Send(context.Background(), ch, secretJSON, msg); err != nil {
		t.Fatalf("Send: %v", err)
	}
	<-capt.Handled
	var card map[string]any
	mustJSON(t, capt.Body, &card)
	if card["@type"] != "MessageCard" || card["title"] != msg.Subject {
		t.Fatalf("teams card = %v", card)
	}
	if card["text"] != msg.Body {
		t.Fatalf("teams text mismatch")
	}
	if card["themeColor"] != themeColor(SeverityCritical) {
		t.Fatalf("themeColor = %v, want %q", card["themeColor"], themeColor(SeverityCritical))
	}
}

// --- SMTP -------------------------------------------------------------------

// smtpSink is a minimal local SMTP server: greeting, EHLO, MAIL/RCPT, DATA and
// QUIT. It stores the raw DATA payload so tests can assert the RFC 5322
// message the stdlib adapter built.
type smtpSink struct {
	t        *testing.T
	ln       net.Listener
	mu       sync.Mutex
	messages []string
}

func newSMTPSink(t *testing.T) *smtpSink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &smtpSink{t: t, ln: ln}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *smtpSink) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *smtpSink) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *smtpSink) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	write := func(line string) {
		_, _ = bw.WriteString(line + "\r\n")
		_ = bw.Flush()
	}
	write("220 test-sink ESMTP ready")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			_, _ = bw.WriteString("250-test-sink\r\n250 OK\r\n")
			_ = bw.Flush()
		case strings.HasPrefix(cmd, "MAIL FROM"), strings.HasPrefix(cmd, "RCPT TO"), cmd == "RSET", cmd == "NOOP":
			write("250 OK")
		case cmd == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var msg strings.Builder
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				msg.WriteString(dl)
			}
			s.mu.Lock()
			s.messages = append(s.messages, msg.String())
			s.mu.Unlock()
			write("250 OK queued")
		case cmd == "QUIT":
			write("221 Bye")
			return
		default:
			write("250 OK")
		}
	}
}

func (s *smtpSink) last(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		if n := len(s.messages); n > 0 {
			msg := s.messages[n-1]
			s.mu.Unlock()
			return msg
		}
		s.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("SMTP sink received no DATA")
	return ""
}

func TestSMTPTransportDeliversToLocalSink(t *testing.T) {
	sink := newSMTPSink(t)
	msg := testMessage(t)
	cfg, _ := json.Marshal(SMTPConfig{
		Host: "127.0.0.1", Port: sink.port(),
		From: "argus@example.test", To: []string{"ops@example.test"},
	})
	ch := Channel{ID: uuid.New(), Kind: KindSMTP, Name: "mail", Enabled: true, Config: cfg}

	code, ex, err := SMTPTransport{}.Send(context.Background(), ch, nil, msg)
	if err != nil {
		t.Fatalf("Send: %v (code=%d excerpt=%q)", err, code, ex)
	}
	if code != 250 {
		t.Fatalf("code = %d, want 250", code)
	}
	raw := sink.last(t)
	for _, want := range []string{
		"From: argus@example.test",
		"To: ops@example.test",
		"Subject: " + mimeSubject(msg.Subject),
		"Severity: critical",
		"Scope: HQ / sw-1",
		"Summary: " + msg.Summary,
		"Started: " + msg.StartedAt.UTC().Format(time.RFC3339),
		"Evidence: " + msg.EvidenceURL,
		"Ack: " + msg.AckURL,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("SMTP message missing %q:\n%s", want, raw)
		}
	}
}

func TestSMTPSubjectHeaderInjectionGuard(t *testing.T) {
	msg := testMessage(t)
	msg.Subject = "legit\r\nBcc: evil@example.test"
	cfg := SMTPConfig{From: "argus@example.test", To: []string{"ops@example.test"}}
	raw := string(smtpMessage(cfg, msg))
	if strings.Contains(raw, "\r\nBcc:") {
		t.Fatalf("CRLF injection survived mimeSubject:\n%s", raw)
	}
	if !strings.Contains(raw, "Subject: legit  Bcc: evil@example.test") {
		t.Fatalf("subject mangled unexpectedly:\n%s", raw)
	}
}

func TestExcerptBounded(t *testing.T) {
	long := strings.Repeat("x", ResponseExcerptMax*2)
	if got := excerpt("  " + long + "  "); len(got) != ResponseExcerptMax {
		t.Fatalf("excerpt length = %d, want %d", len(got), ResponseExcerptMax)
	}
	if got := excerpt(""); got != "" {
		t.Fatalf("empty excerpt = %q", got)
	}
}

func TestTransportRejectsUnknownKind(t *testing.T) {
	ch := Channel{ID: uuid.New(), Kind: "carrier_pigeon", Config: []byte("{}")}
	if _, _, err := DefaultHTTPTransport().Send(context.Background(), ch, nil, testMessage(t)); err == nil {
		t.Fatal("unknown kind accepted by HTTP transport")
	}
}

func TestHTTPTransportUnreadableConfigAndSecret(t *testing.T) {
	ch := Channel{ID: uuid.New(), Kind: KindWebhook, Config: []byte("{not json")}
	if _, _, err := DefaultHTTPTransport().Send(context.Background(), ch, nil, testMessage(t)); err == nil {
		t.Fatal("malformed config accepted")
	}
	cfg, _ := json.Marshal(WebhookConfig{URL: "http://127.0.0.1:1/hook", Payload: PayloadSummary})
	ch = Channel{ID: uuid.New(), Kind: KindWebhook, Config: cfg}
	if _, _, err := DefaultHTTPTransport().Send(context.Background(), ch, []byte("{not json"), testMessage(t)); err == nil {
		t.Fatal("malformed secret accepted")
	}
}
