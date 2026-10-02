package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Transport sends one rendered message to one channel. Implementations must
// be safe for concurrent use. The returned code is the provider response code
// (0 when no response was received) and excerpt is the bounded, redacted
// response text persisted in the delivery log.
type Transport interface {
	Send(ctx context.Context, ch Channel, secretJSON []byte, msg Message) (code int, excerpt string, err error)
}

// HTTPTransport implements the generic webhook, Slack and Teams adapters over
// one bounded HTTP client.
type HTTPTransport struct {
	Client *http.Client
}

// DefaultHTTPTransport returns the production HTTP transport (10 s timeout).
func DefaultHTTPTransport() HTTPTransport {
	return HTTPTransport{Client: &http.Client{Timeout: RequestTimeout}}
}

// Sign computes the canonical webhook signature digest:
// hex(hmac-sha256(signing_secret, timestamp + "." + body)). Callers put it in
// the X-Argus-Signature header as "v1=" + digest.
func Sign(signingSecret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature is the receiver-side counterpart of the webhook adapter: it
// validates an inbound X-Argus-Signature/ X-Argus-Timestamp pair against the
// canonical scheme and the 5 min replay window (docs/12 §22.17). The delivery
// path never calls it; it exists for receivers and for executable contract
// tests.
func VerifySignature(signingSecret, timestampHeader, signatureHeader string, body []byte, now time.Time) error {
	timestampHeader = strings.TrimSpace(timestampHeader)
	if timestampHeader == "" {
		return errors.New("notify: missing X-Argus-Timestamp")
	}
	ts, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return errors.New("notify: X-Argus-Timestamp must be Unix seconds")
	}
	if delta := now.Sub(time.Unix(ts, 0)); delta > ReplayWindow || delta < -ReplayWindow {
		return errors.New("notify: timestamp outside the 5 minute replay window")
	}
	if !strings.HasPrefix(signatureHeader, "v1=") {
		return errors.New("notify: X-Argus-Signature must use the v1 scheme")
	}
	want := Sign(signingSecret, timestampHeader, body)
	if !hmac.Equal([]byte(want), []byte(strings.TrimPrefix(signatureHeader, "v1="))) {
		return errors.New("notify: signature mismatch")
	}
	return nil
}

// Send implements Transport.
func (t HTTPTransport) Send(ctx context.Context, ch Channel, secretJSON []byte, msg Message) (int, string, error) {
	var (
		target  string
		body    []byte
		headers = map[string]string{}
		timeout = RequestTimeout
	)
	switch ch.Kind {
	case KindWebhook:
		var cfg WebhookConfig
		if err := json.Unmarshal(ch.Config, &cfg); err != nil {
			return 0, "", fmt.Errorf("notify: channel config unreadable: %w", err)
		}
		target = cfg.URL
		if cfg.Payload == PayloadIDs {
			body = idsOnlyPayload(msg)
		} else {
			body = msg.Payload
		}
		var sec SigningSecret
		if len(secretJSON) > 0 {
			if err := json.Unmarshal(secretJSON, &sec); err != nil {
				return 0, "", fmt.Errorf("notify: channel secret unreadable: %w", err)
			}
		}
		ts := strconv.FormatInt(msg.SentAt.Unix(), 10)
		headers["Content-Type"] = "application/json"
		headers["X-Argus-Event"] = msg.EventType
		headers["X-Argus-Delivery"] = msg.DeliveryID.String()
		headers["X-Argus-Dedup-Key"] = msg.DedupKey
		headers["X-Argus-Timestamp"] = ts
		headers["X-Argus-Signature"] = "v1=" + Sign(sec.SigningSecret, ts, body)
		if cfg.TimeoutMS > 0 {
			timeout = time.Duration(cfg.TimeoutMS) * time.Millisecond
		}
	case KindSlack:
		var sec WebhookURLSecret
		if err := json.Unmarshal(secretJSON, &sec); err != nil {
			return 0, "", fmt.Errorf("notify: channel secret unreadable: %w", err)
		}
		target = sec.WebhookURL
		body, _ = json.Marshal(map[string]any{"text": msg.Subject + "\n" + msg.Body})
		headers["Content-Type"] = "application/json"
	case KindTeams:
		var sec WebhookURLSecret
		if err := json.Unmarshal(secretJSON, &sec); err != nil {
			return 0, "", fmt.Errorf("notify: channel secret unreadable: %w", err)
		}
		target = sec.WebhookURL
		card := map[string]any{
			"@type":      "MessageCard",
			"@context":   "http://schema.org/extensions",
			"summary":    msg.Summary,
			"title":      msg.Subject,
			"text":       msg.Body,
			"themeColor": themeColor(msg.Severity),
		}
		body, _ = json.Marshal(card)
		headers["Content-Type"] = "application/json"
	default:
		return 0, "", fmt.Errorf("notify: no HTTP adapter for kind %q", ch.Kind)
	}

	client := t.Client
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, target, strings.NewReader(string(body)))
	if err != nil {
		return 0, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, excerpt(err.Error()), err
	}
	defer func() { _ = res.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, ResponseExcerptMax))
	text := excerpt(string(raw))
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return res.StatusCode, text, fmt.Errorf("notify: provider returned HTTP %d", res.StatusCode)
	}
	return res.StatusCode, text, nil
}

func themeColor(severity string) string {
	switch severity {
	case SeverityCritical:
		return "D32F2F"
	case SeverityWarning:
		return "F9A825"
	default:
		return "1976D2"
	}
}

// SMTPTransport implements the SMTP adapter with the Go standard library
// (net/smtp is frozen but supported; pinning a third-party mailer buys
// nothing for plain AUTH LOGIN/PLAIN + optional STARTTLS, and the stdlib
// keeps the dependency surface minimal — recorded in M11_EVIDENCE §S2).
type SMTPTransport struct{}

// Send implements Transport. 250 is reported on a completed DATA/QUIT.
func (SMTPTransport) Send(ctx context.Context, ch Channel, secretJSON []byte, msg Message) (int, string, error) {
	var cfg SMTPConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		return 0, "", fmt.Errorf("notify: channel config unreadable: %w", err)
	}
	var sec SMTPSecret
	if len(secretJSON) > 0 {
		if err := json.Unmarshal(secretJSON, &sec); err != nil {
			return 0, "", fmt.Errorf("notify: channel secret unreadable: %w", err)
		}
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: RequestTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, excerpt(err.Error()), err
	}
	deadline := time.Now().Add(RequestTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		_ = conn.Close()
		return 0, excerpt(err.Error()), err
	}
	defer func() { _ = client.Close() }()
	if cfg.StartTLS {
		if err := client.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return 0, excerpt(err.Error()), err
		}
	}
	if cfg.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.Username, sec.Password, cfg.Host)); err != nil {
			return 0, excerpt(err.Error()), err
		}
	}
	if err := client.Mail(cfg.From); err != nil {
		return 0, excerpt(err.Error()), err
	}
	for _, to := range cfg.To {
		if err := client.Rcpt(strings.TrimSpace(to)); err != nil {
			return 0, excerpt(err.Error()), err
		}
	}
	w, err := client.Data()
	if err != nil {
		return 0, excerpt(err.Error()), err
	}
	if _, err := w.Write(smtpMessage(cfg, msg)); err != nil {
		_ = w.Close()
		return 0, excerpt(err.Error()), err
	}
	if err := w.Close(); err != nil {
		return 0, excerpt(err.Error()), err
	}
	if err := client.Quit(); err != nil {
		return 0, excerpt(err.Error()), err
	}
	return 250, "250 OK", nil
}

// smtpMessage builds a minimal RFC 5322 text/plain message. The body always
// carries severity/scope/summary/start time/evidence/ack links.
func smtpMessage(cfg SMTPConfig, msg Message) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", cfg.From)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(cfg.To, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", mimeSubject(msg.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", msg.SentAt.UTC().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&b, "\r\n")
	body := strings.ReplaceAll(msg.Body, "\n", "\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// mimeSubject keeps the subject on one header line (header injection guard:
// CR/LF are stripped).
func mimeSubject(s string) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.TrimSpace(s)
}

// excerpt bounds a provider response/error string for the delivery log.
func excerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > ResponseExcerptMax {
		s = s[:ResponseExcerptMax]
	}
	return s
}

var errNoTransport = errors.New("notify: no transport configured for channel kind")
