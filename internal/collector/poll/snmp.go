package poll

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// SNMP client constants. Defaults follow canonical docs/07 §12.3: per-RPC
// timeout 2 s with 2 retries, GETBULK max-repetitions inside the documented
// 10-25 band (default 25), GETNEXT fallback for misbehaving agents, and a
// smaller-bulk retry on fragmentation (TooBig).
const (
	SNMPVersionV2c = "v2c"
	SNMPVersionV3  = "v3"

	// DefaultSNMPPort is the command responder port (RFC 3417).
	DefaultSNMPPort = 161
	// DefaultSNMPTimeout is the canonical per-RPC timeout.
	DefaultSNMPTimeout = 2 * time.Second
	// DefaultSNMPRetries is the canonical retry count (per RPC).
	DefaultSNMPRetries = 2
	// SNMPMinMaxRepetitions / SNMPMaxMaxRepetitions bound the GETBULK
	// max-repetitions knob (canonical 10-25).
	SNMPMinMaxRepetitions = 10
	SNMPMaxMaxRepetitions = 25
	// DefaultSNMPMaxRepetitions uses the top of the documented band: fewer
	// RPCs per table walk; the walk loop halves it on TooBig responses and
	// falls back to GETNEXT at the lower bound.
	DefaultSNMPMaxRepetitions = 25
	// maxWalkRequests bounds one table walk (runaway-agent guard).
	maxWalkRequests = 2000
	// maxWalkVarbinds bounds one table walk's result set.
	maxWalkVarbinds = 200000
)

// SNMP errors (stable sentinels; the poll-health error classes are derived
// from them in classifySNMRErrorClass). gosnmp reports some conditions as
// plain messages; the pin documented in VERSIONS.md makes those checks stable.
var (
	// ErrSNMPTimeout is a per-RPC timeout after the configured retries.
	ErrSNMPTimeout = errors.New("snmp: request timeout")
	// ErrSNMPAuthFailure groups v3 USM authentication/decryption failures and
	// SNMP authorization errors: credentials are wrong or the engine state is
	// unusable (canonical `auth.failure`).
	ErrSNMPAuthFailure = errors.New("snmp: authentication failure")
	// ErrSNMPTooBig signals a response too large to transport (fragmentation
	// evidence): the walk retries with a smaller bulk, then GETNEXT.
	ErrSNMPTooBig = errors.New("snmp: response too big")
	// ErrSNMPTruncated signals a walk that did not complete (non-increasing
	// OIDs, no progress, or the request cap).
	ErrSNMPTruncated = errors.New("snmp: walk truncated")
	// ErrSNMPUnreachable covers socket/transport errors other than timeouts.
	ErrSNMPUnreachable = errors.New("snmp: unreachable")
)

// SNMPCredentials is the credential material needed by one SNMP session.
// M9-S2 receives these from a CredentialSource (fixtures in this slice); M9-S3
// swaps the source for signed-bundle materialization without touching the
// client or the prober.
type SNMPCredentials struct {
	Version string // "v2c" | "v3"
	// v2c. Canonical preference puts v3 authPriv first; v2c is allowed with a
	// warning posture (docs/07 §12.6).
	Community string
	// v3 context name (selects the simulated/physical context; usually empty).
	Context string
	// v3 authPriv.
	Username     string
	AuthProtocol string // SHA | SHA-224 | SHA-256 | SHA-384 | SHA-512
	AuthKey      string
	PrivProtocol string // AES | AES-192 | AES-256
	PrivKey      string
}

// Validate checks the credential shape. SNMPv1 is deliberately rejected
// (RFC 1157 Historic; canonical discourages it) and so is v3 authNoPriv /
// noAuthNoPriv (canonical preference is authPriv).
func (c SNMPCredentials) Validate() error {
	switch strings.ToLower(strings.TrimSpace(c.Version)) {
	case SNMPVersionV2c:
		if strings.TrimSpace(c.Community) == "" {
			return errors.New("snmp: v2c credentials need a community")
		}
		return nil
	case SNMPVersionV3:
		if strings.TrimSpace(c.Username) == "" {
			return errors.New("snmp: v3 credentials need a username")
		}
		if _, ok := snmpAuthProtocol(c.AuthProtocol); !ok {
			return fmt.Errorf("snmp: v3 auth protocol %q is not a supported SHA family", c.AuthProtocol)
		}
		if strings.TrimSpace(c.AuthKey) == "" {
			return errors.New("snmp: v3 credentials need an auth key")
		}
		if _, ok := snmpPrivProtocol(c.PrivProtocol); !ok {
			return fmt.Errorf("snmp: v3 priv protocol %q is not a supported AES variant", c.PrivProtocol)
		}
		if strings.TrimSpace(c.PrivKey) == "" {
			return errors.New("snmp: v3 credentials need a priv key")
		}
		return nil
	default:
		return fmt.Errorf("snmp: unsupported credential version %q (v2c or v3)", c.Version)
	}
}

// UsesWarningPosture reports whether the credential is a v2c community, for
// which the collector logs the canonical warning posture on use.
func (c SNMPCredentials) UsesWarningPosture() bool {
	return strings.EqualFold(strings.TrimSpace(c.Version), SNMPVersionV2c)
}

func snmpAuthProtocol(s string) (gosnmp.SnmpV3AuthProtocol, bool) {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "")) {
	case "SHA", "SHA1":
		return gosnmp.SHA, true
	case "SHA224":
		return gosnmp.SHA224, true
	case "SHA256":
		return gosnmp.SHA256, true
	case "SHA384":
		return gosnmp.SHA384, true
	case "SHA512":
		return gosnmp.SHA512, true
	default:
		return 0, false
	}
}

func snmpPrivProtocol(s string) (gosnmp.SnmpV3PrivProtocol, bool) {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", "")) {
	case "AES", "AES128":
		return gosnmp.AES, true
	case "AES192":
		return gosnmp.AES192, true
	case "AES256":
		return gosnmp.AES256, true
	default:
		return 0, false
	}
}

// CredentialSource resolves the SNMP credentials for a device. This is the
// M9-S3 seam: S2 ships fixture-backed implementations only; S3 materializes
// per-session credentials from signed bundles behind the same interface.
type CredentialSource interface {
	Lookup(deviceID string) (SNMPCredentials, bool)
}

// StaticCredentialSource is the fixture/dev implementation (M9-S2). A Default
// entry applies to every device without an explicit entry; production S3 will
// replace it. It is safe for concurrent use (tests swap fixtures at runtime).
type StaticCredentialSource struct {
	mu       sync.RWMutex
	byDevice map[string]SNMPCredentials
	def      *SNMPCredentials
}

// NewStaticCredentialSource returns an empty fixture source.
func NewStaticCredentialSource() *StaticCredentialSource {
	return &StaticCredentialSource{byDevice: make(map[string]SNMPCredentials)}
}

// Set assigns one device's fixture credentials.
func (s *StaticCredentialSource) Set(deviceID string, creds SNMPCredentials) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byDevice[deviceID] = creds
}

// SetDefault assigns the fallback credentials for devices without an entry.
func (s *StaticCredentialSource) SetDefault(creds SNMPCredentials) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.def = &creds
}

// Lookup implements CredentialSource.
func (s *StaticCredentialSource) Lookup(deviceID string) (SNMPCredentials, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.byDevice[deviceID]; ok {
		return c, true
	}
	if s.def != nil {
		return *s.def, true
	}
	return SNMPCredentials{}, false
}

// SNMPValueKind is the protocol-neutral varbind value kind.
type SNMPValueKind int

// Varbind value kinds.
const (
	ValueUnknown SNMPValueKind = iota
	ValueInteger
	ValueUnsigned // Counter32/Gauge32/TimeTicks/UInteger32
	ValueCounter64
	ValueString
	ValueOID
	ValueIPAddress
	ValueNoSuch   // noSuchObject / noSuchInstance
	ValueEndOfMib // endOfMibView
)

// SNMPVarBind is one protocol-neutral OID/value pair.
type SNMPVarBind struct {
	OID  string
	Kind SNMPValueKind
	Uint uint64
	Int  int64
	Str  string
}

// Numeric returns the numeric value of gauge/counter varbinds.
func (v SNMPVarBind) Numeric() (float64, bool) {
	switch v.Kind {
	case ValueInteger:
		return float64(v.Int), true
	case ValueUnsigned, ValueCounter64:
		// #nosec G115 -- counter magnitudes are bounded by the wire type and
		// deliberately converted to float64 for rate math (documented).
		return float64(v.Uint), true
	default:
		return 0, false
	}
}

// CounterWidth reports the counter width for counter varbinds (32/64), 0 for
// non-counters.
func (v SNMPVarBind) CounterWidth() int {
	switch v.Kind {
	case ValueUnsigned:
		return 32
	case ValueCounter64:
		return 64
	default:
		return 0
	}
}

// snmpSession is the narrow, read-only session surface the client depends on.
// It deliberately has no Set method: the monitoring path never issues SNMP SET
// (canonical docs/07 §12.6; P2-AC-15, pinned by the client-boundary test).
type snmpSession interface {
	Get(oids ...string) ([]SNMPVarBind, error)
	GetBulk(oids []string, maxRepetitions int) ([]SNMPVarBind, error)
	GetNext(oids ...string) ([]SNMPVarBind, error)
	Close() error
}

// SNMPClient is the read-only client surface. It exposes Get and Walk only —
// there is no Set path to call (test-pinned).
type SNMPClient interface {
	Get(oids []string) ([]SNMPVarBind, error)
	Walk(rootOID string) ([]SNMPVarBind, error)
	Close() error
}

// ClientConfig carries the per-profile SNMP tunables. Zero values take the
// canonical defaults (docs/07 §12.3).
type ClientConfig struct {
	Port           int
	Timeout        time.Duration
	Retries        int
	MaxRepetitions int
}

func (c ClientConfig) withDefaults() ClientConfig {
	if c.Port <= 0 || c.Port > 65535 {
		c.Port = DefaultSNMPPort
	}
	if c.Timeout <= 0 {
		c.Timeout = DefaultSNMPTimeout
	}
	if c.Retries < 0 {
		c.Retries = DefaultSNMPRetries
	}
	if c.MaxRepetitions <= 0 {
		c.MaxRepetitions = DefaultSNMPMaxRepetitions
	}
	if c.MaxRepetitions < SNMPMinMaxRepetitions {
		c.MaxRepetitions = SNMPMinMaxRepetitions
	}
	if c.MaxRepetitions > SNMPMaxMaxRepetitions {
		c.MaxRepetitions = SNMPMaxMaxRepetitions
	}
	return c
}

// ClientFactory builds one read-only client per probe. Tests inject fakes;
// production uses NewGosnmpClient. Session pooling is M9-S4 work.
type ClientFactory func(target netip.Addr, creds SNMPCredentials, cfg ClientConfig) (SNMPClient, error)

// NewGosnmpClient builds a gosnmp-backed read-only client for one target. The
// returned client is single-use (Close after the probe); one client performs
// at most one walk at a time.
func NewGosnmpClient(target netip.Addr, creds SNMPCredentials, cfg ClientConfig) (SNMPClient, error) {
	if err := creds.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	g := &gosnmp.GoSNMP{
		Target:  target.String(),
		Port:    uint16(cfg.Port), // #nosec G115 -- validated [1,65535] in withDefaults
		Timeout: cfg.Timeout,
		Retries: cfg.Retries,
		// gosnmp default transport is UDP; that is the only transport this
		// slice supports (TLS/DTLS is canonical V2).
		Transport: "udp",
		Version:   gosnmp.Version2c,
		Community: creds.Community,
	}
	if strings.EqualFold(strings.TrimSpace(creds.Version), SNMPVersionV3) {
		auth, _ := snmpAuthProtocol(creds.AuthProtocol) // validated above
		priv, _ := snmpPrivProtocol(creds.PrivProtocol) // validated above
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = gosnmp.AuthPriv
		g.ContextName = creds.Context
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 creds.Username,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: creds.AuthKey,
			PrivacyProtocol:          priv,
			PrivacyPassphrase:        creds.PrivKey,
		}
	}
	if err := g.Connect(); err != nil {
		return nil, classifySNMPError(err)
	}
	return &snmpClient{session: &gosnmpSession{conn: g}, maxRepetitions: cfg.MaxRepetitions}, nil
}

// snmpClient wraps a session with the walk policy (bulk sizing, fallback) and
// the one-walk-in-flight-per-device guarantee (canonical docs/07 §12.3).
type snmpClient struct {
	session        snmpSession
	maxRepetitions int
	mu             sync.Mutex // serializes walks on this client/device
}

// Get implements SNMPClient.
func (c *snmpClient) Get(oids []string) ([]SNMPVarBind, error) {
	return c.session.Get(oids...)
}

// Walk implements SNMPClient using GETBULK with a GETNEXT fallback.
func (c *snmpClient) Walk(rootOID string) ([]SNMPVarBind, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return walkOID(c.session, rootOID, c.maxRepetitions)
}

// Close implements SNMPClient.
func (c *snmpClient) Close() error { return c.session.Close() }

// walkOID walks one subtree. Strategy (canonical docs/07 §12.3): GETBULK with
// max-repetitions; on a TooBig response halve the bulk size down to the
// documented lower bound, then fall back to GETNEXT for the remainder.
func walkOID(s snmpSession, rootOID string, maxRepetitions int) ([]SNMPVarBind, error) {
	root := strings.TrimPrefix(strings.TrimSpace(rootOID), ".")
	if root == "" {
		return nil, errors.New("snmp: walk needs a root OID")
	}
	if maxRepetitions <= 0 {
		maxRepetitions = DefaultSNMPMaxRepetitions
	}
	if maxRepetitions < SNMPMinMaxRepetitions {
		maxRepetitions = SNMPMinMaxRepetitions
	}
	if maxRepetitions > SNMPMaxMaxRepetitions {
		maxRepetitions = SNMPMaxMaxRepetitions
	}

	var out []SNMPVarBind
	cur := root
	useBulk := true
	reps := maxRepetitions
	for requests := 0; requests < maxWalkRequests; requests++ {
		var (
			vars []SNMPVarBind
			err  error
		)
		if useBulk {
			vars, err = s.GetBulk([]string{cur}, reps)
			if errors.Is(err, ErrSNMPTooBig) {
				// Fragmentation evidence: retry with a smaller bulk; at the
				// lower bound switch to GETNEXT (canonical).
				if reps > SNMPMinMaxRepetitions {
					reps /= 2
					if reps < SNMPMinMaxRepetitions {
						reps = SNMPMinMaxRepetitions
					}
					continue
				}
				useBulk = false
				continue
			}
		} else {
			vars, err = s.GetNext(cur)
		}
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSNMPTimeout) {
				return out, ErrSNMPTimeout
			}
			return out, err
		}
		if len(vars) == 0 {
			return out, nil
		}
		progress := false
		for _, v := range vars {
			if v.Kind == ValueEndOfMib || v.Kind == ValueNoSuch {
				return out, nil
			}
			if !oidUnder(v.OID, root) {
				return out, nil
			}
			if !oidGreater(v.OID, cur) {
				// A non-increasing OID means the agent ignored the request or
				// wrapped; the walk is truncated (P2-AC-20).
				return out, fmt.Errorf("%w: non-increasing OID %s after %s", ErrSNMPTruncated, v.OID, cur)
			}
			out = append(out, v)
			cur = v.OID
			progress = true
			if len(out) > maxWalkVarbinds {
				return out, fmt.Errorf("%w: varbind cap %d reached at %s", ErrSNMPTruncated, maxWalkVarbinds, cur)
			}
			if !useBulk {
				break // GETNEXT returns one varbind per request
			}
		}
		if !progress {
			return out, fmt.Errorf("%w: no progress at %s", ErrSNMPTruncated, cur)
		}
	}
	return out, fmt.Errorf("%w: request cap %d reached at %s", ErrSNMPTruncated, maxWalkRequests, cur)
}

// oidUnder reports whether oid is inside the subtree rooted at root (strictly
// below it).
func oidUnder(oid, root string) bool {
	return strings.HasPrefix(oid, root+".")
}

// oidGreater compares dotted numeric OIDs lexicographically by arc.
func oidGreater(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] == bs[i] {
			continue
		}
		an, aerr := parseOIDArc(as[i])
		bn, berr := parseOIDArc(bs[i])
		if aerr != nil || berr != nil {
			return a > b
		}
		return an > bn
	}
	return len(as) > len(bs)
}

func parseOIDArc(s string) (uint64, error) {
	var n uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("snmp: invalid OID arc %q", s)
		}
		n = n*10 + uint64(s[i]-'0')
	}
	return n, nil
}

// gosnmpSession adapts *gosnmp.GoSNMP to snmpSession. Only read operations are
// wired: there is no code path that can call GoSNMP.Set.
type gosnmpSession struct {
	conn *gosnmp.GoSNMP
}

func (s *gosnmpSession) Get(oids ...string) ([]SNMPVarBind, error) {
	pkt, err := s.conn.Get(oids)
	return snmpPacketVars(pkt, err)
}

func (s *gosnmpSession) GetBulk(oids []string, maxRepetitions int) ([]SNMPVarBind, error) {
	pkt, err := s.conn.GetBulk(oids, 0, uint32(maxRepetitions)) // #nosec G115 -- bounded 10-25 by caller
	return snmpPacketVars(pkt, err)
}

func (s *gosnmpSession) GetNext(oids ...string) ([]SNMPVarBind, error) {
	pkt, err := s.conn.GetNext(oids)
	return snmpPacketVars(pkt, err)
}

func (s *gosnmpSession) Close() error {
	if s.conn == nil || s.conn.Conn == nil {
		return nil
	}
	return s.conn.Conn.Close()
}

func snmpPacketVars(pkt *gosnmp.SnmpPacket, err error) ([]SNMPVarBind, error) {
	if err != nil {
		return nil, classifySNMPError(err)
	}
	if pkt == nil {
		return nil, ErrSNMPUnreachable
	}
	switch pkt.Error {
	case gosnmp.NoError:
	case gosnmp.TooBig:
		return nil, ErrSNMPTooBig
	case gosnmp.AuthorizationError:
		return nil, ErrSNMPAuthFailure
	default:
		return nil, fmt.Errorf("%w: agent error status %s", ErrSNMPUnreachable, pkt.Error)
	}
	out := make([]SNMPVarBind, 0, len(pkt.Variables))
	for _, v := range pkt.Variables {
		out = append(out, snmpVarBind(v))
	}
	return out, nil
}

func snmpVarBind(pdu gosnmp.SnmpPDU) SNMPVarBind {
	v := SNMPVarBind{OID: strings.TrimPrefix(pdu.Name, ".")}
	switch pdu.Type {
	case gosnmp.Integer:
		v.Kind = ValueInteger
		if n, ok := pdu.Value.(int); ok {
			v.Int = int64(n)
		}
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.TimeTicks, gosnmp.Uinteger32:
		v.Kind = ValueUnsigned
		switch n := pdu.Value.(type) {
		case uint:
			v.Uint = uint64(n)
		case uint32:
			v.Uint = uint64(n)
		case int:
			v.Uint = uint64(n) // #nosec G115 -- wire type is unsigned
		}
	case gosnmp.Counter64:
		v.Kind = ValueCounter64
		if n, ok := pdu.Value.(uint64); ok {
			v.Uint = n
		}
	case gosnmp.OctetString:
		v.Kind = ValueString
		switch s := pdu.Value.(type) {
		case []byte:
			v.Str = string(s)
		case string:
			v.Str = s
		}
	case gosnmp.ObjectIdentifier:
		v.Kind = ValueOID
		v.Str, _ = pdu.Value.(string)
	case gosnmp.IPAddress:
		v.Kind = ValueIPAddress
		v.Str, _ = pdu.Value.(string)
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance:
		v.Kind = ValueNoSuch
	case gosnmp.EndOfMibView:
		v.Kind = ValueEndOfMib
	default:
		v.Kind = ValueUnknown
	}
	return v
}

// classifySNMPError maps gosnmp errors onto the stable sentinels. gosnmp
// reports timeouts and some v3 conditions as plain messages, so the pinned
// version's message shapes are matched explicitly (see VERSIONS.md).
func classifySNMPError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrSNMPTimeout) || errors.Is(err, ErrSNMPAuthFailure) ||
		errors.Is(err, ErrSNMPTooBig) || errors.Is(err, ErrSNMPTruncated) ||
		errors.Is(err, ErrSNMPUnreachable) {
		return err
	}
	if errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "request timeout") ||
		isTimeout(err) {
		return fmt.Errorf("%w: %w", ErrSNMPTimeout, err)
	}
	if isSNMPAuthError(err) {
		return fmt.Errorf("%w: %w", ErrSNMPAuthFailure, err)
	}
	return fmt.Errorf("%w: %w", ErrSNMPUnreachable, err)
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isSNMPAuthError(err error) bool {
	return errors.Is(err, gosnmp.ErrUnknownUsername) ||
		errors.Is(err, gosnmp.ErrWrongDigest) ||
		errors.Is(err, gosnmp.ErrDecryption) ||
		errors.Is(err, gosnmp.ErrNotInTimeWindow) ||
		errors.Is(err, gosnmp.ErrUnknownEngineID) ||
		errors.Is(err, gosnmp.ErrUnknownSecurityLevel) ||
		errors.Is(err, gosnmp.ErrUnknownSecurityModels) ||
		errors.Is(err, gosnmp.ErrUnknownPDUHandlers) ||
		strings.Contains(err.Error(), "not authentic") ||
		strings.Contains(err.Error(), "unknown security level")
}

// classifySNMPErrorClass maps an SNMP error onto the poll-health error class
// vocabulary (P2-AC-20): timeout, auth_failure, walk_truncation (and
// unreachable for other transport failures).
func classifySNMPErrorClass(err error) string {
	switch {
	case err == nil:
		return ErrorNone
	case errors.Is(err, ErrSNMPTimeout):
		return ErrorTimeout
	case errors.Is(err, ErrSNMPAuthFailure):
		return ErrorAuthFailure
	case errors.Is(err, ErrSNMPTruncated):
		return ErrorWalkTruncation
	default:
		return ErrorUnreachable
	}
}

// snmpLogger carries the v2c warning posture once per device.
type snmpLogger struct {
	mu   sync.Mutex
	seen map[string]bool
	log  *slog.Logger
}

func newSNMPLogger(log *slog.Logger) *snmpLogger {
	return &snmpLogger{seen: make(map[string]bool), log: log}
}

// warnV2c logs the canonical v2c warning posture once per device.
func (l *snmpLogger) warnV2c(deviceID string) {
	if l == nil || l.log == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.seen[deviceID] {
		return
	}
	l.seen[deviceID] = true
	l.log.Warn("SNMP v2c in use; canonical preference is v3 authPriv",
		"device_id", deviceID)
}
