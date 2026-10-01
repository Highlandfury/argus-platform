package poll

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// fakeSession is a scripted snmpSession.
type fakeSession struct {
	getFn   func(oids ...string) ([]SNMPVarBind, error)
	bulkFn  func(oids []string, maxReps int) ([]SNMPVarBind, error)
	nextFn  func(oids ...string) ([]SNMPVarBind, error)
	onClose func() error
}

func (f *fakeSession) Get(oids ...string) ([]SNMPVarBind, error) {
	if f.getFn == nil {
		return nil, nil
	}
	return f.getFn(oids...)
}

func (f *fakeSession) GetBulk(oids []string, maxReps int) ([]SNMPVarBind, error) {
	if f.bulkFn == nil {
		return nil, nil
	}
	return f.bulkFn(oids, maxReps)
}

func (f *fakeSession) GetNext(oids ...string) ([]SNMPVarBind, error) {
	if f.nextFn == nil {
		return nil, nil
	}
	return f.nextFn(oids...)
}

func (f *fakeSession) Close() error {
	if f.onClose == nil {
		return nil
	}
	return f.onClose()
}

func bind(oid string, kind SNMPValueKind, n uint64) SNMPVarBind {
	return SNMPVarBind{OID: oid, Kind: kind, Uint: n}
}

func TestWalkBulkPages(t *testing.T) {
	pages := [][]SNMPVarBind{
		{bind("1.3.6.1.2.1.2.2.1.2.1", ValueString, 0), bind("1.3.6.1.2.1.2.2.1.2.2", ValueString, 0)},
		{bind("1.3.6.1.2.1.2.2.1.2.3", ValueString, 0), bind("1.3.6.1.2.1.2.2.1.8.1", ValueUnsigned, 1)},
	}
	calls := 0
	gotReps := []int{}
	s := &fakeSession{bulkFn: func(_ []string, reps int) ([]SNMPVarBind, error) {
		gotReps = append(gotReps, reps)
		switch {
		case calls < len(pages):
			p := pages[calls]
			calls++
			return p, nil
		case calls == len(pages):
			calls++
			return []SNMPVarBind{bind("1.3.6.1.2.1.2.2.1.8.2", ValueUnsigned, 1)}, nil
		default:
			return []SNMPVarBind{{OID: "1.3.6.1.2.1.2.2.1.8.3", Kind: ValueEndOfMib}}, nil
		}
	}}
	vars, err := walkOID(s, "1.3.6.1.2.1.2.2.1", 25)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(vars) != 5 {
		t.Fatalf("varbinds = %d, want 5: %+v", len(vars), vars)
	}
	if vars[4].OID != "1.3.6.1.2.1.2.2.1.8.2" {
		t.Fatalf("last varbind = %s", vars[4].OID)
	}
	if len(gotReps) != 4 || gotReps[0] != 25 {
		t.Fatalf("bulk reps = %v, want four calls starting at 25", gotReps)
	}
}

func TestWalkStopsOutsideSubtree(t *testing.T) {
	s := &fakeSession{bulkFn: func(_ []string, _ int) ([]SNMPVarBind, error) {
		return []SNMPVarBind{
			bind("1.3.6.1.2.1.2.2.1.2.1", ValueString, 0),
			bind("1.3.6.1.2.1.3.1.1.1", ValueString, 0), // outside the walk root
		}, nil
	}}
	vars, err := walkOID(s, "1.3.6.1.2.1.2.2.1", 25)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(vars) != 1 {
		t.Fatalf("varbinds = %d, want 1", len(vars))
	}
}

func TestWalkSmallerBulkOnTooBigThenGetNext(t *testing.T) {
	reps := []int{}
	nextCalls := 0
	s := &fakeSession{
		bulkFn: func(_ []string, maxReps int) ([]SNMPVarBind, error) {
			reps = append(reps, maxReps)
			return nil, ErrSNMPTooBig
		},
		nextFn: func(_ ...string) ([]SNMPVarBind, error) {
			nextCalls++
			if nextCalls == 1 {
				return []SNMPVarBind{bind("1.3.6.1.2.1.2.2.1.2.1", ValueString, 0)}, nil
			}
			return []SNMPVarBind{{OID: "1.3.6.1.2.1.2.2.1.2.2", Kind: ValueEndOfMib}}, nil
		},
	}
	vars, err := walkOID(s, "1.3.6.1.2.1.2.2.1", 25)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(vars) != 1 || nextCalls != 2 {
		t.Fatalf("vars=%d nextCalls=%d, want 1/2", len(vars), nextCalls)
	}
	want := []int{25, 12, 10} // halve, clamp at the documented lower bound
	if !reflect.DeepEqual(reps, want) {
		t.Fatalf("bulk reps = %v, want %v", reps, want)
	}
}

func TestWalkTruncationOnNonIncreasingOID(t *testing.T) {
	s := &fakeSession{bulkFn: func(_ []string, _ int) ([]SNMPVarBind, error) {
		return []SNMPVarBind{bind("1.3.6.1.2.1.2.2.1.2.1", ValueString, 0)}, nil
	}}
	if _, err := walkOID(s, "1.3.6.1.2.1.2.2.1", 25); !errors.Is(err, ErrSNMPTruncated) {
		t.Fatalf("err = %v, want ErrSNMPTruncated", err)
	}
}

func TestWalkTimeoutMapping(t *testing.T) {
	s := &fakeSession{bulkFn: func(_ []string, _ int) ([]SNMPVarBind, error) {
		return nil, context.DeadlineExceeded
	}}
	if _, err := walkOID(s, "1.3.6.1.2.1.2.2.1", 25); !errors.Is(err, ErrSNMPTimeout) {
		t.Fatalf("err = %v, want ErrSNMPTimeout", err)
	}
}

func TestClassifySNMPErrorClasses(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ErrorNone},
		{ErrSNMPTimeout, ErrorTimeout},
		{ErrSNMPAuthFailure, ErrorAuthFailure},
		{ErrSNMPTruncated, ErrorWalkTruncation},
		{ErrSNMPUnreachable, ErrorUnreachable},
		{context.DeadlineExceeded, ErrorTimeout},
		{errors.New("request timeout (after 2 retries)"), ErrorTimeout},
		{gosnmp.ErrWrongDigest, ErrorAuthFailure},
		{gosnmp.ErrDecryption, ErrorAuthFailure},
		{gosnmp.ErrUnknownUsername, ErrorAuthFailure},
		{errors.New("incoming packet is not authentic, discarding"), ErrorAuthFailure},
		{errors.New("connection refused"), ErrorUnreachable},
	}
	for _, tc := range cases {
		if got := classifySNMPErrorClass(classifySNMPError(tc.err)); got != tc.want {
			t.Errorf("classify(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestSNMPClientSurfaceHasNoSet pins P2-AC-15: the client boundary exposes
// read operations only, so the monitoring path cannot issue an SNMP SET.
func TestSNMPClientSurfaceHasNoSet(t *testing.T) {
	clientMethods := exportedMethodNames(reflect.TypeOf((*SNMPClient)(nil)).Elem())
	if want := []string{"Close", "Get", "Walk"}; !reflect.DeepEqual(clientMethods, want) {
		t.Fatalf("SNMPClient methods = %v, want %v (no Set)", clientMethods, want)
	}
	sessionMethods := exportedMethodNames(reflect.TypeOf((*snmpSession)(nil)).Elem())
	want := []string{"Close", "Get", "GetBulk", "GetNext"}
	if !reflect.DeepEqual(sessionMethods, want) {
		t.Fatalf("snmpSession methods = %v, want %v (no Set)", sessionMethods, want)
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(&snmpClient{}), reflect.TypeOf(&gosnmpSession{})} {
		for _, m := range exportedMethodNames(typ) {
			if m == "Set" || strings.HasPrefix(m, "Set") {
				t.Fatalf("%v exposes a Set path (%s); the monitoring path must be read-only", typ, m)
			}
		}
	}
}

func exportedMethodNames(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumMethod(); i++ {
		name := t.Method(i).Name
		if name != "" && name[0] >= 'A' && name[0] <= 'Z' {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func TestSNMPCredentialsValidate(t *testing.T) {
	valid := SNMPCredentials{
		Version: SNMPVersionV3, Username: "u",
		AuthProtocol: "SHA-256", AuthKey: "auth-pass",
		PrivProtocol: "AES", PrivKey: "priv-pass",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid v3 rejected: %v", err)
	}
	if err := (SNMPCredentials{Version: SNMPVersionV2c, Community: "public"}).Validate(); err != nil {
		t.Fatalf("valid v2c rejected: %v", err)
	}
	if err := (SNMPCredentials{Version: "v1", Community: "public"}).Validate(); err == nil {
		t.Fatal("SNMPv1 must be rejected (RFC 1157 Historic)")
	}
	for _, bad := range []SNMPCredentials{
		{Version: SNMPVersionV2c},
		{Version: SNMPVersionV3, Username: "u", AuthProtocol: "MD5", AuthKey: "k", PrivProtocol: "AES", PrivKey: "k"},
		{Version: SNMPVersionV3, Username: "u", AuthProtocol: "SHA", AuthKey: "k", PrivProtocol: "DES", PrivKey: "k"},
		{Version: SNMPVersionV3, Username: "u", AuthProtocol: "SHA", PrivProtocol: "AES", PrivKey: "k"},
		{Version: SNMPVersionV3, Username: "u", AuthProtocol: "SHA", AuthKey: "k", PrivProtocol: "AES"},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid credentials accepted: %+v", bad)
		}
	}
	if got := valid.UsesWarningPosture(); got {
		t.Fatal("v3 must not use the v2c warning posture")
	}
	if got := (SNMPCredentials{Version: SNMPVersionV2c}).UsesWarningPosture(); !got {
		t.Fatal("v2c must use the warning posture")
	}
}

func TestStaticCredentialSource(t *testing.T) {
	src := NewStaticCredentialSource()
	if _, ok := src.Lookup("dev-1"); ok {
		t.Fatal("empty source returned credentials")
	}
	src.Set("dev-1", SNMPCredentials{Version: SNMPVersionV2c, Community: "public"})
	src.SetDefault(SNMPCredentials{Version: SNMPVersionV2c, Community: "fallback"})
	if c, ok := src.Lookup("dev-1"); !ok || c.Community != "public" {
		t.Fatalf("device credentials = %+v ok=%v", c, ok)
	}
	if c, ok := src.Lookup("dev-2"); !ok || c.Community != "fallback" {
		t.Fatalf("default credentials = %+v ok=%v", c, ok)
	}
}

func TestSNMPLoggerWarnsOncePerDevice(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, nil))
	l := newSNMPLogger(log)
	l.warnV2c("dev-1")
	l.warnV2c("dev-1")
	l.warnV2c("dev-2")
	if got := strings.Count(buf.String(), "SNMP v2c in use"); got != 2 {
		t.Fatalf("warnings = %d, want 2 (once per device)", got)
	}
}

func TestOIDHelpers(t *testing.T) {
	if !oidUnder("1.3.6.1.2.1", "1.3.6.1") {
		t.Fatal("expected subtree match")
	}
	if oidUnder("1.3.6.1", "1.3.6.1") {
		t.Fatal("root itself is not strictly under the root")
	}
	if oidGreater("1.3.6.1.2", "1.3.6.1.10") {
		t.Fatal("numeric arc comparison must be numeric, not lexical (2 < 10)")
	}
	if !oidGreater("2", "1.9") {
		t.Fatal("expected 2 > 1.9")
	}
	if !oidGreater("1.3.6.1.2.1", "1.3.6.1.2") {
		t.Fatal("longer prefix of equal arcs is greater")
	}
}

func TestNewGosnmpClientRejectsInvalidCredentialsBeforeDial(t *testing.T) {
	_, err := NewGosnmpClient(netip.MustParseAddr("192.0.2.1"), SNMPCredentials{Version: "v1"}, ClientConfig{Timeout: 10 * time.Millisecond})
	if err == nil {
		t.Fatal("invalid credentials must fail before connecting")
	}
}
