package poll

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Credential payload schema (M9-S3, wire contract between the server's
// SecretsVault plaintext and the collector SNMP session). The server never
// interprets the vault plaintext; it moves those exact bytes into the
// per-session sealed record and labels it with the credential kind. The
// collector parses the decrypted bytes here:
//
//	snmp_v2c: the community string (the whole secret, not JSON)
//	snmp_v3:  a JSON object, keys in snake_case:
//	          {"username":"…","auth_protocol":"SHA-256","auth_key":"…",
//	           "priv_protocol":"AES-256","priv_key":"…","context":"…"}
//
// Payload-derived strings are never echoed in returned error messages (a
// malformed payload must not leak fragments into poll health or logs).
const (
	// CredentialKindV2c / CredentialKindV3 are the server-side credential
	// kinds that carry SNMP material (device_credentials.kind).
	CredentialKindV2c = "snmp_v2c" //nolint:gosec // credential kind label, not a secret
	CredentialKindV3  = "snmp_v3"  //nolint:gosec // credential kind label, not a secret
)

// errCredentialPayload is the single sanitized error for malformed payloads.
var errCredentialPayload = errors.New("poll: credential payload is not a valid SNMP authPriv credential")

// ParseCredentialPayload decodes one decrypted credential payload into the SNMP
// session shape. It performs no I/O and keeps nothing.
func ParseCredentialPayload(kind string, plaintext []byte) (SNMPCredentials, error) {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case CredentialKindV2c:
		community := string(plaintext)
		if strings.TrimSpace(community) == "" {
			return SNMPCredentials{}, errCredentialPayload
		}
		return SNMPCredentials{Version: SNMPVersionV2c, Community: community}, nil
	case CredentialKindV3:
		var payload struct {
			Username     string `json:"username"`
			AuthProtocol string `json:"auth_protocol"`
			AuthKey      string `json:"auth_key"`
			PrivProtocol string `json:"priv_protocol"`
			PrivKey      string `json:"priv_key"`
			Context      string `json:"context"`
		}
		dec := json.NewDecoder(bytes.NewReader(plaintext))
		if err := dec.Decode(&payload); err != nil {
			return SNMPCredentials{}, errCredentialPayload
		}
		creds := SNMPCredentials{
			Version:      SNMPVersionV3,
			Context:      payload.Context,
			Username:     payload.Username,
			AuthProtocol: payload.AuthProtocol,
			AuthKey:      payload.AuthKey,
			PrivProtocol: payload.PrivProtocol,
			PrivKey:      payload.PrivKey,
		}
		if err := creds.Validate(); err != nil {
			// Validate's message echoes protocol strings from the payload;
			// collapse to the sanitized sentinel.
			return SNMPCredentials{}, errCredentialPayload
		}
		return creds, nil
	default:
		return SNMPCredentials{}, fmt.Errorf("poll: unsupported credential kind %q", kind)
	}
}
