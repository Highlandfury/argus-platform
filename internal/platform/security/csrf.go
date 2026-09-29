package security

// VerifyCSRF validates the double-submit CSRF scheme with server-side anchoring:
//
//   - the raw token is issued in a readable cookie (argus_csrf),
//   - the same raw token must be echoed in the X-CSRF-Token header on unsafe
//     methods,
//   - and HashToken(raw) must equal the hash stored on the session row.
//
// The third check means a stolen cookie alone (without the session row
// co-signature match) cannot satisfy verification, and a forged pair cannot
// reuse another session's stored hash (SPEC §24.7, S-10).
func VerifyCSRF(cookieRaw, headerRaw string, sessionHash []byte) bool {
	if cookieRaw == "" || headerRaw == "" || len(sessionHash) == 0 {
		return false
	}
	if !SecureEqual([]byte(cookieRaw), []byte(headerRaw)) {
		return false
	}
	return SecureEqual(HashToken(cookieRaw), sessionHash)
}
