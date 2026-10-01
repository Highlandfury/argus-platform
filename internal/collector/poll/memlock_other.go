//go:build !linux

package poll

// mlock / munlock are no-ops on non-Linux hosts (the canonical best-effort
// contract is Linux-specific; Windows and darwin collectors stay heap-only).
func mlock(_ []byte) bool { return false }

func munlock(_ []byte) {}
