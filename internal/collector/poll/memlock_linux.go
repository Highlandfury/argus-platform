//go:build linux

package poll

import "syscall"

// mlock pins the session seed into RAM, best-effort (canonical docs/14 §24.5:
// "collector keeps plaintext only in RAM (Linux mlock best-effort)"). Failure
// (e.g. RLIMIT_MEMLOCK exhausted) is not fatal: the seed stays heap-only.
func mlock(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return syscall.Mlock(b) == nil
}

func munlock(b []byte) {
	if len(b) > 0 {
		_ = syscall.Munlock(b)
	}
}
