//go:build !linux

package poll

// The collector is Linux-targeted (canonical Phase 2: Windows collector is
// V2). This stub keeps `go build ./...` green on developer hosts; every probe
// reports `unsupported` poll health and produces no samples.
func newSocketPinger() (Pinger, error) {
	return nil, ErrUnsupportedPlatform
}
