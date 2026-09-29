// Package buildinfo carries build metadata injected at compile time via
// -ldflags "-X github.com/argus-platform/argus/internal/platform/buildinfo.Version=...".
package buildinfo

// Values are overridden by the build; defaults describe a local dev build.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)
