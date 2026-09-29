# scripts/env.sh — prepend the local toolchain to PATH (source this, or use make).
# Usage:  . ./scripts/env.sh   (bash/zsh)   or   bash -lc 'source scripts/env.sh && ...'

ARGUS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"

export ARGUS_ROOT
export GOPATH="$ARGUS_ROOT/.tools/gopath"
export GOMODCACHE="$ARGUS_ROOT/.tools/gomodcache"
export GOBIN="$ARGUS_ROOT/.tools/bin"
export GOTOOLCHAIN=local
export PATH="$ARGUS_ROOT/.tools/go/bin:$ARGUS_ROOT/.tools/bin:$PATH"
