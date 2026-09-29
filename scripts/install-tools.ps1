# scripts/install-tools.ps1 — installs the pinned developer toolchain into .tools/bin.
# Requires the user-local Go from .tools/go (extracted from the official go1.27.1 zip).
# Pins are recorded in docs/phase-1/VERSIONS.md; never install '@latest'.

param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$env:GOPATH = Join-Path $Root '.tools\gopath'
$env:GOMODCACHE = Join-Path $Root '.tools\gomodcache'
$env:GOBIN = Join-Path $Root '.tools\bin'
$env:GOTOOLCHAIN = 'local'

$Go = Join-Path $Root '.tools\go\bin\go.exe'
if (-not (Test-Path $Go)) { $Go = 'go' }

New-Item -ItemType Directory -Force -Path $env:GOBIN | Out-Null

$tools = @(
    @{ pkg = 'github.com/bufbuild/buf/cmd/buf';                          version = 'v1.73.0' },
    @{ pkg = 'google.golang.org/protobuf/cmd/protoc-gen-go';            version = 'v1.36.12' },
    @{ pkg = 'google.golang.org/grpc/cmd/protoc-gen-go-grpc';           version = 'v1.6.2' },
    @{ pkg = 'github.com/golangci/golangci-lint/v2/cmd/golangci-lint';  version = 'v2.14.0' }
)

foreach ($t in $tools) {
    Write-Host "installing $($t.pkg)@$($t.version) ..."
    & $Go install "$($t.pkg)@$($t.version)"
    if ($LASTEXITCODE -ne 0) { throw "go install failed: $($t.pkg)@$($t.version)" }
}

Write-Host "tools installed into $env:GOBIN"
Get-ChildItem $env:GOBIN | Select-Object -ExpandProperty Name
