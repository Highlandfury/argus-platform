#!/usr/bin/env pwsh
<#
.SYNOPSIS
  Local equivalent of the GitHub Actions pipeline (works without GitHub).

.DESCRIPTION
  Runs the same gates as .github/workflows/ci.yml using the repository's pinned
  tools (.tools) and Docker Desktop. Use this when GitHub Actions is unavailable
  (account billing lock blocks all jobs, including self-hosted runners) or as a
  pre-push verification. The GitHub workflow remains the canonical definition;
  this script mirrors its stages.

  Default stages (fast, no Docker):
    fmt       gofmt -l cmd internal must be empty
    vet       go vet ./...
    build     go build ./... + server/collector binaries into bin\
    test      go test ./internal/... ./tests/contract/... -count=1
              (-Race switches to -race, Linux/WSL only: needs cgo/gcc)
    lint      golangci-lint run (pinned)
    proto     buf lint + buf generate + git diff --exit-code -- gen

  Optional stages:
    -WithSuites   integration failure + security suites (testcontainers; Docker required)
    -WithIntegration  full tests/integration suite - all slice suites (testcontainers; Docker required)
    -WithStack    compose up --build --wait, extract CA, run the e2e harness,
                  then compose down (volumes kept) AFTER the optional web stage
    -WithWeb      web production build + Playwright suite (needs the stack running;
                  combine with -WithStack or start it yourself)

.PARAMETER Race
  Run the test stage with the race detector. Requires cgo/gcc (Linux/WSL);
  the Windows host cannot build the race runtime.

.EXAMPLE
  .\scripts\ci-local.ps1
  .\scripts\ci-local.ps1 -Race -WithSuites
  .\scripts\ci-local.ps1 -WithStack -WithWeb
#>
param(
  [switch]$Race,
  [switch]$WithSuites,
  [switch]$WithIntegration,
  [switch]$WithStack,
  [switch]$WithWeb
)

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$go   = Join-Path $root '.tools\go\bin\go.exe'
$gofmt = Join-Path $root '.tools\go\bin\gofmt.exe'
$buf  = Join-Path $root '.tools\bin\buf.exe'
$lint = Join-Path $root '.tools\bin\golangci-lint.exe'
$env:PATH = (Join-Path $root '.tools\go\bin') + ';' + (Join-Path $root '.tools\bin') + ';' + $env:PATH
$env:GOPATH = Join-Path $root '.tools\gopath'
$env:GOMODCACHE = Join-Path $root '.tools\gomodcache'
$env:GOTOOLCHAIN = 'local'

$dockerDir = 'C:\Program Files\Docker\Docker\resources\bin'
if (Test-Path $dockerDir) { $env:PATH = "$dockerDir;$env:PATH" }
$d = Join-Path $dockerDir 'docker.exe'
$cf = 'deployments\compose\docker-compose.dev.yml'

$failures = New-Object System.Collections.ArrayList
$timings = New-Object System.Collections.ArrayList

function Step([string]$name, [scriptblock]$block) {
  Write-Host "`n== $name ==" -ForegroundColor Cyan
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  & $block
  $sw.Stop()
  [void]$timings.Add([pscustomobject]@{ Stage = $name; Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1) })
  if ($global:LASTEXITCODE -ne 0) {
    [void]$failures.Add($name)
    Write-Host "FAIL: $name" -ForegroundColor Red
  } else {
    Write-Host "PASS: $name" -ForegroundColor Green
  }
}

Step 'fmt' {
  $bad = & $gofmt -l cmd internal
  if ($bad) { Write-Host "unformatted files: $bad"; $global:LASTEXITCODE = 1 } else { $global:LASTEXITCODE = 0 }
}

Step 'vet' { & $go vet ./... }

Step 'build' {
  & $go build ./...
  if ($global:LASTEXITCODE -ne 0) { return }
  & $go build -o bin\argus-server.exe ./cmd/argus-server
  if ($global:LASTEXITCODE -ne 0) { return }
  & $go build -o bin\argus-collector.exe ./cmd/argus-collector
}

if ($Race) {
  Step 'test (-race; needs cgo/gcc — Linux/WSL)' { & $go test -race ./internal/... ./tests/contract/... -count=1 }
} else {
  Step 'test' { & $go test ./internal/... ./tests/contract/... -count=1 }
}

Step 'lint' { & $lint run }

Step 'proto' {
  & $buf lint
  if ($global:LASTEXITCODE -ne 0) { return }
  & $buf generate
  if ($global:LASTEXITCODE -ne 0) { return }
  git diff --exit-code -- gen
}

if ($WithSuites) {
  Step 'suites (failure + security, testcontainers)' {
    & $go test ./tests/integration/... -run 'TestFailureSuite|TestSecuritySuite' -count=1 -v
  }
}

if ($WithIntegration) {
  Step 'integration (full suite, testcontainers)' {
    & $go test ./tests/integration/... -count=1
  }
}

if ($WithStack) {
  Step 'stack up (compose --wait)' {
    & $d compose -f $cf up -d --build --wait
  }
  Step 'e2e harness (AC-01/02/03/08, T7)' {
    & $d compose -f $cf cp server:/var/lib/argus/ca/root.pem ./.dev/ca-root.pem
    if ($global:LASTEXITCODE -ne 0) { return }
    $env:ARGUS_E2E = '1'
    try { & $go test ./tests/e2e/... -count=1 -v }
    finally { Remove-Item Env:\ARGUS_E2E -ErrorAction SilentlyContinue }
  }
}

if ($WithWeb) {
  Step 'web build + Playwright' {
    Push-Location web
    try {
      & 'C:\Program Files\nodejs\npm.cmd' run build
      if ($global:LASTEXITCODE -ne 0) { return }
      & 'C:\Program Files\nodejs\npx.cmd' playwright test --reporter=list
    } finally {
      Pop-Location
    }
  }
}

# Tear the stack down only after the web stage, so `-WithStack -WithWeb` keeps
# the stack serving while Playwright runs.
if ($WithStack) {
  Step 'stack down (volumes kept)' { & $d compose -f $cf down }
}

Write-Host "`n===== local CI summary =====" -ForegroundColor Cyan
$timings | Format-Table -AutoSize | Out-String | Write-Host
if ($failures.Count -gt 0) {
  Write-Host "FAILED stages: $($failures -join ', ')" -ForegroundColor Red
  exit 1
}
Write-Host 'ALL STAGES GREEN' -ForegroundColor Green
exit 0
