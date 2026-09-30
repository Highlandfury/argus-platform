# scripts/dev.ps1 — Windows developer entrypoints (mirrors the Makefile).
# Usage:  .\scripts\dev.ps1 <command>
param(
    [Parameter(Position = 0)]
    [ValidateSet('up', 'dev', 'down', 'reset', 'logs', 'ps', 'build', 'test', 'check', 'vet', 'fmt', 'lint', 'proto', 'tidy', 'versions', 'doctor', 'check-compose', 'install-tools')]
    [string]$Command = 'help'
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

# Dev credentials are never tracked: generate a gitignored .env with random
# values on first use and load it into this session (compose also auto-loads it
# from the project directory). Placeholder fallbacks live in the compose file
# and .env.example for a bare `docker compose up`.
$EnvFile = Join-Path $Root 'deployments\compose\.env'
if (-not (Test-Path $EnvFile)) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $dbBytes = New-Object byte[] 16
    $adminBytes = New-Object byte[] 16
    $rng.GetBytes($dbBytes)
    $rng.GetBytes($adminBytes)
    $dbPw = ($dbBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    $adminPw = ($adminBytes | ForEach-Object { $_.ToString('x2') }) -join ''
    "ARGUS_DEV_DB_PASSWORD=$dbPw`nARGUS_DEV_ADMIN_PASSWORD=$adminPw" |
        Set-Content -Path $EnvFile -Encoding ASCII -NoNewline
    Write-Host "generated dev credentials: deployments\compose\.env (gitignored)"
}
Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^([A-Za-z_][A-Za-z0-9_]*)=(.*)$') {
        Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
    }
}

# Local toolchain first (user-local, gitignored).
$env:GOPATH = Join-Path $Root '.tools\gopath'
$env:GOMODCACHE = Join-Path $Root '.tools\gomodcache'
$env:GOBIN = Join-Path $Root '.tools\bin'
$env:GOTOOLCHAIN = 'local'
$env:PATH = (Join-Path $Root '.tools\go\bin') + ';' + (Join-Path $Root '.tools\bin') + ';' + $env:PATH
$dockerDir = Join-Path ${env:ProgramFiles} 'Docker\Docker\resources\bin'
if (Test-Path $dockerDir) { $env:PATH = "$dockerDir;$env:PATH" }

$Go = Join-Path $Root '.tools\go\bin\go.exe'
if (-not (Test-Path $Go)) { $Go = 'go' }

$ComposeFile = Join-Path $Root 'deployments\compose\docker-compose.dev.yml'
$LdFlags = '-s -w -X github.com/argus-platform/argus/internal/platform/buildinfo.Version=dev -X github.com/argus-platform/argus/internal/platform/buildinfo.Commit=none -X github.com/argus-platform/argus/internal/platform/buildinfo.Date=unknown'

function Invoke-Command([string]$Exe, [string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}

Set-Location $Root

switch ($Command) {
    'help' {
        Write-Host 'Argus dev commands:'
        Write-Host '  .\scripts\dev.ps1 up|down|reset|logs|ps      - local stack lifecycle'
        Write-Host '  .\scripts\dev.ps1 build                      - compile server + collector to bin/'
        Write-Host '  .\scripts\dev.ps1 test|check|vet|fmt         - Go quality gates'
        Write-Host '  .\scripts\dev.ps1 lint|proto                 - golangci-lint / buf (installs into .tools/bin)'
        Write-Host '  .\scripts\dev.ps1 install-tools              - install pinned dev tools'
        Write-Host '  .\scripts\dev.ps1 versions|doctor            - environment info'
    }
    'up' { Invoke-Command 'docker' @('compose', '-f', $ComposeFile, 'up', '--build', '--wait') }
    'dev' { Invoke-Command 'docker' @('compose', '-f', $ComposeFile, 'up', '--build', '--wait') }
    'down' { Invoke-Command 'docker' @('compose', '-f', $ComposeFile, 'down') }
    'reset' { Invoke-Command 'docker' @('compose', '-f', $ComposeFile, 'down', '-v', '--remove-orphans') }
    'logs' { Invoke-Command 'docker' @('compose', '-f', $ComposeFile, 'logs', '-f', '--tail=100') }
    'ps' { Invoke-Command 'docker' @('compose', '-f', $ComposeFile, 'ps') }
    'build' {
        Invoke-Command $Go @('build', '-trimpath', '-ldflags', $LdFlags, '-o', 'bin\argus-server.exe', '.\cmd\argus-server')
        Invoke-Command $Go @('build', '-trimpath', '-ldflags', $LdFlags, '-o', 'bin\argus-collector.exe', '.\cmd\argus-collector')
    }
    'test' { Invoke-Command $Go @('test', './...') }
    'vet' { Invoke-Command $Go @('vet', './...') }
    'fmt' { Invoke-Command $Go @('fmt', './...') }
    'check' {
        Invoke-Command $Go @('vet', './...')
        Invoke-Command $Go @('test', './...')
    }
    'lint' { Invoke-Command (Join-Path $Root '.tools\bin\golangci-lint.exe') @('run') }
    'proto' {
        Invoke-Command (Join-Path $Root '.tools\bin\buf.exe') @('lint')
        Invoke-Command (Join-Path $Root '.tools\bin\buf.exe') @('generate')
    }
    'tidy' { Invoke-Command $Go @('mod', 'tidy') }
    'check-compose' { Invoke-Command 'powershell' @('-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'check-compose.ps1')) }
    'versions' {
        Invoke-Command $Go @('version')
        try { (node --version) } catch { Write-Host 'node: not installed' }
        try { docker compose version } catch { Write-Host 'docker: not installed' }
    }
    'doctor' { Invoke-Command $Go @('run', './cmd/argus-collector', 'doctor') }
    'install-tools' { Invoke-Command 'powershell' @('-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'install-tools.ps1')) }
}
