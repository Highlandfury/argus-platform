# scripts/check-compose.ps1 — regression check: PostgreSQL 18 image volume layout.
#
# The official PostgreSQL 18 images set PGDATA=/var/lib/postgresql/18/docker and declare
# /var/lib/postgresql as the image volume target. Mounting a volume at the pre-18 path
# /var/lib/postgresql/data makes the PG18 entrypoint treat the mount as foreign data and
# refuse to start. This check makes that mistake impossible to merge silently.
#
# Used by: .\scripts\dev.ps1 check-compose  and CI (compose-smoke job, bash equivalent).

$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$ComposeFile = Join-Path $Root 'deployments\compose\docker-compose.dev.yml'

$Docker = 'docker'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    $candidate = Join-Path ${env:ProgramFiles} 'Docker\Docker\resources\bin\docker.exe'
    if (Test-Path $candidate) { $Docker = $candidate }
    else { throw 'docker CLI not found; install Docker Desktop or add it to PATH' }
}

$json = (& $Docker compose -f $ComposeFile config --format json) -join "`n"
if ($LASTEXITCODE -ne 0) { throw 'docker compose config failed' }

$targets = [regex]::Matches($json, '"target"\s*:\s*"([^"]+)"') |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique

$targets | ForEach-Object { Write-Host "volume target: $_" }

if ($targets -notcontains '/var/lib/postgresql') {
    throw "db volume must mount /var/lib/postgresql (PostgreSQL 18 image layout); got: $($targets -join ', ')"
}
if ($targets -contains '/var/lib/postgresql/data') {
    throw 'PG17-style mount /var/lib/postgresql/data detected; PostgreSQL 18 images reject it'
}
if ($targets -contains '/docker-entrypoint-initdb.d') {
    throw 'directory mount over /docker-entrypoint-initdb.d detected; it hides the image''s own init scripts (TimescaleDB extension install/tune). Mount init scripts as files instead.'
}

Write-Host 'compose volume layout OK (PG18 data dir + safe init mounts)'
