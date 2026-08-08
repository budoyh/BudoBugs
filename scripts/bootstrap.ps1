[CmdletBinding()]
param(
    [switch]$RunDoctor
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Require-Command {
    param([Parameter(Mandatory)][string]$Name)
    if ($null -eq (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command is unavailable: $Name"
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $RepoRoot
try {
    Require-Command uv
    Require-Command pnpm

    & uv sync --frozen --extra dev
    if ($LASTEXITCODE -ne 0) { throw "uv sync failed with exit code $LASTEXITCODE" }

    & pnpm install --frozen-lockfile
    if ($LASTEXITCODE -ne 0) { throw "pnpm install failed with exit code $LASTEXITCODE" }

    & uv run python scripts/verify_skills.py
    if ($LASTEXITCODE -ne 0) { throw "skill verification failed with exit code $LASTEXITCODE" }

    & uv run python scripts/verify_release.py --source
    if ($LASTEXITCODE -ne 0) { throw "release verification failed with exit code $LASTEXITCODE" }

    if ($RunDoctor) {
        $doctorJson = & uv run budo doctor --json
        if ($LASTEXITCODE -ne 0) { throw "tool doctor command failed with exit code $LASTEXITCODE" }
        $doctor = $doctorJson | ConvertFrom-Json
        $doctorJson
        if ($doctor.overall -ne "PASS") { throw "tool doctor did not reach PASS" }
    }
}
finally {
    Pop-Location
}

Write-Output "Project dependencies and local verification are ready."
Write-Output "Run with -RunDoctor to execute tool and runtime health checks."
