[CmdletBinding()]
param(
    [ValidateSet("install", "up", "down", "status", "validate")]
    [string]$Action = "status",
    [string]$Target = "http://127.0.0.1:8765/healthz"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
& uv run --project $ProjectRoot python (Join-Path $PSScriptRoot "hexstrike_lab_ai.py") $Action --target $Target
exit $LASTEXITCODE
