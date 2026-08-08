param(
    [string]$Distro = "BudoBugs-Ubuntu-24.04"
)

$ErrorActionPreference = "Stop"
$dataRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "budobugs\budobugs"))
$runtimeRoot = Join-Path $dataRoot "runtimes\wsl-ubuntu-24.04"
$downloadRoot = Join-Path $dataRoot "downloads"
New-Item -ItemType Directory -Force -Path $runtimeRoot, $downloadRoot | Out-Null

$existingBytes = & wsl.exe --list --quiet 2>$null
$existingText = if ($existingBytes -is [byte[]]) {
    [System.Text.Encoding]::Unicode.GetString($existingBytes)
}
else {
    ($existingBytes -join "`n")
}

if ($existingText -notmatch [regex]::Escape($Distro)) {
    $assetName = "ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz"
    $assetPath = Join-Path $downloadRoot $assetName
    & curl.exe --fail --location --silent --show-error --retry 8 --retry-all-errors --retry-delay 3 --output $assetPath "https://cloud-images.ubuntu.com/wsl/releases/noble/current/$assetName"
    if ($LASTEXITCODE -ne 0) {
        throw "Ubuntu WSL rootfs download failed."
    }
    $actual = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expected = "8251e27ffff381a4af5f41dcb94d867de3e0d9774a9241908ab34555d99315ea"
    if ($actual -ne $expected) {
        throw "Ubuntu WSL rootfs checksum mismatch: $actual"
    }
    & wsl.exe --import $Distro $runtimeRoot $assetPath --version 2
    if ($LASTEXITCODE -ne 0) {
        throw "WSL import failed."
    }
    Remove-Item -LiteralPath $assetPath -Force
    Write-Output "PASS imported $Distro sha256:$actual"
}
else {
    Write-Output "PASS existing $Distro"
}

& wsl.exe -d $Distro -u root -- bash -lc "set -euo pipefail; export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get install -y ca-certificates curl git jq python3 python3-pip python3-venv docker.io docker-compose-v2; docker --version; docker compose version; python3 --version"
if ($LASTEXITCODE -ne 0) {
    throw "WSL runtime package installation failed."
}
Write-Output "PASS WSL runtime packages"
