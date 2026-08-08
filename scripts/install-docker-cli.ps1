$ErrorActionPreference = "Stop"

$installRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "budobugs\budobugs"))
$binDir = Join-Path $installRoot "bin"
$pluginDir = Join-Path $env:USERPROFILE ".docker\cli-plugins"
New-Item -ItemType Directory -Force -Path $binDir, $pluginDir | Out-Null

$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $env:TEMP ("budobugs-docker-cli-" + [guid]::NewGuid().ToString("N"))))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    $dockerSource = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Links\docker.exe"
    $dockerAssetHash = "installed-by-winget"
    $wingetValidated = Test-Path -LiteralPath $dockerSource -PathType Leaf
    if (-not $wingetValidated) {
        $dockerAsset = Join-Path $tempRoot "docker-29.7.2.zip"
        & curl.exe --fail --location --silent --show-error --retry 5 --retry-all-errors --retry-delay 2 --output $dockerAsset "https://download.docker.com/win/static/stable/x86_64/docker-29.7.2.zip"
        if ($LASTEXITCODE -ne 0) {
            throw "Docker CLI download failed."
        }
        $dockerExpanded = Join-Path $tempRoot "docker"
        Expand-Archive -LiteralPath $dockerAsset -DestinationPath $dockerExpanded
        $dockerExe = Get-ChildItem -LiteralPath $dockerExpanded -Recurse -File |
            Where-Object Name -eq "docker.exe" |
            Select-Object -First 1
        if ($null -eq $dockerExe) {
            throw "docker.exe was not present in the official static archive."
        }
        $dockerSource = $dockerExe.FullName
        $dockerAssetHash = (Get-FileHash -LiteralPath $dockerAsset -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $dockerVersion = (& $dockerSource --version) -join " "
    if ($LASTEXITCODE -ne 0 -or $dockerVersion -notmatch "29\.7\.2") {
        throw "Unexpected Docker CLI version: $dockerVersion"
    }
    if (-not $wingetValidated) {
        throw "Direct Docker CLI archives do not publish an in-band checksum; install Docker.DockerCLI 29.7.2 with winget first."
    }
    Copy-Item -LiteralPath $dockerSource -Destination (Join-Path $binDir "docker.exe") -Force
    Write-Output "PASS docker.exe 29.7.2 source=winget-hash-verified archive-sha256:$dockerAssetHash"

    $composeAssetName = "docker-compose-windows-x86_64.exe"
    & gh release download "v5.4.0" --repo "docker/compose" --pattern $composeAssetName --dir $tempRoot
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Compose download failed."
    }
    $composeAsset = Join-Path $tempRoot $composeAssetName
    $composeHash = (Get-FileHash -LiteralPath $composeAsset -Algorithm SHA256).Hash.ToLowerInvariant()
    $composeExpected = "d51bc731b3ff6f062a26e8fdfd391ae98aeab516432f097c66d39c1c9d06680e"
    if ($composeHash -ne $composeExpected) {
        throw "Docker Compose checksum mismatch: $composeHash"
    }
    Copy-Item -LiteralPath $composeAsset -Destination (Join-Path $pluginDir "docker-compose.exe") -Force
    Write-Output "PASS docker-compose.exe v5.4.0 sha256:$composeHash"
}
finally {
    $tempBase = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd("\") + "\"
    $safeName = [System.IO.Path]::GetFileName($tempRoot).StartsWith("budobugs-docker-cli-")
    if ($tempRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and $safeName) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

$pathParts = [Environment]::GetEnvironmentVariable("Path", "User") -split ";"
if ($pathParts -notcontains $binDir) {
    $newPath = (($pathParts | Where-Object { $_ }) + $binDir) -join ";"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}
Write-Output "BIN $binDir"
