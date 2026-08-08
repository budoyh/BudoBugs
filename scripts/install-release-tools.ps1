param(
    [ValidateSet("core", "extended", "sqlite", "all")]
    [string]$Profile = "all"
)

$ErrorActionPreference = "Stop"
$installRoot = [System.IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA "budobugs\budobugs"))
$binDir = Join-Path $installRoot "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null

$assets = @(
    [pscustomobject]@{ Profile = "core"; Repo = "jqlang/jq"; Tag = "jq-1.8.2"; Asset = "jq-windows-amd64.exe"; Hash = "a6fc67fedaf9128a3309a1e2ebb8b986aeccf70122ee46d2cb4849e423f0c627"; Exe = "jq-windows-amd64.exe"; Dest = "jq.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "mikefarah/yq"; Tag = "v4.53.3"; Asset = "yq_windows_amd64.exe"; Hash = "e279bc506a452eeafcdf364f91a025455e402a8001169083caf01f4b64a544e2"; Exe = "yq_windows_amd64.exe"; Dest = "yq.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "sharkdp/fd"; Tag = "v10.4.2"; Asset = "fd-v10.4.2-x86_64-pc-windows-msvc.zip"; Hash = "b2816e506390a89941c63c9187d58a3cc10e9a55f2ef0685f9ea0eccaf7c98c8"; Exe = "fd.exe"; Dest = "fd.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "epi052/feroxbuster"; Tag = "v2.13.1"; Asset = "x86_64-windows-feroxbuster.exe.zip"; Hash = "6255fc1998220833d22b221e5c740895ada2a5fbaf31587e799276c59da7dab2"; Exe = "feroxbuster.exe"; Dest = "feroxbuster.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "gitleaks/gitleaks"; Tag = "v8.30.1"; Asset = "gitleaks_8.30.1_windows_x64.zip"; Hash = "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e"; Exe = "gitleaks.exe"; Dest = "gitleaks.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "hahwul/dalfox"; Tag = "v3.2.0"; Asset = "dalfox-v3.2.0-windows-x86_64.zip"; Hash = "04d74c5277df02ad6aa2c969bc33fc9673ff50ca87ee9adc47f4a74e929f43ae"; Exe = "dalfox.exe"; Dest = "dalfox.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "aquasecurity/trivy"; Tag = "v0.73.0"; Asset = "trivy_0.73.0_windows-64bit.zip"; Hash = "d2d3ad5292aae470a03eb6506db86fce81b1894592b8451cadaf60eaa22f2025"; Exe = "trivy.exe"; Dest = "trivy.exe" },
    [pscustomobject]@{ Profile = "core"; Repo = "google/osv-scanner"; Tag = "v2.5.0"; Asset = "osv-scanner_windows_amd64.exe"; Hash = "4342285bd8be36b9f113468f3eea86e7900befbcd19ca8dc6ac4f0f6cbe7c362"; Exe = "osv-scanner_windows_amd64.exe"; Dest = "osv-scanner.exe" },
    [pscustomobject]@{ Profile = "extended"; Repo = "anchore/syft"; Tag = "v1.50.0"; Asset = "syft_1.50.0_windows_amd64.zip"; Hash = "815ee6973ec5dff6a671d7f41b0e78835a8c45b91d5a39f4743ea1cee833d3be"; Exe = "syft.exe"; Dest = "syft.exe" },
    [pscustomobject]@{ Profile = "extended"; Repo = "anchore/grype"; Tag = "v0.116.1"; Asset = "grype_0.116.1_windows_amd64.zip"; Hash = "a8ad864f2f06c9afcc90d417f46f5587adeaba4e1e46cc4e32a6a076dae2fda7"; Exe = "grype.exe"; Dest = "grype.exe" }
)

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw "GitHub CLI (gh) is required for checksum-bound release downloads."
}

$tempRoot = [System.IO.Path]::GetFullPath((Join-Path $env:TEMP ("budobugs-release-" + [guid]::NewGuid().ToString("N"))))
New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    foreach ($item in $assets) {
        if ($Profile -eq "sqlite" -or ($Profile -ne "all" -and $item.Profile -ne $Profile)) {
            continue
        }
        $assetDir = Join-Path $tempRoot (($item.Repo -replace "/", "-") + "-" + $item.Tag)
        New-Item -ItemType Directory -Path $assetDir | Out-Null
        & gh release download $item.Tag --repo $item.Repo --pattern $item.Asset --dir $assetDir
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed: $($item.Repo) $($item.Asset)"
        }
        $download = Join-Path $assetDir $item.Asset
        $actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $item.Hash) {
            throw "Checksum mismatch for $($item.Asset): $actual"
        }
        if ([System.IO.Path]::GetExtension($download) -eq ".zip") {
            $expanded = Join-Path $assetDir "expanded"
            Expand-Archive -LiteralPath $download -DestinationPath $expanded
            $source = Get-ChildItem -LiteralPath $expanded -Recurse -File |
                Where-Object Name -eq $item.Exe |
                Select-Object -First 1
            if ($null -eq $source) {
                throw "Executable $($item.Exe) was not present in $($item.Asset)."
            }
            Copy-Item -LiteralPath $source.FullName -Destination (Join-Path $binDir $item.Dest) -Force
        }
        else {
            Copy-Item -LiteralPath $download -Destination (Join-Path $binDir $item.Dest) -Force
        }
        Write-Output ("PASS {0} {1} sha256:{2}" -f $item.Dest, $item.Tag, $actual)
    }
    if ($Profile -in @("core", "sqlite", "all")) {
        $sqliteAsset = "sqlite-tools-win-x64-3530400.zip"
        $sqliteDownload = Join-Path $tempRoot $sqliteAsset
        & curl.exe --fail --location --silent --show-error --output $sqliteDownload "https://www.sqlite.org/2026/$sqliteAsset"
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed: SQLite $sqliteAsset"
        }
        $repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
        $pythonExe = Join-Path $repoRoot ".venv\Scripts\python.exe"
        if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
            $pythonExe = (Get-Command python -ErrorAction Stop).Source
        }
        $sqliteHashOutput = & $pythonExe -c "import hashlib, pathlib, sys; print(hashlib.sha3_256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())" $sqliteDownload
        if ($LASTEXITCODE -ne 0 -or -not $sqliteHashOutput) {
            throw "Could not calculate SQLite SHA3-256."
        }
        $sqliteHash = $sqliteHashOutput.Trim()
        $sqliteExpected = "88b4659fe747896b853af10157316b4ade143553efb89c1c8ca7423a278dcc8b"
        if ($sqliteHash -ne $sqliteExpected) {
            throw "SHA3-256 mismatch for ${sqliteAsset}: $sqliteHash"
        }
        $sqliteExpanded = Join-Path $tempRoot "sqlite-expanded"
        Expand-Archive -LiteralPath $sqliteDownload -DestinationPath $sqliteExpanded
        $sqliteExe = Get-ChildItem -LiteralPath $sqliteExpanded -Recurse -File |
            Where-Object Name -eq "sqlite3.exe" |
            Select-Object -First 1
        if ($null -eq $sqliteExe) {
            throw "sqlite3.exe was not present in $sqliteAsset."
        }
        Copy-Item -LiteralPath $sqliteExe.FullName -Destination (Join-Path $binDir "sqlite3.exe") -Force
        Write-Output "PASS sqlite3.exe 3.53.4 sha3-256:$sqliteHash"
    }
}
finally {
    $tempBase = [System.IO.Path]::GetFullPath($env:TEMP).TrimEnd("\") + "\"
    $safeName = [System.IO.Path]::GetFileName($tempRoot).StartsWith("budobugs-release-")
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
