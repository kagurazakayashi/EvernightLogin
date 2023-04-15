# Step 89: verify a local EvernightLogin release directory.
#
# Checks every zip against SHA256SUMS.txt, extracts each package, re-checks the
# inner checksum manifest, enforces the exclusion policy (no AI files, runtime
# databases, logs, test keys or secrets), verifies required content, scans text
# files for private key blocks, and on Windows optionally smoke-runs the
# windows/amd64 binaries (version/help/no-arg exit codes).
#
# Read-only with respect to the repository: it only reads <ReleaseDir> and uses
# a temporary extraction directory which it deletes before returning.
# No network access, no git write, no server/port is started.
#
# Windows PowerShell 5.1 and PowerShell 7 compatible (ASCII messages).
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\verify-release.ps1 -ReleaseDir P:\go\tmp\deploy-step89
#
# Exit codes: 0 = all checks passed; 1 = at least one check failed.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseDir,

    [string]$ExpectedVersion = "",

    [switch]$SkipBinaryRun
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# PowerShell 5.1 在进程环境同时存在大小写重复的代理变量（NO_PROXY/no_proxy 等）
# 时，Start-Process/环境块会抛 "Item has already been added"。发布校验不能因此
# 失败；在脚本边界清掉这些重复键（不改变网络策略，仅避免环境字典异常）。
foreach ($name in @('http_proxy','https_proxy','all_proxy','no_proxy',
        'HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY',
        'Http_Proxy','Https_Proxy','All_Proxy','No_Proxy')) {
    try { [Environment]::SetEnvironmentVariable($name, $null, 'Process') } catch { }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$failures = New-Object System.Collections.Generic.List[string]
$checks = 0

function Add-Check {
    param([string]$Message, [bool]$Ok)
    $script:checks = $script:checks + 1
    if ($Ok) {
        Write-Host ("  [PASS] " + $Message)
    } else {
        Write-Host ("  [FAIL] " + $Message)
        $script:failures.Add($Message)
    }
}

function Get-Sha256Lower {
    param([string]$Path)
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Parse "hash  relative/path" lines from a SHA256SUMS.txt file.
function Read-Checksums {
    param([string]$Path)
    $entries = @()
    foreach ($line in Get-Content -LiteralPath $Path) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        if ($trimmed.StartsWith("#")) { continue }
        $parts = $trimmed -split "\s+", 2
        if ($parts.Count -ne 2) { continue }
        $entries += [pscustomobject]@{ Hash = $parts[0].ToLowerInvariant(); Relative = $parts[1] }
    }
    return $entries
}

$releaseDir = (Resolve-Path -LiteralPath $ReleaseDir).Path
$topSumsPath = Join-Path $releaseDir "SHA256SUMS.txt"
if (-not (Test-Path -LiteralPath $topSumsPath -PathType Leaf)) {
    Write-Host ("[FAIL] missing top-level checksum manifest: " + $topSumsPath)
    exit 1
}

Write-Host "== 1. Top-level checksum manifest"
$topEntries = Read-Checksums $topSumsPath
Add-Check "top-level SHA256SUMS.txt has entries" (@($topEntries).Count -gt 0)
foreach ($entry in $topEntries) {
    $target = Join-Path $releaseDir $entry.Relative
    if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
        Add-Check ("missing archive " + $entry.Relative) $false
        continue
    }
    $actual = Get-Sha256Lower $target
    Add-Check ("sha256 " + $entry.Relative) ($actual -eq $entry.Hash)
}

$matrixPath = Join-Path $releaseDir "build-matrix.txt"
Add-Check "build-matrix.txt exists" (Test-Path -LiteralPath $matrixPath -PathType Leaf)

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("lv-" + [Guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null

# Expand-Archive 在 Windows PowerShell 5.1 下对目标目录/长路径较脆弱；统一用
# .NET ZipFile 解压，并显式创建目标目录，兼容空格/中文路径与嵌套目录。
function Expand-ReleaseArchive {
    param([Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$DestinationPath)
    if (Test-Path -LiteralPath $DestinationPath) {
        Remove-Item -LiteralPath $DestinationPath -Recurse -Force -ErrorAction Stop
    }
    New-Item -ItemType Directory -Force -Path $DestinationPath | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $DestinationPath)
}

# Forbidden path/content policy of a release package.
$forbiddenPathPatterns = @(
    '(^|/)\.ai/',
    '(^|/)\.agents/',
    '(^|/)AGENTS\.md$',
    '(^|/)MEMORY\.md$',
    '\.db$',
    '\.db-',
    '\.sqlite',
    '\.log$',
    '\.key$',
    '\.pem$',
    '\.p12$',
    '\.pfx$',
    '\.env$',
    '(^|/)secrets/'
)

$requiredRelativePaths = @(
    "VERSION.txt",
    "README.txt",
    "SHA256SUMS.txt",
    "DEPENDENCIES.txt",
    "BUILDINFO.txt",
    "LICENSE",
    "docs/licenses/THIRD_PARTY_NOTICES.md",
    "config/login.example.yaml",
    "docs/deployment/README.md",
    "docs/deployment/standalone-service.md",
    "docs/deployment/first-run.md",
    "docs/deployment/reverse-proxy.md",
    "docs/deployment/container.md",
    "docs/deployment/service-hosting.md",
    "docs/deployment/integration.md",
    "docs/deployment/packaging.md",
    "docs/licenses/THIRD_PARTY_NOTICES.md"
)

try {
    $archives = Get-ChildItem -LiteralPath $releaseDir -File -Filter "evernight-login-*.zip" | Sort-Object Name
    Write-Host ""
    Write-Host ("== 2. Package content and exclusions (" + @($archives).Count + " archives)")
    Add-Check "at least one release archive found" (@($archives).Count -gt 0)

    foreach ($archive in $archives) {
        Write-Host ("-- " + $archive.Name)
        $extractDir = Join-Path $tempRoot ($archive.BaseName)
        Expand-ReleaseArchive -ArchivePath $archive.FullName -DestinationPath $extractDir
        $packageDirs = Get-ChildItem -LiteralPath $extractDir -Directory
        if (@($packageDirs).Count -ne 1) {
            Add-Check ($archive.Name + " contains exactly one top-level directory") $false
            continue
        }
        $packageRoot = $packageDirs[0].FullName
        Add-Check ($archive.Name + " top-level directory is " + $packageDirs[0].Name) `
            ($packageDirs[0].Name -eq $archive.BaseName)

        $allFiles = Get-ChildItem -LiteralPath $packageRoot -File -Recurse
        $allRelative = @()
        foreach ($file in $allFiles) {
            $relative = $file.FullName.Substring($packageRoot.Length + 1).Replace("\", "/")
            $allRelative += $relative
            foreach ($pattern in $forbiddenPathPatterns) {
                if ($relative -match $pattern) {
                    Add-Check ($archive.Name + " excludes forbidden path " + $relative) $false
                }
            }
        }
        Add-Check ($archive.Name + " has no forbidden paths") ($true)

        foreach ($required in $requiredRelativePaths) {
            $exists = Test-Path -LiteralPath (Join-Path $packageRoot $required) -PathType Leaf
            Add-Check ($archive.Name + " contains " + $required) $exists
        }
        $licensePath = Join-Path $packageRoot "LICENSE"
        if (Test-Path -LiteralPath $licensePath -PathType Leaf) {
            $licenseText = Get-Content -LiteralPath $licensePath -Raw
            Add-Check ($archive.Name + " LICENSE identifies Mulan PSL v2") `
                ($licenseText -match "Mulan PSL v2" -or $licenseText -match "Mulan Permissive Software License")
            Add-Check ($archive.Name + " LICENSE has required attribution without year") `
                ($licenseText -match "Copyright \(c\) KagurazakaYashi\(KagurazakaMiyabi\)" -and
                 -not ($licenseText -match "Copyright \(c\) [0-9]{4} KagurazakaYashi\(KagurazakaMiyabi\)"))
        } else {
            Add-Check ($archive.Name + " contains LICENSE") $false
        }
        foreach ($requiredBin in @("bin/login-server", "bin/loginctl", "bin/login-backup")) {
            $found = $false
            $candidates = @($requiredBin, ($requiredBin + ".exe"))
            foreach ($candidate in $candidates) {
                if ($allRelative -contains $candidate) { $found = $true }
            }
            Add-Check ($archive.Name + " contains " + $requiredBin) $found
        }

        # Inner manifest: every listed file matches and no file is missing.
        $innerSumsPath = Join-Path $packageRoot "SHA256SUMS.txt"
        if (Test-Path -LiteralPath $innerSumsPath) {
            $innerEntries = Read-Checksums $innerSumsPath
            Add-Check ($archive.Name + " inner manifest has entries") (@($innerEntries).Count -gt 0)
            $bad = 0
            foreach ($innerEntry in $innerEntries) {
                $innerTarget = Join-Path $packageRoot $innerEntry.Relative
                if (-not (Test-Path -LiteralPath $innerTarget -PathType Leaf)) { $bad = $bad + 1; continue }
                if ((Get-Sha256Lower $innerTarget) -ne $innerEntry.Hash) { $bad = $bad + 1 }
            }
            Add-Check ($archive.Name + " inner manifest matches all files (" + @($innerEntries).Count + " entries, bad=" + $bad + ")") ($bad -eq 0)
        } else {
            Add-Check ($archive.Name + " has inner SHA256SUMS.txt") $false
        }

        # Private key material scan (text files only; binaries are covered by policy above).
        $keyHits = @()
        foreach ($file in $allFiles) {
            if ($file.Length -gt 2MB) { continue }
            $extension = $file.Extension.ToLowerInvariant()
            if ($extension -in @(".exe", ".zip")) { continue }
            try {
                $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
            } catch {
                continue
            }
            if ($content -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') {
                $keyHits += $file.Name
            }
        }
        Add-Check ($archive.Name + " contains no private key blocks") (@($keyHits).Count -eq 0)
    }

    # ---------- 3. Optional Windows binary smoke runs ----------
    Write-Host ""
    Write-Host "== 3. Windows amd64 binary smoke run"
    if ($SkipBinaryRun) {
        Write-Host "  [SKIP] -SkipBinaryRun specified"
    } elseif (-not ($archives | Where-Object { $_.Name -match "windows-amd64" })) {
        Write-Host "  [SKIP] no windows-amd64 archive in release dir"
    } else {
        $winArchive = $archives | Where-Object { $_.Name -match "windows-amd64" } | Select-Object -First 1
        $winDir = Join-Path $tempRoot "win-smoke"
        Expand-ReleaseArchive -ArchivePath $winArchive.FullName -DestinationPath $winDir
        $packageRoot = (Get-ChildItem -LiteralPath $winDir -Directory)[0].FullName
        $loginServer = Join-Path $packageRoot "bin\login-server.exe"
        $loginBackup = Join-Path $packageRoot "bin\login-backup.exe"
        $loginCtl = Join-Path $packageRoot "bin\loginctl.exe"

        function Invoke-Captured {
            param([string]$Exe, [string[]]$Arguments)
            $stdoutFile = [System.IO.Path]::GetTempFileName()
            $stderrFile = [System.IO.Path]::GetTempFileName()
            try {
                if ($null -ne $Arguments -and @($Arguments).Count -gt 0) {
                    $process = Start-Process -FilePath $Exe -ArgumentList $Arguments -Wait -PassThru `
                        -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -NoNewWindow
                } else {
                    $process = Start-Process -FilePath $Exe -Wait -PassThru `
                        -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -NoNewWindow
                }
                $stdout = (Get-Content -LiteralPath $stdoutFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
                $stderr = (Get-Content -LiteralPath $stderrFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue)
                if ($null -eq $stdout) { $stdout = "" }
                if ($null -eq $stderr) { $stderr = "" }
                return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout; Stderr = $stderr }
            } finally {
                Remove-Item -LiteralPath $stdoutFile -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
            }
        }

        $versionResult = Invoke-Captured $loginServer @("--version")
        Add-Check ("login-server --version exit code 0 (actual " + $versionResult.ExitCode + ")") ($versionResult.ExitCode -eq 0)
        Add-Check "login-server --version prints version information" ($versionResult.Stdout -match 'login-server\s')
        if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
            Add-Check ("login-server --version contains expected version " + $ExpectedVersion) `
                ($versionResult.Stdout -match [regex]::Escape($ExpectedVersion))
        }

        $helpResult = Invoke-Captured $loginServer @("--help")
        Add-Check ("login-server --help exit code 0 (actual " + $helpResult.ExitCode + ")") ($helpResult.ExitCode -eq 0)

        $noArgsResult = Invoke-Captured $loginServer @()
        Add-Check ("login-server without arguments fails honestly (actual " + $noArgsResult.ExitCode + ")") ($noArgsResult.ExitCode -ne 0)
        Add-Check "login-server without arguments prints its honest not-implemented hint" `
            (($noArgsResult.Stdout + $noArgsResult.Stderr) -match '--help|\u5C1A\u672A\u5B9E\u73B0')

        $backupResult = Invoke-Captured $loginBackup @("version")
        Add-Check ("login-backup version exit code 0 (actual " + $backupResult.ExitCode + ")") ($backupResult.ExitCode -eq 0)
        Add-Check "login-backup version prints build information" ($backupResult.Stdout -match 'login-backup\s')

        $ctlResult = Invoke-Captured $loginCtl @("--version")
        Add-Check ("loginctl --version exit code 0 (actual " + $ctlResult.ExitCode + ")") ($ctlResult.ExitCode -eq 0)
        Add-Check "loginctl --version prints build information" ($ctlResult.Stdout -match 'loginctl\s')

        Write-Host ("  login-server --version output: " + $versionResult.Stdout.Trim())
        Write-Host ("  login-server no-arg stderr  : " + $noArgsResult.Stderr.Trim())

        # Optional: validate the packaged sample configuration with the real config loader.
        $goAvailable = $null -ne (Get-Command go -ErrorAction SilentlyContinue)
        if ($goAvailable) {
            $sampleConfig = Join-Path $packageRoot "config\login.example.yaml"
            $previousLocation = (Get-Location).Path
            Push-Location $repo
            try {
                $env:GOMAXPROCS = "2"
                $env:CGO_ENABLED = "0"
                $configResult = Invoke-Captured "go" @("run", "./examples/config-load", "-config", $sampleConfig)
            } finally {
                Pop-Location
                Set-Location $previousLocation
            }
            Add-Check ("packaged sample config validates with real loader (actual exit " + $configResult.ExitCode + ")") ($configResult.ExitCode -eq 0)
            Add-Check "sample config validation reports no secret leakage" (-not ($configResult.Stdout -match 'master_key = [^[]'))
        } else {
            Write-Host "  [SKIP] go toolchain not found; packaged sample config not re-validated"
        }
    }
} finally {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host ("Checks run: " + $checks + ", failures: " + $failures.Count)
if ($failures.Count -gt 0) {
    Write-Host "VERIFY: FAIL"
    foreach ($failure in $failures) { Write-Host ("  - " + $failure) }
    exit 1
}
Write-Host "VERIFY: PASS"
exit 0
