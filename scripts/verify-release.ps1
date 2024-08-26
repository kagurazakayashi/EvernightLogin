# verify-release.ps1 - Step 248 release package verifier.
#
# Verifies a local release directory produced by scripts/package-release.ps1:
# - top-level file set (12 zips + SHA256SUMS.txt + build-matrix.txt +
#   release-summary.json + RELEASE-NOTES.md);
# - top-level SHA-256/manifest and build-matrix consistency;
# - RELEASE-NOTES.md four required headings (completed/failed/unimplemented/
#   untested in Chinese), version and source commits;
# - every zip: inner SHA256SUMS.txt (GNU format, LF, sorted, no self entry),
#   exact file set, forbidden-path scan, required license/metadata files,
#   product docs for login packages (docs/README, guide, deployment, embedding,
#   database, requirements, licenses; reference when produced by step 245);
# - binary magic/arch (PE/ELF/Mach-O) and size/sha256 against build-summary v1;
# - Windows/amd64 short smoke: login-server/loginctl/login-backup/evernightmail
#   version commands only (no serve, no init, no port).
#
# Read-only, no network/git writes, temporary extraction dir always removed.
# The forbidden-path rule must stay in sync with scripts/package-release.ps1:
# docs/database is product documentation, acceptance/evidence are never packaged.
# Exit codes: 0 ok; 10 release/prereq structure invalid; 20 build-summary invalid;
# 21 zip/extract/file-set/forbidden; 22 checksum mismatch; 30 license/metadata/
# docs/release-notes; 31 binary type/arch/smoke; 40 internal error.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseDir,
    [string]$BuildSummary = "",
    [string]$ExpectedVersion = "",
    [switch]$SkipBinaryRun
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$Targets = @("windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64")
$RequiredTop = @("SHA256SUMS.txt", "build-matrix.txt", "release-summary.json", "RELEASE-NOTES.md")

function Fail([int]$Code, [string]$Message) {
    Write-Host ("VERIFY: FAIL [" + $Code + "] " + $Message)
    exit $Code
}
function Get-Sha256Lower([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace "-", "").ToLowerInvariant() }
        finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}
function Read-ChecksumLines([string]$Path) {
    $result = New-Object System.Collections.Generic.List[object]
    $lineNumber = 0
    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $lineNumber = $lineNumber + 1
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith("#")) { continue }
        if ($line -notmatch '^([0-9a-fA-F]{64})  (.+)$') { Fail 22 "invalid checksum line ${lineNumber} in $Path" }
        $result.Add([pscustomobject]@{ Hash = $Matches[1].ToLowerInvariant(); Relative = $Matches[2] })
    }
    return $result
}
function Assert-SortedOrdinal([object[]]$Items, [string]$Path) {
    $last = $null
    foreach ($item in $Items) {
        if ($null -ne $last -and [string]::CompareOrdinal($last, $item.Relative) -gt 0) {
            Fail 22 "checksum entries are not ordinal-sorted in $Path"
        }
        $last = $item.Relative
    }
}
function Get-BinaryInfo([string]$Path) {
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $buffer = New-Object byte[] 4096
        $read = $stream.Read($buffer, 0, $buffer.Length)
        if ($read -lt 64) { return $null }
        if ($buffer[0] -eq 0x4D -and $buffer[1] -eq 0x5A) { # MZ
            $peOffset = [System.BitConverter]::ToInt32($buffer, 0x3C)
            if ($peOffset -lt 0 -or $peOffset + 6 -ge $read) { return $null }
            if ($buffer[$peOffset] -ne 0x50 -or $buffer[$peOffset + 1] -ne 0x45 -or
                $buffer[$peOffset + 2] -ne 0 -or $buffer[$peOffset + 3] -ne 0) { return $null }
            $machine = [System.BitConverter]::ToUInt16($buffer, $peOffset + 4)
            if ($machine -eq 0x8664) { return [pscustomobject]@{ Type = "PE"; Arch = "amd64" } }
            if ($machine -eq 0xAA64) { return [pscustomobject]@{ Type = "PE"; Arch = "arm64" } }
            return $null
        }
        if ($buffer[0] -eq 0x7F -and $buffer[1] -eq 0x45 -and $buffer[2] -eq 0x4C -and $buffer[3] -eq 0x46) {
            if ($buffer[4] -ne 2) { return $null }
            $machine = [System.BitConverter]::ToUInt16($buffer, 18)
            if ($machine -eq 0x3E) { return [pscustomobject]@{ Type = "ELF"; Arch = "amd64" } }
            if ($machine -eq 0xB7) { return [pscustomobject]@{ Type = "ELF"; Arch = "arm64" } }
            return $null
        }
        if ($buffer[0] -eq 0xCF -and $buffer[1] -eq 0xFA -and $buffer[2] -eq 0xED -and $buffer[3] -eq 0xFE) {
            $cpu = [System.BitConverter]::ToInt32($buffer, 4)
            if ($cpu -eq 0x01000007) { return [pscustomobject]@{ Type = "Mach-O"; Arch = "amd64" } }
            if ($cpu -eq 0x0100000C) { return [pscustomobject]@{ Type = "Mach-O"; Arch = "arm64" } }
            return $null
        }
        return $null
    } finally { $stream.Dispose() }
}
function Invoke-Captured([string]$Exe, [string[]]$Arguments, [int]$TimeoutMs = 15000) {
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Exe
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true
    $startInfo.Arguments = (@($Arguments) -join " ")
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $null = $process.Start()
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($TimeoutMs)) {
        try { $process.Kill() } catch { }
        return [pscustomobject]@{ ExitCode = -1; Stdout = ""; Stderr = "timeout" }
    }
    $process.WaitForExit()
    return [pscustomobject]@{
        ExitCode = $process.ExitCode
        Stdout = $stdoutTask.Result
        Stderr = $stderrTask.Result
    }
}

$tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("step202-verify-" + [guid]::NewGuid().ToString("N"))
try {
    if (-not (Test-Path -LiteralPath $ReleaseDir -PathType Container)) { Fail 10 "release dir not found: $ReleaseDir" }
    $ReleaseDir = (Resolve-Path -LiteralPath $ReleaseDir).Path
    $summaryPath = Join-Path $ReleaseDir "release-summary.json"
    if (-not (Test-Path -LiteralPath $summaryPath -PathType Leaf)) { Fail 10 "release-summary.json missing" }
    try { $release = Get-Content -LiteralPath $summaryPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Fail 10 "release-summary.json is not valid JSON" }
    if ([int]$release.format -ne 1) { Fail 10 "release-summary format != 1" }
    if ([string]::IsNullOrWhiteSpace($ExpectedVersion)) { $ExpectedVersion = [string]$release.version }
    if ([string]$release.version -ne $ExpectedVersion) { Fail 10 "release version mismatch" }

    $zips = @($release.zips)
    if ($zips.Count -ne 12) { Fail 10 "release-summary zips count != 12" }
    foreach ($required in $RequiredTop) {
        if (-not (Test-Path -LiteralPath (Join-Path $ReleaseDir $required) -PathType Leaf)) { Fail 10 "top-level file missing: $required" }
    }
    # Step 248 release notes: four separated sections + traceable metadata.
    $notesPath = Join-Path $ReleaseDir "RELEASE-NOTES.md"
    $notesText = [System.IO.File]::ReadAllText($notesPath)
    $requiredHeadings = @(
        ("$([char]0x5DF2)$([char]0x5B8C)$([char]0x6210)"),
        ("$([char]0x5931)$([char]0x8D25)"),
        ("$([char]0x672A)$([char]0x5B9E)$([char]0x73B0)"),
        ("$([char]0x672A)$([char]0x6D4B)")
    )
    foreach ($heading in $requiredHeadings) {
        $pattern = '(?m)^##\s+(?:\d+\.\s*)?' + [regex]::Escape($heading)
        if ($notesText -notmatch $pattern) {
            Fail 30 ("RELEASE-NOTES.md missing required section: " + $heading)
        }
    }
    if ($notesText.IndexOf($ExpectedVersion, [System.StringComparison]::Ordinal) -lt 0) {
        Fail 30 "RELEASE-NOTES.md lacks expected version: $ExpectedVersion"
    }
    $sourceCommits = $release.source_commits
    foreach ($commitField in @([string]$sourceCommits.login, [string]$sourceCommits.mail,
        [string]$sourceCommits.tool)) {
        if ([string]::IsNullOrWhiteSpace($commitField)) { Fail 30 "release-summary lacks source commit metadata" }
        if ($notesText.IndexOf($commitField, [System.StringComparison]::Ordinal) -lt 0) {
            Fail 30 "RELEASE-NOTES.md lacks source commit: $commitField"
        }
    }
    if ($notesText -notmatch '\b12\b') { Fail 30 "RELEASE-NOTES.md lacks 12 zip count" }
    $expectedTop = New-Object System.Collections.Generic.List[string]
    $expectedTop.AddRange([string[]]$RequiredTop)
    foreach ($zip in $zips) { $expectedTop.Add([string]$zip.name) }
    $actualTop = @(Get-ChildItem -LiteralPath $ReleaseDir -File | ForEach-Object { $_.Name } | Sort-Object)
    $expectedTopSorted = @($expectedTop | Sort-Object)
    if (($actualTop -join "`n") -ne ($expectedTopSorted -join "`n")) {
        Fail 10 "top-level file set mismatch: got [$($actualTop -join ', ')]"
    }

    # Top-level checksums: GNU format, sorted, all 12 zips covered, no self.
    $topSums = Read-ChecksumLines (Join-Path $ReleaseDir "SHA256SUMS.txt")
    if ($topSums.Count -ne 12) { Fail 22 "top-level SHA256SUMS must list 12 zips" }
    Assert-SortedOrdinal @($topSums) "SHA256SUMS.txt"
    $zipByName = @{}
    foreach ($zip in $zips) { $zipByName[[string]$zip.name] = $zip }
    foreach ($entry in $topSums) {
        if ($entry.Relative -eq "SHA256SUMS.txt") { Fail 22 "top-level SHA256SUMS contains itself" }
        if (-not $zipByName.ContainsKey($entry.Relative)) { Fail 22 "top-level SHA256SUMS lists unknown file: $($entry.Relative)" }
        $zipPath = Join-Path $ReleaseDir $entry.Relative
        if ((Get-Item -LiteralPath $zipPath).Length -ne [long]$zipByName[$entry.Relative].size) { Fail 22 "zip size mismatch: $($entry.Relative)" }
        if ((Get-Sha256Lower $zipPath) -ne $entry.Hash) { Fail 22 "zip sha256 mismatch: $($entry.Relative)" }
    }

    # build-matrix.txt must list exactly the 12 (target, product) rows.
    $matrix = @(Get-Content -LiteralPath (Join-Path $ReleaseDir "build-matrix.txt") | Where-Object { $_ -and -not $_.StartsWith("#") })
    if ($matrix.Count -ne 13) { Fail 10 "build-matrix.txt must have header + 12 target/product rows (got $($matrix.Count))" }
    $matrixRows = @($matrix | Select-Object -Skip 1)
    $expectedMatrix = @{}
    foreach ($zip in $zips) { $expectedMatrix["$($zip.goos)/$($zip.goarch)|$($zip.product)"] = [string]$zip.name }
    if ($matrixRows.Count -ne $expectedMatrix.Count) { Fail 10 "build-matrix row count mismatch" }
    foreach ($row in $matrixRows) {
        $parts = $row.Trim() -split "\s+"
        if ($parts.Count -lt 4) { Fail 10 "invalid build-matrix row: $row" }
        $key = "$($parts[0])|$($parts[1])"
        if (-not $expectedMatrix.ContainsKey($key)) { Fail 10 "build-matrix unknown row: $row" }
        if ($parts[2] -ne $expectedMatrix[$key] -or $parts[3] -ne "status=OK") { Fail 10 "build-matrix row mismatch: $row" }
    }

    # build-summary v1 cross-check.
    if ([string]::IsNullOrWhiteSpace($BuildSummary)) { $BuildSummary = [string]$release.build_summary }
    if ([string]::IsNullOrWhiteSpace($BuildSummary)) { Fail 10 "build-summary path is not recorded; pass -BuildSummary" }
    if (-not (Test-Path -LiteralPath $BuildSummary -PathType Leaf)) { Fail 10 "build-summary not found: $BuildSummary" }
    try { $build = Get-Content -LiteralPath $BuildSummary -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Fail 10 "build-summary is not valid JSON" }
    if ([int]$build.format -ne 1 -or [int]$build.exit_code -ne 0 -or [string]$build.stage -ne "completed" -or
        [int]$build.totals.verified -ne 24 -or [int]$build.totals.failed -ne 0 -or
        [int]$build.verification.exit_code -ne 0) { Fail 20 "build-summary is not a fully verified clean 24/24 build" }
    foreach ($module in @($build.modules)) { if ([bool]$module.dirty) { Fail 20 "build-summary records dirty module $($module.name)" } }
    $checklist = @($build.checklist)
    if ($checklist.Count -ne 24) { Fail 20 "build-summary checklist != 24" }
    foreach ($item in $checklist) { if ([string]$item.status -ne "OK") { Fail 20 "build-summary non-OK artifact: $($item.path)" } }
    $checkByKey = @{}
    foreach ($item in $checklist) {
        $bin = [System.IO.Path]::GetFileName([string]$item.path)
        $checkByKey["$($item.module)|$($item.goos)|$($item.goarch)|$bin"] = $item
    }

    function Test-Forbidden([string]$Relative) {
        $normalized = $Relative -replace "\\", "/"
        # Keep in sync with scripts/package-release.ps1. docs/database is
        # product documentation; acceptance/evidence are source-only.
        if ($normalized -cmatch '^docs/database(/|$)') { return $false }
        return ($normalized -cmatch '(^|/)(\.ai|\.agents|AGENTS\.md|MEMORY\.md|database|secrets|scripts|tools|examples|_tools|EvernightMail|go-build-all|acceptance|evidence)(/|$)|\.(db|db-shm|db-wal|log|key|pem|p12|pfx|env|ttf|otf|woff2?)$')
    }

    New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
    foreach ($zip in ($zips | Sort-Object name -CaseSensitive)) {
        $zipName = [string]$zip.name
        $zipPath = Join-Path $ReleaseDir $zipName
        $extract = Join-Path $tmpRoot (([string]$zip.product) + "-" + ([string]$zip.goos) + "-" + ([string]$zip.goarch))
        if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
        New-Item -ItemType Directory -Force -Path $extract | Out-Null
        try { [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extract) }
        catch { Fail 21 "cannot extract $zipName" }
        $children = @(Get-ChildItem -LiteralPath $extract -Force)
        if ($children.Count -ne 1 -or -not $children[0].PSIsContainer) { Fail 21 "$zipName must contain exactly one top-level package directory" }
        $packageRoot = $children[0].FullName
        $pkgPrefix = $children[0].Name
        $expectedNamePrefix = if ([string]$zip.product -eq "login") { "evernight-login-" } else { "evernightmail-" }
        if (-not $pkgPrefix.StartsWith($expectedNamePrefix)) { Fail 21 "unexpected package dir in $zipName" }

        $actualFiles = @(Get-ChildItem -LiteralPath $packageRoot -Recurse -File | ForEach-Object {
            $_.FullName.Substring($packageRoot.Length).TrimStart('\', '/') -replace "\\", "/" } | Sort-Object -CaseSensitive)
        $expectedFiles = @($zip.files) + @("SHA256SUMS.txt")
        $expectedFiles = @($expectedFiles | Sort-Object -CaseSensitive)
        if (($actualFiles -join "`n") -ne ($expectedFiles -join "`n")) { Fail 21 "file set mismatch in $zipName" }
        foreach ($rel in $actualFiles) { if (Test-Forbidden $rel) { Fail 21 "forbidden path in $zipName : $rel" } }

        $innerPath = Join-Path $packageRoot "SHA256SUMS.txt"
        $inner = Read-ChecksumLines $innerPath
        if ($inner.Count -eq 0) { Fail 21 "inner SHA256SUMS empty in $zipName" }
        Assert-SortedOrdinal @($inner) "$zipName/SHA256SUMS.txt"
        $innerMap = @{}
        foreach ($entry in $inner) {
            if ($entry.Relative -eq "SHA256SUMS.txt") { Fail 22 "inner checksum includes itself: $zipName" }
            $innerMap[$entry.Relative] = $entry.Hash
            $filePath = Join-Path $packageRoot ($entry.Relative -replace "/", "\")
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { Fail 22 "inner checksum file missing: $zipName/$($entry.Relative)" }
            if ((Get-Sha256Lower $filePath) -ne $entry.Hash) { Fail 22 "inner checksum mismatch: $zipName/$($entry.Relative)" }
        }
        $filesWithoutSums = @($actualFiles | Where-Object { $_ -ne "SHA256SUMS.txt" })
        if ($innerMap.Count -ne $filesWithoutSums.Count) { Fail 22 "inner checksum count mismatch in $zipName" }
        foreach ($rel in $filesWithoutSums) { if (-not $innerMap.ContainsKey($rel)) { Fail 22 "inner checksum missing entry: $zipName/$rel" } }

        # Required license/metadata.
        foreach ($required in @("LICENSE", "README.md", "THIRD_PARTY_NOTICES.txt", "VERSION.txt",
            "BUILDINFO.txt", "DEPENDENCIES.txt", "SHA256SUMS.txt")) {
            $path = Join-Path $packageRoot $required
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail 30 "$zipName missing $required" }
            if ((Get-Item -LiteralPath $path).Length -eq 0) { Fail 30 "$zipName has empty $required" }
        }
        # Step 248: login packages must carry the product documentation tree.
        if ([string]$zip.product -eq "login") {
            foreach ($docRel in @("docs/README.md", "docs/guide/README.md",
                "docs/deployment/README.md", "docs/embedding/README.md")) {
                $docPath = Join-Path $packageRoot ($docRel -replace "/", "\")
                if (-not (Test-Path -LiteralPath $docPath -PathType Leaf)) {
                    Fail 30 "$zipName missing product doc: $docRel"
                }
                if ((Get-Item -LiteralPath $docPath).Length -eq 0) {
                    Fail 30 "$zipName has empty product doc: $docRel"
                }
            }
            foreach ($docDir in @("docs/database", "docs/requirements", "docs/licenses")) {
                $dirPath = Join-Path $packageRoot ($docDir -replace "/", "\")
                if (-not (Test-Path -LiteralPath $dirPath -PathType Container)) {
                    Fail 30 "$zipName missing product docs dir: $docDir"
                }
            }
        }
        $license = [System.IO.File]::ReadAllText((Join-Path $packageRoot "LICENSE"))
        if ($license -notmatch "Mulan PSL v2" -or $license -notmatch "KagurazakaYashi\(KagurazakaMiyabi\)") {
            Fail 30 "$zipName LICENSE lacks Mulan PSL v2/project attribution"
        }
        $versionText = [System.IO.File]::ReadAllText((Join-Path $packageRoot "VERSION.txt"))
        if ($versionText -notmatch [regex]::Escape($ExpectedVersion)) { Fail 30 "$zipName VERSION.txt lacks version" }
        if ($versionText -match "worktree_dirty:\s*yes") { Fail 30 "$zipName records dirty worktree" }

        # Binary type/arch and build-summary size/sha.
        $requiredBins = if ([string]$zip.product -eq "login") {
            @("login-server", "loginctl", "login-backup") } else { @("evernightmail") }
        foreach ($bin in $requiredBins) {
            $candidates = @((Join-Path (Join-Path $packageRoot "bin") $bin),
                (Join-Path (Join-Path $packageRoot "bin") ($bin + ".exe")))
            $binPath = $null
            foreach ($candidate in $candidates) { if (Test-Path -LiteralPath $candidate -PathType Leaf) { $binPath = $candidate; break } }
            if ($null -eq $binPath) { Fail 31 "$zipName missing binary $bin" }
            $info = Get-BinaryInfo $binPath
            if ($null -eq $info) { Fail 31 "$zipName/$bin has no valid PE/ELF/Mach-O magic" }
            if ($info.Arch -ne [string]$zip.goarch) { Fail 31 "$zipName/$bin architecture $($info.Arch) != $($zip.goarch)" }
            $expectedType = @{ windows = "PE"; linux = "ELF"; darwin = "Mach-O" }[[string]$zip.goos]
            if ($info.Type -ne $expectedType) { Fail 31 "$zipName/$bin type $($info.Type) != $expectedType" }
            $module = if ([string]$zip.product -eq "login") { "EvernightLogin" } else { "EvernightMail" }
            $key = "$module|$($zip.goos)|$($zip.goarch)|$(Split-Path -Leaf $binPath)"
            if (-not $checkByKey.ContainsKey($key)) { Fail 20 "build-summary lacks checklist entry for $zipName/$bin" }
            $item = $checkByKey[$key]
            if ((Get-Item -LiteralPath $binPath).Length -ne [long]$item.size) { Fail 22 "binary size differs from build-summary: $zipName/$bin" }
            if ((Get-Sha256Lower $binPath) -ne ([string]$item.sha256).ToLowerInvariant()) { Fail 22 "binary sha256 differs from build-summary: $zipName/$bin" }
            if ([string]$item.type -ne $info.Type -or [string]$item.arch -ne $info.Arch) { Fail 31 "build-summary type/arch mismatch: $zipName/$bin" }
        }

        if ([string]$zip.goos -eq "windows" -and [string]$zip.goarch -eq "amd64" -and -not $SkipBinaryRun) {
            $binDir = Join-Path $packageRoot "bin"
            if ([string]$zip.product -eq "login") {
                $versionExe = Join-Path $binDir "login-server.exe"
                $versionResult = Invoke-Captured $versionExe @("--version")
                if ($versionResult.ExitCode -ne 0 -or $versionResult.Stdout -notmatch "login-server") { Fail 31 "login-server --version smoke failed" }
                if ($versionResult.Stdout -notmatch [regex]::Escape($ExpectedVersion)) { Fail 31 "login-server --version lacks version" }
                $helpResult = Invoke-Captured $versionExe @("--help")
                if ($helpResult.ExitCode -ne 0) { Fail 31 "login-server --help smoke failed" }
                $ctlResult = Invoke-Captured (Join-Path $binDir "loginctl.exe") @("--version")
                if ($ctlResult.ExitCode -ne 0 -or $ctlResult.Stdout -notmatch "loginctl") { Fail 31 "loginctl --version smoke failed" }
                $backupResult = Invoke-Captured (Join-Path $binDir "login-backup.exe") @("version")
                if ($backupResult.ExitCode -ne 0 -or $backupResult.Stdout -notmatch "login-backup") { Fail 31 "login-backup version smoke failed" }
            } else {
                $mailResult = Invoke-Captured (Join-Path $binDir "evernightmail.exe") @("--version")
                if ($mailResult.ExitCode -ne 0 -or $mailResult.Stdout -notmatch "evernightmail") { Fail 31 "evernightmail --version smoke failed" }
            }
        }
        Remove-Item -LiteralPath $extract -Recurse -Force
    }

    Write-Host ("VERIFY: PASS release={0} version={1} zips={2} targets={3}" -f $ReleaseDir, $ExpectedVersion, $zips.Count, $Targets.Count)
    exit 0
} catch {
    Fail 40 ("unexpected error: " + $_.Exception.Message)
} finally {
    if (Test-Path -LiteralPath $tmpRoot) { Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue }
}
