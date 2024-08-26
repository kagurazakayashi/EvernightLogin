# package-release.ps1 - Step 248 release packaging (local artifacts only).
#
# Input: a clean build produced by scripts/build-all.ps1 (step 179) with a v1
# build-summary.json containing 24 verified product binaries.
# Output: dist/release/evernight-<version>/ with 12 per-target zip files
# (2 products x 6 targets), top-level SHA256SUMS.txt, build-matrix.txt,
# release-summary.json and a four-section RELEASE-NOTES.md.
#
# Step 248: Login packages include an explicit allow-list of product docs under
# docs/ (guide/deployment/embedding/database/requirements/licenses/reference;
# acceptance/evidence are never packaged); doc links that point to source-only
# directories are rewritten and checked. Release notes are generated from
# docs/release-notes/round10.md (or -ReleaseNotes) and must carry the four
# required headings (completed/failed/unimplemented/untested in Chinese) plus
# version/commit/12-zip evidence.
#
# Safety: no git write, no commit/tag/push/upload, no server/port, no network,
# no runtime database/key/log access. Only an explicit allow-list of files is
# copied; everything else is excluded by construction and re-scanned.
# Windows PowerShell 5.1 and PowerShell 7 compatible (ASCII messages outside
# the product-doc / release-notes content).
#
# Exit codes: 0 ok; 10 prerequisites/build-summary invalid; 20 build-summary
# verification failed; 21 zip assembly failed; 22 checksum failed; 30 license/
# metadata/docs/release-notes missing; 31 type/arch/file-set/link failed; 40 internal error.

[CmdletBinding()]
param(
    [string]$Version = "0.1.0-dev",
    [string]$BuildDir = "",
    [string]$BuildSummary = "",
    [string]$OutputDir = "",
    [string]$RepoRoot = "",
    [string]$MetadataRoot = "",
    # Optional release-notes template; empty uses docs\release-notes\round10.md.
    [string]$ReleaseNotes = "",
    [switch]$SkipBinaryRun
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = Split-Path -Parent $ScriptDir }
$RepoRoot = [System.IO.Path]::GetFullPath($RepoRoot)
if ([string]::IsNullOrWhiteSpace($MetadataRoot)) { $MetadataRoot = $RepoRoot }
$MetadataRoot = [System.IO.Path]::GetFullPath($MetadataRoot)
if ([string]::IsNullOrWhiteSpace($BuildDir)) { $BuildDir = Join-Path $RepoRoot "dist\build" }
$BuildDir = [System.IO.Path]::GetFullPath($BuildDir)
if ([string]::IsNullOrWhiteSpace($BuildSummary)) { $BuildSummary = Join-Path $BuildDir "build-summary.json" }

$Targets = @(
    "windows/amd64", "windows/arm64", "linux/amd64",
    "linux/arm64", "darwin/amd64", "darwin/arm64"
)
$LoginProducts = @("login-server", "loginctl", "login-backup")
$MailProducts = @("evernightmail")

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Text, $encoding)
}
function Write-LfLines([string]$Path, [string[]]$Lines) {
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $text = ($Lines -join "`n") + "`n"
    [System.IO.File]::WriteAllText($Path, $text, $encoding)
}
function Get-Sha256([string]$Path) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace "-", "").ToLowerInvariant() }
        finally { $stream.Dispose() }
    } finally { $sha.Dispose() }
}
function Get-DosDateTime([datetime]$Utc) {
    $clamped = $Utc
    if ($clamped.Year -lt 1980) { $clamped = [datetime]::new(1980, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc) }
    if ($clamped.Year -gt 2107) { $clamped = [datetime]::new(2107, 12, 31, 23, 59, 58, [System.DateTimeKind]::Utc) }
    return [System.DateTimeOffset]::new($clamped)
}
function Fail([int]$Code, [string]$Message) {
    Write-Host ("PACKAGE: FAIL - " + $Message)
    exit $Code
}

try {
    if (-not (Test-Path -LiteralPath $BuildSummary -PathType Leaf)) { Fail 10 "build-summary not found: $BuildSummary" }
    if (-not (Test-Path -LiteralPath $BuildDir -PathType Container)) { Fail 10 "build dir not found: $BuildDir" }
    if (-not (Test-Path -LiteralPath (Join-Path $MetadataRoot "LICENSE") -PathType Leaf)) { Fail 30 "LICENSE not found under metadata root" }

    try { $summary = Get-Content -LiteralPath $BuildSummary -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { Fail 10 "build-summary is not valid JSON" }

    # v1 aggregate contract: only a fully successful clean build may be packaged.
    if ([int]$summary.format -ne 1) { Fail 10 "unsupported build-summary format" }
    if ([int]$summary.exit_code -ne 0) { Fail 20 "build-summary exit_code != 0" }
    if ([string]$summary.stage -ne "completed") { Fail 20 "build-summary stage != completed" }
    if ([string]$summary.version -ne $Version) { Fail 10 "version mismatch: summary=$($summary.version) requested=$Version" }
    if ([int]$summary.totals.expected -ne 24 -or [int]$summary.totals.verified -ne 24 -or
        [int]$summary.totals.failed -ne 0) { Fail 20 "build-summary totals are not 24/24/0" }
    if ([int]$summary.verification.exit_code -ne 0) { Fail 20 "build verification exit_code != 0" }
    $checklist = @($summary.checklist)
    if ($checklist.Count -ne 24) { Fail 20 "build-summary checklist count != 24" }
    foreach ($item in $checklist) {
        if ([string]$item.status -ne "OK") { Fail 20 "build-summary has non-OK artifact: $($item.path)" }
    }
    foreach ($module in @($summary.modules)) {
        if ([bool]$module.dirty) { Fail 10 "build-summary records dirty worktree for $($module.name)" }
    }
    foreach ($warning in @($summary.warnings)) {
        if ([string]$warning -match "dirty|gitlink.*!=") { Fail 10 "build-summary warning indicates non-clean build: $warning" }
    }
    $platforms = @($summary.platforms)
    if (($platforms -join ",") -ne ($Targets -join ",")) { Fail 10 "unexpected platform matrix in build-summary" }

    $loginModule = @($summary.modules | Where-Object { $_.name -eq "EvernightLogin" })[0]
    $mailModule = @($summary.modules | Where-Object { $_.name -eq "EvernightMail" })[0]
    if ($null -eq $loginModule -or $null -eq $mailModule) { Fail 10 "build-summary modules incomplete" }
    $buildTime = [datetime]::Parse([string]$summary.build_time).ToUniversalTime()
    if ([string]::IsNullOrWhiteSpace($OutputDir)) {
        $OutputDir = Join-Path (Join-Path $RepoRoot "dist\release") ("evernight-" + $Version)
    }
    $OutputDir = [System.IO.Path]::GetFullPath($OutputDir)
    $stagingRoot = Join-Path $OutputDir ".staging"
    if (Test-Path -LiteralPath $stagingRoot) { Remove-Item -LiteralPath $stagingRoot -Recurse -Force }
    if (Test-Path -LiteralPath $OutputDir) { Remove-Item -LiteralPath $OutputDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

    $forbiddenPattern = '(^|/)(\.ai|\.agents|AGENTS\.md|MEMORY\.md|database|secrets|scripts|tools|examples|_tools|EvernightMail|go-build-all|acceptance|evidence)(/|$)|\.(db|db-shm|db-wal|log|key|pem|p12|pfx|env|ttf|otf|woff2?)$'
    function Test-ForbiddenPath([string]$Relative) {
        $normalized = $Relative -replace "\\", "/"
        # Product documentation legitimately contains docs/database/**. The
        # runtime data directory is the top-level database/; docs/database is
        # an explicit allow-listed product-doc directory, not runtime data.
        if ($normalized -cmatch '^docs/database(/|$)') { return $false }
        return ($normalized -cmatch $forbiddenPattern)
    }

    # Locate one verified artifact from the build tree (invocations define root).
    $invocationRoots = @{}
    foreach ($invocation in @($summary.invocations)) {
        $product = [string]$invocation.product
        $root = [string]$invocation.output_root
        if ([string]::IsNullOrWhiteSpace($root) -or -not (Test-Path -LiteralPath $root -PathType Container)) {
            $root = Join-Path $BuildDir $product
        }
        $invocationRoots[$product] = [System.IO.Path]::GetFullPath($root)
    }
    function Resolve-Artifact([object]$Item) {
        $productFolder = if ([string]$Item.module -eq "EvernightMail") { "mail" } else { "login" }
        $root = $invocationRoots[$productFolder]
        if ([string]::IsNullOrWhiteSpace($root)) { $root = Join-Path $BuildDir $productFolder }
        $candidate = Join-Path $root ([string]$Item.path)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        $candidate = Join-Path $BuildDir ([string]$Item.path)
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
        Fail 20 "artifact missing: $($Item.path)"
    }
    function Assert-Artifact([string]$Path, [object]$Item) {
        $size = (Get-Item -LiteralPath $Path).Length
        if ($size -ne [long]$Item.size) { Fail 31 "artifact size mismatch: $($Item.path)" }
        if ((Get-Sha256 $Path) -ne ([string]$Item.sha256).ToLowerInvariant()) { Fail 31 "artifact sha256 mismatch: $($Item.path)" }
        if (Test-ForbiddenPath ([string]$Item.path)) { Fail 31 "forbidden artifact path: $($Item.path)" }
    }

    # Explicit metadata copy list (no repository globbing).
    $metadata = @{}
    function Copy-One([string]$Relative, [string]$Destination) {
        $source = Join-Path $MetadataRoot $Relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { Fail 30 "required metadata missing: $Relative" }
        $destPath = Join-Path $Destination $Relative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destPath) | Out-Null
        Copy-Item -LiteralPath $source -Destination $destPath -Force
        $metadata[$Relative] = $destPath
    }
    function Copy-OneAs([string]$Relative, [string]$DestinationRelative, [string]$Destination) {
        $source = Join-Path $MetadataRoot $Relative
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { Fail 30 "required metadata missing: $Relative" }
        $destPath = Join-Path $Destination $DestinationRelative
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destPath) | Out-Null
        Copy-Item -LiteralPath $source -Destination $destPath -Force
    }
    function Copy-Dir([string]$Relative, [string]$Destination, [bool]$Optional) {
        $source = Join-Path $MetadataRoot $Relative
        if (-not (Test-Path -LiteralPath $source -PathType Container)) {
            if ($Optional) { Write-Host "PACKAGE: WARN missing optional metadata dir $Relative"; return }
            Fail 30 "required metadata dir missing: $Relative"
        }
        Get-ChildItem -LiteralPath $source -Recurse -File | ForEach-Object {
            $rel = $_.FullName.Substring($source.Length).TrimStart('\', '/')
            $targetRel = ($Relative -replace "\\", "/") + "/" + ($rel -replace "\\", "/")
            if (Test-ForbiddenPath $targetRel) { Fail 31 "forbidden metadata path: $targetRel" }
            $destPath = Join-Path $Destination $targetRel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $destPath) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $destPath -Force
        }
    }

    # Product documentation allow-list. Source-only directories (examples/,
    # docs/acceptance/, docs/evidence/) are never copied into release zips.
    $ProductDocDirs = @("guide", "deployment", "embedding", "database", "requirements", "licenses")

    function Assert-PackageDocLinks([string]$DocsRoot, [string]$PackageRoot) {
        $packageFull = [System.IO.Path]::GetFullPath($PackageRoot).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
        $bad = New-Object System.Collections.Generic.List[string]
        foreach ($file in @(Get-ChildItem -LiteralPath $DocsRoot -Recurse -File -Filter *.md)) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            foreach ($match in [regex]::Matches($text, '\]\(([^)]+)\)')) {
                $targetText = ([string]$match.Groups[1].Value).Trim()
                if ($targetText.StartsWith('<') -and $targetText.Contains('>')) {
                    $targetText = $targetText.Substring(1, $targetText.IndexOf('>') - 1).Trim()
                } elseif ($targetText -match '\s') {
                    $targetText = ($targetText -split '\s+')[0]
                }
                if ([string]::IsNullOrWhiteSpace($targetText)) { continue }
                if ($targetText -match '^[a-zA-Z][a-zA-Z0-9+.-]*:' -or $targetText.StartsWith('#')) { continue }
                $pathPart = ($targetText -split '#')[0]
                if ([string]::IsNullOrWhiteSpace($pathPart)) { continue }
                try { $decoded = [System.Uri]::UnescapeDataString($pathPart) } catch { $decoded = $pathPart }
                $resolved = [System.IO.Path]::GetFullPath((Join-Path $file.DirectoryName $decoded))
                if (-not $resolved.StartsWith($packageFull, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $bad.Add(($file.Name + " -> " + $targetText))
                    continue
                }
                if (-not (Test-Path -LiteralPath $resolved)) {
                    $bad.Add(($file.Name + " -> " + $targetText))
                }
            }
        }
        if ($bad.Count -gt 0) {
            Fail 31 ("unresolved product document links: " + ($bad -join "; "))
        }
    }

    function Copy-ProductDocs([string]$Destination) {
        # 1) Documentation index and explicit product-doc directories.
        Copy-OneAs "docs\README.md" "docs/README.md" $Destination
        foreach ($dir in $ProductDocDirs) {
            $relative = "docs\" + $dir
            if (-not (Test-Path -LiteralPath (Join-Path $MetadataRoot $relative) -PathType Container)) {
                Fail 30 "required product docs dir missing: $relative"
            }
            Copy-Dir $relative $Destination $false
        }
        # reference is produced by step 245; package it when present, but do not
        # fabricate a missing directory or fail before that step.
        $reference = "docs\reference"
        if (Test-Path -LiteralPath (Join-Path $MetadataRoot $reference) -PathType Container) {
            Copy-Dir $reference $Destination $false
        } else {
            Write-Host "PACKAGE: WARN docs/reference not present; interface reference section is documented as source-only in RELEASE-NOTES.md"
        }

        # 2) Strip links to source-only directories that are not part of the
        #    release package (examples/acceptance/evidence/scripts/tools/
        #    internal/cmd/submodule sources). Keep root README/LICENSE links
        #    because those files are packaged at the root; docs/database links
        #    are packaged product docs and must stay.
        $docRoot = Join-Path $Destination "docs"
        foreach ($file in @(Get-ChildItem -LiteralPath $docRoot -Recurse -File -Filter *.md)) {
            $text = [System.IO.File]::ReadAllText($file.FullName)
            $text = [regex]::Replace($text,
                '\[([^\]]+)\]\((?:\.\./)*(?:acceptance|examples|evidence|scripts|tools|internal|cmd|EvernightMail|go-build-all|_tools)/[^)]*\)',
                '$1')
            [System.IO.File]::WriteAllText($file.FullName, $text,
                (New-Object System.Text.UTF8Encoding($false)))
        }

        # 3) Fail closed if any remaining relative link escapes the package or
        #    points at a missing packaged doc.
        Assert-PackageDocLinks $docRoot $Destination
    }

    function New-InnerSums([string]$StagingDir) {
        $files = @(Get-ChildItem -LiteralPath $StagingDir -Recurse -File |
            Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
            ForEach-Object { $_.FullName.Substring($StagingDir.Length).TrimStart('\', '/') -replace "\\", "/" })
        [System.Array]::Sort($files, [System.StringComparer]::Ordinal)
        $lines = New-Object System.Collections.Generic.List[string]
        foreach ($rel in $files) {
            $full = Join-Path $StagingDir ($rel -replace "/", "\")
            $lines.Add((Get-Sha256 $full) + "  " + $rel)
        }
        Write-LfLines (Join-Path $StagingDir "SHA256SUMS.txt") $lines.ToArray()
    }

    function New-VersionFile([string]$StagingDir, [string]$LoginCommit, [string]$MailCommit,
        [string]$ToolCommit, [string]$ToolSha, [string]$Product) {
        $lines = @(
            "product: $Product",
            "version: $Version",
            "build_time_utc: $($buildTime.ToString('o'))",
            "worktree_dirty: no",
            "login_commit: $LoginCommit",
            "mail_commit: $MailCommit",
            "tool_commit: $ToolCommit",
            "tool_sha256: $ToolSha",
            "go_version: $([string]$summary.go.version)",
            "cgo_enabled: $([string]$summary.go.cgo_enabled)",
            "build_options: trimpath=on buildvcs=off ldflags=-s -w (toolchain=local)",
            "platforms: $($Targets -join ', ')"
        )
        Write-LfLines (Join-Path $StagingDir "VERSION.txt") $lines
    }

    $zipEntries = New-Object System.Collections.Generic.List[object]
    $matrixLines = New-Object System.Collections.Generic.List[string]
    $matrixLines.Add("target product zip status")
    $releaseProducts = @(
        @{ Name = "login"; Prefix = "evernight-login"; Folder = "login"; Bins = $LoginProducts; Module = "EvernightLogin" },
        @{ Name = "mail"; Prefix = "evernightmail"; Folder = "mail"; Bins = $MailProducts; Module = "EvernightMail" }
    )

    foreach ($product in $releaseProducts) {
        foreach ($target in $Targets) {
            $parts = $target.Split("/")
            $goos = $parts[0]; $goarch = $parts[1]
            $pkgName = "$($product.Prefix)-$Version-$goos-$goarch"
            $staging = Join-Path $stagingRoot $pkgName
            New-Item -ItemType Directory -Force -Path (Join-Path $staging "bin") | Out-Null

            $binItems = @($checklist | Where-Object {
                [string]$_.module -eq $product.Module -and [string]$_.goos -eq $goos -and
                [string]$_.goarch -eq $goarch -and ($product.Bins -contains [string]$_.product) })
            if ($binItems.Count -ne $product.Bins.Count) { Fail 20 "checklist binaries incomplete for $target/$($product.Name)" }
            foreach ($item in $binItems) {
                $source = Resolve-Artifact $item
                Assert-Artifact $source $item
                $binName = [System.IO.Path]::GetFileName([string]$item.path)
                $dest = Join-Path (Join-Path $staging "bin") $binName
                Copy-Item -LiteralPath $source -Destination $dest -Force
            }

            if ($product.Name -eq "login") {
                Copy-One "LICENSE" $staging
                Copy-One "README.md" $staging
                Copy-OneAs "docs\licenses\THIRD_PARTY_NOTICES.md" "THIRD_PARTY_NOTICES.txt" $staging
                Copy-ProductDocs $staging
                $buildInfo = @()
                foreach ($bin in $LoginProducts) {
                    $exe = if ($goos -eq "windows") { "$bin.exe" } else { $bin }
                    $binPath = Join-Path (Join-Path $staging "bin") $exe
                    try { $buildInfo += ("## " + $bin); $buildInfo += @(& go version -m $binPath 2>&1) }
                    catch { Fail 31 "go version -m failed for $bin ($target)" }
                }
                Write-LfLines (Join-Path $staging "BUILDINFO.txt") $buildInfo
                try { $deps = @(& go list -m all 2>&1) } catch { Fail 31 "go list -m all failed" }
                Write-LfLines (Join-Path $staging "DEPENDENCIES.txt") $deps
                Write-LfLines (Join-Path $staging "README-PACKAGE.txt") @(
                    "EvernightLogin $Version ($goos/$goarch)",
                    "See docs/README.md for the product documentation index.",
                    "See docs/deployment/samples/ for example config and deployment files.",
                    "On Unix, add execute bits to the three files under bin/ (zip does not preserve +x).",
                    "This package contains only product binaries, product documentation, deployment samples and license documents; no database/log/key/AI files.",
                    "Source-repository-only directories (examples/, docs/acceptance/) and their links are intentionally not packaged."
                )
                New-VersionFile $staging ([string]$loginModule.commit) ([string]$mailModule.commit) ([string]$summary.tool.commit) ([string]$summary.tool.sha256) "EvernightLogin"
            } else {
                Copy-OneAs "EvernightMail\LICENSE" "LICENSE" $staging
                Copy-OneAs "EvernightMail\README.md" "README.md" $staging
                Copy-OneAs "EvernightMail\THIRD_PARTY_NOTICES.md" "THIRD_PARTY_NOTICES.txt" $staging
                Copy-OneAs "EvernightMail\EvernightMail.example.yaml" "evernightmail.example.yaml" $staging
                foreach ($doc in @("README.md", "config-reference.md", "cli-reference.md", "protocol-matrix.md", "offline-security.md")) {
                    Copy-OneAs ("EvernightMail\docs\" + $doc) ("docs/" + $doc) $staging
                }
                $bin = $binItems[0]
                $source = Resolve-Artifact $bin
                $exe = [System.IO.Path]::GetFileName([string]$bin.path)
                $binPath = Join-Path (Join-Path $staging "bin") $exe
                try { $buildInfo = @(& go version -m $binPath 2>&1) } catch { Fail 31 "go version -m failed for mail ($target)" }
                Write-LfLines (Join-Path $staging "BUILDINFO.txt") $buildInfo
                try { $deps = @(& go list -m all 2>&1) } catch { Fail 31 "go list -m all failed" }
                Write-LfLines (Join-Path $staging "DEPENDENCIES.txt") $deps
                Write-LfLines (Join-Path $staging "README-PACKAGE.txt") @(
                    "EvernightMail $Version ($goos/$goarch)",
                    "Offline mail test server; binds loopback by default and does not deliver to the public internet.",
                    "See docs/ for selected deployment/usage documents.",
                    "On Unix, add execute bits to bin/evernightmail (zip does not preserve +x)."
                )
                New-VersionFile $staging ([string]$loginModule.commit) ([string]$mailModule.commit) ([string]$summary.tool.commit) ([string]$summary.tool.sha256) "EvernightMail"
            }

            # Metadata sanity: no forbidden file, required files exist.
            $stagedFiles = @(Get-ChildItem -LiteralPath $staging -Recurse -File)
            foreach ($file in $stagedFiles) {
                $rel = $file.FullName.Substring($staging.Length).TrimStart('\', '/') -replace "\\", "/"
                if (Test-ForbiddenPath $rel) { Fail 31 "forbidden file staged: $rel" }
            }
            foreach ($required in @("LICENSE", "README.md", "THIRD_PARTY_NOTICES.txt", "VERSION.txt",
                "BUILDINFO.txt", "DEPENDENCIES.txt")) {
                if (-not (Test-Path -LiteralPath (Join-Path $staging $required) -PathType Leaf)) { Fail 30 "package missing $required ($pkgName)" }
            }
            New-InnerSums $staging
            if (-not (Test-Path -LiteralPath (Join-Path $staging "SHA256SUMS.txt") -PathType Leaf)) {
                Fail 22 "inner SHA256SUMS was not created ($pkgName)"
            }
            $zipPath = Join-Path $OutputDir ($pkgName + ".zip")
            try {
                $fileStream = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
                try {
                    $archive = New-Object System.IO.Compression.ZipArchive($fileStream, [System.IO.Compression.ZipArchiveMode]::Create)
                    try {
                        $entries = @(Get-ChildItem -LiteralPath $staging -Recurse -File) | Sort-Object FullName
                        foreach ($entry in $entries) {
                            $rel = $entry.FullName.Substring($staging.Length).TrimStart('\', '/') -replace "\\", "/"
                            $name = $pkgName + "/" + $rel
                            $newEntry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
                            $newEntry.LastWriteTime = Get-DosDateTime $buildTime
                            $input = [System.IO.File]::OpenRead($entry.FullName)
                            try { $output = $newEntry.Open(); try { $input.CopyTo($output) } finally { $output.Dispose() } }
                            finally { $input.Dispose() }
                        }
                    } finally { $archive.Dispose() }
                } finally { $fileStream.Dispose() }
            } catch { Fail 21 "failed to create zip $pkgName" }
            $zipSize = (Get-Item -LiteralPath $zipPath).Length
            $zipSha = Get-Sha256 $zipPath
            $zipEntries.Add([ordered]@{
                product = $product.Name; goos = $goos; goarch = $goarch;
                name = ($pkgName + ".zip"); size = $zipSize; sha256 = $zipSha;
                files = @($stagedFiles | ForEach-Object { $_.FullName.Substring($staging.Length).TrimStart('\', '/') -replace "\\", "/" } | Sort-Object -CaseSensitive)
            })
            $matrixLines.Add("$goos/$goarch $($product.Name) $(($pkgName + '.zip')) status=OK")
            Remove-Item -LiteralPath $staging -Recurse -Force
        }
    }

    if ($zipEntries.Count -ne 12) { Fail 21 "expected 12 zip files, got $($zipEntries.Count)" }
    $zipNames = [string[]]@($zipEntries | ForEach-Object { [string]$_.name })
    [System.Array]::Sort($zipNames, [System.StringComparer]::Ordinal)
    $topLines = New-Object System.Collections.Generic.List[string]
    $sortedZips = New-Object System.Collections.Generic.List[object]
    foreach ($name in $zipNames) {
        $entry = @($zipEntries | Where-Object { [string]$_.name -eq $name })[0]
        $topLines.Add("$($entry.sha256)  $($entry.name)")
        $sortedZips.Add($entry)
    }
    Write-LfLines (Join-Path $OutputDir "SHA256SUMS.txt") $topLines.ToArray()
    Write-LfLines (Join-Path $OutputDir "build-matrix.txt") $matrixLines.ToArray()
    $releaseSummary = [ordered]@{
        format = 1
        product = "evernight"
        version = $Version
        build_time = $buildTime.ToString("o")
        build_summary = $BuildSummary
        source_commits = [ordered]@{
            login = [string]$loginModule.commit
            mail = [string]$mailModule.commit
            tool = [string]$summary.tool.commit
        }
        tool_sha256 = [string]$summary.tool.sha256
        zips = $sortedZips.ToArray()
    }
    Write-Utf8NoBom (Join-Path $OutputDir "release-summary.json") ($releaseSummary | ConvertTo-Json -Depth 8)
    function Get-ReleaseNotes([string]$Path, [object[]]$Zips, [string]$VersionValue,
        [datetime]$BuildTimeValue, [string]$LoginCommit, [string]$MailCommit,
        [string]$ToolCommit, [string]$ToolSha) {
        if ([string]::IsNullOrWhiteSpace($Path)) { $Path = "docs\release-notes\round10.md" }
        if (-not [System.IO.Path]::IsPathRooted($Path)) {
            $Path = Join-Path $MetadataRoot $Path
        }
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            Fail 30 "release notes template missing: $Path"
        }
        $text = [System.IO.File]::ReadAllText($Path)
        $table = @("| zip | size | sha256 |", "|---|---:|---|")
        foreach ($zip in @($Zips)) {
            $table += ("| " + [string]$zip.name + " | " + [string]$zip.size + " | " + [string]$zip.sha256 + " |")
        }
        $text = $text.Replace('{{VERSION}}', $VersionValue).
            Replace('{{BUILD_TIME}}', $BuildTimeValue.ToString("o")).
            Replace('{{LOGIN_COMMIT}}', $LoginCommit).
            Replace('{{MAIL_COMMIT}}', $MailCommit).
            Replace('{{TOOL_COMMIT}}', $ToolCommit).
            Replace('{{TOOL_SHA256}}', $ToolSha).
            Replace('{{ZIP_TABLE}}', ($table -join "`n"))
        if ($text -match '\{\{[A-Z0-9_]+\}\}') {
            Fail 30 "release notes template contains unresolved placeholders"
        }
        if ($text -match 'TODO-248') {
            Fail 30 "release notes template still contains TODO-248 markers; fill real results first"
        }
        $requiredHeadings = @(
            ("$([char]0x5DF2)$([char]0x5B8C)$([char]0x6210)"),
            ("$([char]0x5931)$([char]0x8D25)"),
            ("$([char]0x672A)$([char]0x5B9E)$([char]0x73B0)"),
            ("$([char]0x672A)$([char]0x6D4B)")
        )
        foreach ($heading in $requiredHeadings) {
            $pattern = '(?m)^##\s+(?:\d+\.\s*)?' + [regex]::Escape($heading)
            if ($text -notmatch $pattern) {
                Fail 30 ("release notes missing required section: " + $heading)
            }
        }
        return $text
    }

    $notesText = Get-ReleaseNotes -Path $ReleaseNotes -Zips $sortedZips.ToArray() `
        -VersionValue $Version -BuildTimeValue $buildTime `
        -LoginCommit ([string]$loginModule.commit) -MailCommit ([string]$mailModule.commit) `
        -ToolCommit ([string]$summary.tool.commit) -ToolSha ([string]$summary.tool.sha256)
    Write-LfLines (Join-Path $OutputDir "RELEASE-NOTES.md") @($notesText -split "`r?`n")
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host ("PACKAGE: PASS version={0} zips={1} output={2}" -f $Version, $zipEntries.Count, $OutputDir)
    exit 0
} catch {
    Fail 40 ("unexpected error: " + $_.Exception.Message)
}
