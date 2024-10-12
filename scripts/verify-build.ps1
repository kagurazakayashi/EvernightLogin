# verify-build.ps1 - 步骤179 构建树独立校验器（30 项产物 + manifest 字段）。
#
# 职责：读取 Login/Mail 两次 go-build-all 产物清单，独立核验 5 产品 × 6 目标（Login 4 + Mail 1）：
#   - manifest 契约：format/exit_code/summary/requested==effective/结果数/状态/
#     tool_version 固定 SHA/build_options（trimpath/buildvcs/ldflags）；
#   - 每个产物：由 manifest output 定位、命名规则交叉核对、存在、非空、
#     大小与 SHA-256 与 manifest 一致、文件类型与架构用 magic 判定（PE/ELF/
#     Mach-O），不依赖扩展名；
#   - 工具自身不得出现在产品清单；两模块命令集合固定为 5 个产品（Login 4 + Mail 1）。
# 退出码：0 全部通过；30 manifest/聚合字段不符；31 产物缺失/类型/尺寸/SHA 不符；
#         40 内部错误。任何必需项失败都不得返回 0。
# 可选 -SelfTest：不读取构建树，只对 magic 判定函数做合成字节自检（0 通过/1 失败）。
[CmdletBinding()]
param(
    [string]$BuildRoot = "",
    [string]$LoginManifest = "",
    [string]$MailManifest = "",
    [string]$Version = "0.1.0-dev",
    [string]$ExpectToolSHA = "8764de6504db1ecd1ecc5c3d4dd6618b51699cf1",
    [string]$JsonOut = "",
    [switch]$SelfTest
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function New-Utf8NoBomWriter([string]$path) {
    return New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false)))
}

function Write-JsonFile([string]$path, $value) {
    $json = $value | ConvertTo-Json -Depth 12
    if ([string]::IsNullOrWhiteSpace($path)) { return }
    $directory = Split-Path -Parent $path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    [System.IO.File]::WriteAllText($path, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Get-SHA256Hex([string]$path) {
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $digest = $sha.ComputeHash($stream)
        } finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

# Get-FileTypeInfo 用 magic 判定文件类型与架构（不信任扩展名）。
# 返回 @{ Type = 'PE'|'ELF'|'Mach-O'|'unknown'; Arch = 'amd64'|'arm64'|'unknown'; Error = "" }
function Get-FileTypeInfo([string]$path) {
    $result = @{ Type = 'unknown'; Arch = 'unknown'; Error = '' }
    if (-not (Test-Path -LiteralPath $path)) { $result.Error = 'file missing'; return $result }
    $info = Get-Item -LiteralPath $path
    if ($info.Length -lt 8) { $result.Error = 'file too small'; return $result }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    # PE: MZ + e_lfanew -> PE\0\0 -> Machine
    if ($bytes.Length -ge 64 -and $bytes[0] -eq 0x4D -and $bytes[1] -eq 0x5A) {
        $lfanew = [System.BitConverter]::ToInt32($bytes, 0x3C)
        if ($lfanew -gt 0 -and $lfanew + 6 -le $bytes.Length -and
            $bytes[$lfanew] -eq 0x50 -and $bytes[$lfanew + 1] -eq 0x45 -and
            $bytes[$lfanew + 2] -eq 0 -and $bytes[$lfanew + 3] -eq 0) {
            $machine = [System.BitConverter]::ToUInt16($bytes, $lfanew + 4)
            $result.Type = 'PE'
            switch ($machine) {
                0x8664 { $result.Arch = 'amd64' }
                0xAA64 { $result.Arch = 'arm64' }
                default { $result.Error = ('unknown PE machine 0x{0:X4}' -f $machine) }
            }
            return $result
        }
        $result.Error = 'MZ without valid PE header'
        return $result
    }
    # ELF: \x7FELF + EI_CLASS(2=64bit) + EI_DATA(1=LE) + e_machine
    if ($bytes.Length -ge 20 -and $bytes[0] -eq 0x7F -and $bytes[1] -eq 0x45 -and
        $bytes[2] -eq 0x4C -and $bytes[3] -eq 0x46) {
        $result.Type = 'ELF'
        if ($bytes[4] -ne 2) { $result.Error = 'ELF not 64-bit'; return $result }
        if ($bytes[5] -ne 1) { $result.Error = 'ELF not little-endian'; return $result }
        $machine = [System.BitConverter]::ToUInt16($bytes, 18)
        switch ($machine) {
            0x3E { $result.Arch = 'amd64' }
            0xB7 { $result.Arch = 'arm64' }
            default { $result.Error = ('unknown ELF machine 0x{0:X4}' -f $machine) }
        }
        return $result
    }
    # Mach-O 64 little-endian: CF FA ED FE + cputype(LE32)
    if ($bytes.Length -ge 8 -and $bytes[0] -eq 0xCF -and $bytes[1] -eq 0xFA -and
        $bytes[2] -eq 0xED -and $bytes[3] -eq 0xFE) {
        $result.Type = 'Mach-O'
        $cpu = [System.BitConverter]::ToUInt32($bytes, 4)
        switch ($cpu) {
            0x01000007 { $result.Arch = 'amd64' }
            0x0100000C { $result.Arch = 'arm64' }
            default { $result.Error = ('unknown Mach-O cputype 0x{0:X8}' -f $cpu) }
        }
        return $result
    }
    $result.Error = 'unknown file magic'
    return $result
}

# Assert-ArtifactType 校验产物类型/架构符合目标平台；返回错误字符串或空串。
function Assert-ArtifactType([string]$path, [string]$goos, [string]$goarch) {
    $found = Get-FileTypeInfo $path
    if ($found.Error) { return $found.Error }
    $expectedType = switch ($goos) {
        'windows' { 'PE' }
        'linux' { 'ELF' }
        'darwin' { 'Mach-O' }
        default { '' }
    }
    if ($expectedType -eq '') { return "unsupported GOOS in manifest: $goos" }
    if ($found.Type -ne $expectedType) { return "type $($found.Type) != expected $expectedType" }
    if ($found.Arch -ne $goarch) { return "arch $($found.Arch) != expected $goarch" }
    return ''
}

function Get-Manifest([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { throw "manifest not found: $path" }
    return (Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

# Test-SelfTest 用合成字节验证 magic 判定（独立于构建树）。
function Test-SelfTest {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("verify-build-selftest-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $failures = New-Object System.Collections.Generic.List[string]
    try {
        $pe = New-Object byte[] 512
        $pe[0] = 0x4D; $pe[1] = 0x5A
        [System.BitConverter]::GetBytes([int]0x80).CopyTo($pe, 0x3C)
        $pe[0x80] = 0x50; $pe[0x81] = 0x45
        [System.BitConverter]::GetBytes([uint16]0x8664).CopyTo($pe, 0x84)
        $pePath = Join-Path $tmp 'pe-amd64.exe'
        [System.IO.File]::WriteAllBytes($pePath, $pe)
        $peArm = $pe.Clone(); [System.BitConverter]::GetBytes([uint16]0xAA64).CopyTo($peArm, 0x84)
        $peArmPath = Join-Path $tmp 'pe-arm64.exe'
        [System.IO.File]::WriteAllBytes($peArmPath, $peArm)

        $elf = New-Object byte[] 256
        $elf[0] = 0x7F; $elf[1] = 0x45; $elf[2] = 0x4C; $elf[3] = 0x46
        $elf[4] = 2; $elf[5] = 1
        [System.BitConverter]::GetBytes([uint16]0x3E).CopyTo($elf, 18)
        $elfPath = Join-Path $tmp 'elf-amd64'
        [System.IO.File]::WriteAllBytes($elfPath, $elf)
        $elfArm = $elf.Clone(); [System.BitConverter]::GetBytes([uint16]0xB7).CopyTo($elfArm, 18)
        $elfArmPath = Join-Path $tmp 'elf-arm64'
        [System.IO.File]::WriteAllBytes($elfArmPath, $elfArm)

        $macho = New-Object byte[] 64
        $macho[0] = 0xCF; $macho[1] = 0xFA; $macho[2] = 0xED; $macho[3] = 0xFE
        [System.BitConverter]::GetBytes([uint32]0x01000007).CopyTo($macho, 4)
        $machoPath = Join-Path $tmp 'macho-amd64'
        [System.IO.File]::WriteAllBytes($machoPath, $macho)
        $machoArm = New-Object byte[] 64
        [System.Array]::Copy($macho, $machoArm, 64)
        [System.BitConverter]::GetBytes([uint32]0x0100000C).CopyTo($machoArm, 4)
        $machoArmPath = Join-Path $tmp 'macho-arm64'
        [System.IO.File]::WriteAllBytes($machoArmPath, $machoArm)

        $textPath = Join-Path $tmp 'not-binary.exe'
        [System.IO.File]::WriteAllText($textPath, 'this is not a binary')

        $cases = @(
            @($pePath, 'PE', 'amd64'), @($peArmPath, 'PE', 'arm64'),
            @($elfPath, 'ELF', 'amd64'), @($elfArmPath, 'ELF', 'arm64'),
            @($machoPath, 'Mach-O', 'amd64'), @($machoArmPath, 'Mach-O', 'arm64')
        )
        foreach ($case in $cases) {
            $found = Get-FileTypeInfo $case[0]
            if ($found.Type -ne $case[1] -or $found.Arch -ne $case[2]) {
                $failures.Add("$($case[0]): got $($found.Type)/$($found.Arch), want $($case[1])/$($case[2])")
            }
        }
        $found = Get-FileTypeInfo $textPath
        if ($found.Type -ne 'unknown') { $failures.Add("text file wrongly classified as $($found.Type)") }
        if ($failures.Count -gt 0) {
            foreach ($item in $failures) { Write-Host "SELFTEST FAIL: $item" }
            return 1
        }
        Write-Host "SELFTEST PASS: 6 binary magic cases + 1 text rejection"
        return 0
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($SelfTest) { exit (Test-SelfTest) }

$checklist = New-Object System.Collections.Generic.List[object]
$manifestChecks = New-Object System.Collections.Generic.List[object]
$warnings = New-Object System.Collections.Generic.List[string]
$failed = 0

function Add-ManifestCheck([string]$name, [bool]$ok, [string]$detail) {
    $manifestChecks.Add([ordered]@{ name = $name; ok = $ok; detail = $detail })
    if (-not $ok) { Write-Host "MANIFEST FAIL: $name ($detail)" }
}

function Add-Checklist([string]$product, [string]$module, [string]$goos, [string]$goarch,
    [string]$path, [long]$size, [string]$sha256, [string]$type, [string]$arch,
    [bool]$ok, [string]$message) {
    $checklist.Add([ordered]@{
        product = $product; module = $module; goos = $goos; goarch = $goarch;
        path = $path; size = $size; sha256 = $sha256; type = $type; arch = $arch;
        status = $(if ($ok) { 'OK' } else { 'FAILED' }); message = $message
    })
}

try {
    if ([string]::IsNullOrWhiteSpace($BuildRoot)) {
        $BuildRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\dist\build')).Path
    }
    if ([string]::IsNullOrWhiteSpace($LoginManifest)) {
        $LoginManifest = Join-Path $BuildRoot 'login\EvernightLogin.manifest.json'
    }
    if ([string]::IsNullOrWhiteSpace($MailManifest)) {
        $MailManifest = Join-Path $BuildRoot 'mail\EvernightMail.manifest.json'
    }

    $knownPlatforms = @('windows/amd64', 'windows/arm64', 'linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64')
    $products = [ordered]@{
        'EvernightLogin' = @('login-server', 'loginctl', 'login-backup', 'login-setup')
        'EvernightMail' = @('evernightmail')
    }

    $manifests = [ordered]@{}
    if (Test-Path -LiteralPath $LoginManifest) { $manifests['EvernightLogin'] = Get-Manifest $LoginManifest }
    if (Test-Path -LiteralPath $MailManifest) { $manifests['EvernightMail'] = Get-Manifest $MailManifest }
    if ($manifests.Count -eq 0) { throw "no build manifest found under $BuildRoot" }

    foreach ($moduleName in @($manifests.Keys)) {
        $document = $manifests[$moduleName]
        $prefix = "$moduleName."
        Add-ManifestCheck ($prefix + 'format') ($document.format -eq 1) ("format=$($document.format)")
        Add-ManifestCheck ($prefix + 'exit_code') ($document.exit_code -eq 0) ("exit_code=$($document.exit_code)")
        Add-ManifestCheck ($prefix + 'summary') (
            $document.summary.failed -eq 0 -and $document.summary.skipped -eq 0 -and
            $document.summary.success -eq $document.summary.total) ("summary=$($document.summary | ConvertTo-Json -Compress)")
        Add-ManifestCheck ($prefix + 'tool_version') (
            ([string]$document.tool_version) -eq $ExpectToolSHA) ("tool_version=$($document.tool_version) expect=$ExpectToolSHA")
        Add-ManifestCheck ($prefix + 'packaging') ($document.packaging -eq 'cli') ("packaging=$($document.packaging)")
        Add-ManifestCheck ($prefix + 'app_version') ($document.app_version -eq $Version) ("app_version=$($document.app_version) expect=$Version")
        $requested = @($document.requested_platforms | ForEach-Object { [string]$_ })
        $effective = @($document.effective_platforms | ForEach-Object { [string]$_ })
        $modulePlatforms = @($requested)
        $unknownPlatforms = @($modulePlatforms | Where-Object { $knownPlatforms -notcontains $_ })
        Add-ManifestCheck ($prefix + 'requested_platforms') (
            $modulePlatforms.Count -gt 0 -and $unknownPlatforms.Count -eq 0) ("requested=$($modulePlatforms -join ',') unknown=$($unknownPlatforms -join ',')")
        Add-ManifestCheck ($prefix + 'effective_platforms') (
            (@($effective | Sort-Object) -join ',') -eq (@($modulePlatforms | Sort-Object) -join ',')) ("effective=$($effective -join ',') requested=$($modulePlatforms -join ',')")
        $buildOptions = $document.build_options
        Add-ManifestCheck ($prefix + 'build_options.trimpath') ($buildOptions.trimpath -eq 'on') ("trimpath=$($buildOptions.trimpath)")
        Add-ManifestCheck ($prefix + 'build_options.buildvcs') ($buildOptions.buildvcs -eq 'off') ("buildvcs=$($buildOptions.buildvcs)")
        Add-ManifestCheck ($prefix + 'build_options.ldflags') (
            -not [string]::IsNullOrWhiteSpace([string]$buildOptions.ldflags)) ("ldflags=$($buildOptions.ldflags)")
        if (-not [string]::IsNullOrWhiteSpace([string]$buildOptions.ldflags) -and
            -not ([string]$buildOptions.ldflags).Contains($Version)) {
            Add-ManifestCheck ($prefix + 'build_options.ldflags.version') $false ("ldflags does not contain version $Version")
        }
        $concurrency = $document.concurrency
        $logical = [int]$concurrency.logical_cpus
        $budget = [Math]::Max(1, [Math]::Floor($logical / 2))
        Add-ManifestCheck ($prefix + 'concurrency.budget') ([int]$concurrency.budget -eq $budget) ("budget=$($concurrency.budget) expect=$budget")
        Add-ManifestCheck ($prefix + 'concurrency.workers') (
            [int]$concurrency.workers -ge 1 -and [int]$concurrency.workers -le $budget -and
            ([int]$concurrency.workers * [int]$concurrency.per_build_p) -le $budget) ("workers=$($concurrency.workers) p=$($concurrency.per_build_p) budget=$budget")

        $entries = @($document.command_entries)
        $bins = @($entries | ForEach-Object { [string]$_.bin } | Sort-Object)
        $expectedBins = @($products[$moduleName] | Sort-Object)
        Add-ManifestCheck ($prefix + 'command_entries') (
            ($bins -join ',') -eq ($expectedBins -join ',')) ("bins=$($bins -join ',') expect=$($expectedBins -join ',')")
        $expectedCount = $expectedBins.Count * $modulePlatforms.Count
        $results = @($document.results)
        Add-ManifestCheck ($prefix + 'results.count') ($results.Count -eq $expectedCount) ("count=$($results.Count) expect=$expectedCount")

        $manifestRoot = Split-Path -Parent $(if ($moduleName -eq 'EvernightLogin') { $LoginManifest } else { $MailManifest })
        foreach ($result in $results) {
            $product = [string]$result.command
            $goos = [string]$result.goos
            $goarch = [string]$result.goarch
            $outputRel = [string]$result.output
            $ok = $true
            $message = ''
            $typeText = 'unknown'
            $archText = 'unknown'
            $fullPath = ''
            if ($product -notin $products[$moduleName]) {
                $ok = $false; $message = "unexpected product in manifest"
            } elseif ([string]$result.status -notlike 'OK*') {
                $ok = $false; $message = "status=$($result.status)"
            } elseif (-not ($modulePlatforms -contains "$goos/$goarch")) {
                $ok = $false; $message = "unexpected platform $goos/$goarch"
            } else {
                $fullPath = Join-Path $manifestRoot $outputRel
                $extension = switch ($goos) { 'windows' { '.exe' } default { '' } }
                $expectedDir = "${product}_v${Version}_${goos}_${goarch}"
                $expectedName = "$product$extension"
                $actualDir = Split-Path -Leaf (Split-Path -Parent $outputRel)
                $actualName = Split-Path -Leaf $outputRel
                if ($actualDir -ne $expectedDir -or $actualName -ne $expectedName) {
                    $ok = $false; $message = "naming mismatch: $outputRel != $expectedDir/$expectedName"
                }
                if ($ok -and -not (Test-Path -LiteralPath $fullPath)) {
                    $ok = $false; $message = "artifact missing: $fullPath"
                }
                if ($ok) {
                    $length = (Get-Item -LiteralPath $fullPath).Length
                    if ($length -le 0) { $ok = $false; $message = 'artifact is empty' }
                    elseif ($length -ne [long]$result.size_bytes) {
                        $ok = $false; $message = "size mismatch: $length != $($result.size_bytes)"
                    }
                }
                if ($ok) {
                    $actualSHA = Get-SHA256Hex $fullPath
                    if ($actualSHA -ne ([string]$result.sha256).ToLowerInvariant()) {
                        $ok = $false; $message = "sha256 mismatch: $actualSHA != $($result.sha256)"
                    }
                }
                if ($ok) {
                    $typeError = Assert-ArtifactType $fullPath $goos $goarch
                    if ($typeError) { $ok = $false; $message = "type check failed: $typeError" } else {
                        $found = Get-FileTypeInfo $fullPath
                        $typeText = $found.Type; $archText = $found.Arch
                    }
                }
                if ($ok) {
                    $targetDirectory = Split-Path -Parent $fullPath
                    if (-not (Get-ChildItem -LiteralPath $targetDirectory -Filter 'README*' -File -ErrorAction SilentlyContinue)) {
                        $warnings.Add("$product/$goos/${goarch}: README missing in target directory")
                    }
                    if (-not (Get-ChildItem -LiteralPath $targetDirectory -Filter 'LICENSE*' -File -ErrorAction SilentlyContinue)) {
                        $warnings.Add("$product/$goos/${goarch}: LICENSE missing in target directory")
                    }
                }
            }
            if (-not $ok) { $failed++ }
            Add-Checklist $product $moduleName $goos $goarch $outputRel ([long]$result.size_bytes) ([string]$result.sha256) $typeText $archText $ok $message
        }
    }

    # 产物矩阵必须恰好覆盖所选模块的 5 产品 × 6 目标（完整构建 = 30），且不得混入工具或其他产品。
    $expectedKeys = New-Object System.Collections.Generic.List[string]
    $expectedTotal = 0
    foreach ($moduleName in @($manifests.Keys)) {
        $modulePlatformsForMatrix = @($manifests[$moduleName].requested_platforms | ForEach-Object { [string]$_ })
        foreach ($product in $products[$moduleName]) {
            foreach ($platform in $modulePlatformsForMatrix) {
                $expectedKeys.Add("$product/$platform")
            }
            $expectedTotal += $modulePlatformsForMatrix.Count
        }
    }
    $actualKeys = @($checklist | ForEach-Object { "$($_.product)/$($_.goos)/$($_.goarch)" } | Sort-Object -Unique)
    $missing = @($expectedKeys | Where-Object { $actualKeys -notcontains $_ })
    $extra = @($actualKeys | Where-Object { $expectedKeys -notcontains $_ })
    Add-ManifestCheck 'matrix.complete' ($checklist.Count -eq $expectedTotal -and $missing.Count -eq 0 -and $extra.Count -eq 0) (
        "count=$($checklist.Count) expected=$expectedTotal missing=$($missing -join ',') extra=$($extra -join ',')")
    Add-ManifestCheck 'matrix.noToolArtifact' (-not ($actualKeys | Where-Object { $_ -like 'go-build-all/*' })) 'tool artifact must not be listed as product'

    $manifestFailed = @($manifestChecks | Where-Object { -not $_.ok }).Count
    if ($manifestFailed -gt 0) { $exitCode = 30 } elseif ($failed -gt 0) { $exitCode = 31 } else { $exitCode = 0 }
    $verified = @($checklist | Where-Object { $_.status -eq 'OK' }).Count
    $document = [ordered]@{
        format = 1
        generated_at = (Get-Date).ToString('o')
        build_root = $BuildRoot
        version = $Version
        expect_tool_sha = $ExpectToolSHA
        exit_code = $exitCode
        manifest_checks = $manifestChecks
        checklist = $checklist
        totals = [ordered]@{ expected = $expectedTotal; verified = $verified; failed = $failed }
        warnings = $warnings
    }
    if (-not [string]::IsNullOrWhiteSpace($JsonOut)) { Write-JsonFile $JsonOut $document }
    Write-Host ("verify-build: manifests={0} ok, artifacts={1}/{2} ok, warnings={3} -> exit {4}" -f
        ($manifestChecks.Count - $manifestFailed), $verified, $checklist.Count, $warnings.Count, $exitCode)
    exit $exitCode
} catch {
    Write-Host "VERIFY ERROR: $($_.Exception.Message)"
    if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
        Write-JsonFile $JsonOut ([ordered]@{ format = 1; exit_code = 40; error = $_.Exception.Message })
    }
    exit 40
}
