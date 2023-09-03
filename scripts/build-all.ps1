# build-all.ps1 - 步骤179 一键六平台构建入口的核心逻辑。
#
# 流程：预检（go/工具链/GOWORK/GOFLAGS/go.work/replace/子模块固定 SHA 与 clean）
#   -> 从源码构建 go-build-all 到 _tools/（记录 SHA256，不进入产品清单）
#   -> 串行两次调用工具（Login 3 命令、Mail 1 命令；六目标；-P cli；-j 由工具夹紧）
#   -> 调用 verify-build.ps1 独立校验 24 项产物（manifest/大小/SHA256/PE-ELF-Mach-O）
#   -> 写 dist/build/build-summary.json（format=1）与 checklist.txt。
# 退出码：0 成功；10 预检失败；20 工具构建失败；21 Login 构建失败；22 Mail 构建失败；
#         30 manifest/聚合字段不符；31 产物缺失/类型/尺寸/SHA 不符；40 内部错误。
# 本脚本不执行 Git 写操作，不修改产品源码，不读取 database/login.db。
[CmdletBinding()]
param(
    [string]$Version = "0.1.0-dev",
    [string]$Products = "all",
    [string]$Targets = "windows/amd64,windows/arm64,linux/amd64,linux/arm64,darwin/amd64,darwin/arm64",
    [string]$Commands = "",
    [int]$Jobs = 0,
    [string]$OutputDir = "",
    [string]$ToolPath = "",
    [string]$GoToolchain = "local",
    [string]$VersionCommit = "",
    [string]$BuildTime = "",
    [string]$Analyze = 'on',
    [switch]$ForceClean,
    [switch]$SkipVerify,
    [switch]$AllowDirty,
    [switch]$StrictGitlink
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# 固定基线（本提交 = go-build-all 179 工具提交；Mail = 175 提交）。
$ToolSHA = '8764de6504db1ecd1ecc5c3d4dd6618b51699cf1'
$MailSHA = 'b9891ac569c7f5a0530ac74b73dfe8d5a9441b6e'
$MinGoVersion = '1.27.0'
$StdoutLog = New-Object System.Collections.Generic.List[string]
$Warnings = New-Object System.Collections.Generic.List[string]
$Invocations = New-Object System.Collections.Generic.List[object]

function Write-Step([string]$text) {
    $line = "[build] $text"
    $StdoutLog.Add($line)
    Write-Host $line
}

function Write-Warn([string]$text) {
    $line = "[warn ] $text"
    $StdoutLog.Add($line)
    $Warnings.Add($text)
    Write-Host $line -ForegroundColor Yellow
}

function New-Utf8NoBomWriter([string]$path) {
    return New-Object System.IO.StreamWriter($path, $false, (New-Object System.Text.UTF8Encoding($false)))
}

function Write-JsonFile([string]$path, $value) {
    $directory = Split-Path -Parent $path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Force -Path $directory | Out-Null
    }
    $json = $value | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($path, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
}

function Get-SHA256Hex([string]$path) {
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $digest = $sha.ComputeHash($stream) } finally { $sha.Dispose() }
    } finally { $stream.Dispose() }
    return ([System.BitConverter]::ToString($digest) -replace '-', '').ToLowerInvariant()
}

function Invoke-Git([string]$directory, [string[]]$arguments) {
    $output = & git -C $directory @arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ("git -C $directory $($arguments -join ' ') failed: $output") }
    return ($output | Out-String).Trim()
}

function Compare-Version([string]$left, [string]$right) {
    $a = $left.Split('.'); $b = $right.Split('.')
    for ($i = 0; $i -lt 3; $i++) {
        $av = 0; $bv = 0
        if ($i -lt $a.Count) { $av = [int]($a[$i] -replace '[^0-9].*$', '') }
        if ($i -lt $b.Count) { $bv = [int]($b[$i] -replace '[^0-9].*$', '') }
        if ($av -lt $bv) { return -1 }
        if ($av -gt $bv) { return 1 }
    }
    return 0
}

# ==== 预检 ====
function Invoke-Preflight([string]$RepositoryRoot, [string]$AbsoluteOutputDir) {
    $git = (Get-Command git -ErrorAction SilentlyContinue)
    if ($null -eq $git) { throw "git not found in PATH" }
    $goCommand = (Get-Command go -ErrorAction SilentlyContinue)
    if ($null -eq $goCommand) { throw "go not found in PATH" }

    if ($Analyze -notin @('on','off')) { throw "invalid -Analyze '$Analyze': expected on or off" }
    if ($GoToolchain -notin @('local')) {
        throw "unsupported -GoToolchain '$GoToolchain': 179 accepts only 'local'"
    }
    $env:GOTOOLCHAIN = 'local'
    $env:GOWORK = 'off'
    $env:GOFLAGS = '-mod=readonly'
    $env:CGO_ENABLED = '0'
    $env:GOMAXPROCS = '2'

    $goVersionText = (& go version) | Out-String
    if ($LASTEXITCODE -ne 0) { throw "go version failed" }
    if ($goVersionText -notmatch 'go version go([0-9]+\.[0-9]+\.[0-9]+)') { throw "cannot parse go version: $goVersionText" }
    $goVersion = $Matches[1]
    if ((Compare-Version $goVersion $MinGoVersion) -lt 0) {
        throw "go $goVersion is older than required $MinGoVersion (EvernightMail go directive)"
    }
    $goworkValue = ((& go env GOWORK) | Out-String).Trim()
    if ($goworkValue -ne '' -and $goworkValue -ne 'off') {
        throw "go env GOWORK is '$goworkValue' (expected empty or 'off')"
    }

    foreach ($root in @($RepositoryRoot, (Join-Path $RepositoryRoot 'EvernightMail'), (Join-Path $RepositoryRoot 'go-build-all'))) {
        $goWork = Get-ChildItem -LiteralPath $root -Filter 'go.work*' -File -ErrorAction SilentlyContinue
        if ($goWork) { throw "go.work file must not exist: $($goWork[0].FullName)" }
    }
    foreach ($gomod in @((Join-Path $RepositoryRoot 'go.mod'), (Join-Path $RepositoryRoot 'EvernightMail\go.mod'))) {
        $replace = Select-String -LiteralPath $gomod -Pattern '^\s*replace\b' -Encoding UTF8
        if ($replace) { throw "replace directive is not allowed in $gomod" }
    }

    $mailDir = Join-Path $RepositoryRoot 'EvernightMail'
    $toolDir = Join-Path $RepositoryRoot 'go-build-all'
    $mailHead = Invoke-Git $mailDir @('rev-parse', 'HEAD')
    $toolHead = Invoke-Git $toolDir @('rev-parse', 'HEAD')
    $parentHead = Invoke-Git $RepositoryRoot @('rev-parse', 'HEAD')
    $parentDirty = ((Invoke-Git $RepositoryRoot @('status', '--porcelain')) -ne '')
    $mailDirty = ((Invoke-Git $mailDir @('status', '--porcelain')) -ne '')
    $toolDirty = ((Invoke-Git $toolDir @('status', '--porcelain')) -ne '')
    if ($mailHead -ne $MailSHA) { throw "EvernightMail HEAD $mailHead != pinned $MailSHA" }
    if ($toolHead -ne $ToolSHA) { throw "go-build-all HEAD $toolHead != pinned $ToolSHA" }
    if ($mailDirty -and -not $AllowDirty) { throw "EvernightMail worktree is dirty; commit or pass -AllowDirty for diagnosis only" }
    if ($toolDirty -and -not $AllowDirty) { throw "go-build-all worktree is dirty; commit or pass -AllowDirty for diagnosis only" }
    if ($parentDirty) { Write-Warn "parent repository worktree is dirty; build-summary records dirty=yes (commit 179 files before formal release)" }

    # 父 gitlink 当前值：B 段自测时指针尚未随 179 提交更新，默认警告；-StrictGitlink 失败。
    $gitlinks = & git -C $RepositoryRoot ls-tree HEAD EvernightMail go-build-all 2>&1
    $mailGitlink = ($gitlinks | Select-String 'EvernightMail' | ForEach-Object { ($_ -split '\s+')[2] })
    $toolGitlink = ($gitlinks | Select-String 'go-build-all' | ForEach-Object { ($_ -split '\s+')[2] })
    if ($mailGitlink -ne $MailSHA -or $toolGitlink -ne $ToolSHA) {
        $message = "parent gitlink (mail=$mailGitlink tool=$toolGitlink) != submodule HEAD; 179 commit must update pointers"
        if ($StrictGitlink) { throw $message } else { Write-Warn $message }
    }

    $selectedProducts = @($Products.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ -ne '' })
    if ($selectedProducts.Count -eq 0) { throw "-Products must be all, login or mail" }
    foreach ($product in $selectedProducts) {
        if ($product -notin @('all', 'login', 'mail')) { throw "unknown product '$product'; expected all, login or mail" }
    }
    if ($selectedProducts -contains 'all' -and $selectedProducts.Count -gt 1) { throw "-Products all cannot be combined" }

    $platforms = @($Targets.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($platforms.Count -eq 0) { throw "-Targets must not be empty" }
    foreach ($platform in $platforms) {
        if ($platform -notmatch '^(windows|linux|darwin)/(amd64|arm64)$') {
            throw "invalid target '$platform'; expected one of windows|linux|darwin / amd64|arm64"
        }
    }

    if ($Commands -ne '' -and -not ($selectedProducts.Count -eq 1 -and $selectedProducts[0] -ne 'all')) {
        throw "-Commands override requires a single selected product (login or mail)"
    }

    if ([string]::IsNullOrWhiteSpace($AbsoluteOutputDir)) {
        $AbsoluteOutputDir = Join-Path $RepositoryRoot 'dist\build'
    }
    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($AbsoluteOutputDir)
    if ($resolvedOutput.TrimEnd('\', '/') -eq $RepositoryRoot.TrimEnd('\', '/')) {
        throw "OutputDir must not be the repository root"
    }

    return [ordered]@{
        go_version = $goVersion
        goos = (& go env GOOS | Out-String).Trim()
        goarch = (& go env GOARCH | Out-String).Trim()
        parent_head = $parentHead
        parent_dirty = $parentDirty
        mail_head = $mailHead
        mail_dirty = $mailDirty
        mail_gitlink = $mailGitlink
        tool_head = $toolHead
        tool_dirty = $toolDirty
        tool_gitlink = $toolGitlink
        output_dir = $resolvedOutput
        selected_products = $selectedProducts
        platforms = $platforms
        mail_root = $mailDir
        tool_root = $toolDir
    }
}

# ==== 主流程 ====
$currentStage = 'preflight'
try {
    $repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    $context = Invoke-Preflight $repositoryRoot $OutputDir
    $AbsoluteOutputDir = $context.output_dir
    $currentStage = 'output-dir'
    Write-Step "repo=$repositoryRoot"
    Write-Step "go=$($context.go_version) ($($context.goos)/$($context.goarch)) GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOMAXPROCS=2"
    Write-Step "products=$($context.selected_products -join ',') targets=$($context.platforms -join ',') version=$Version"

    if (Test-Path -LiteralPath $AbsoluteOutputDir) {
        $existing = @(Get-ChildItem -LiteralPath $AbsoluteOutputDir -Force -ErrorAction SilentlyContinue)
        if ($existing.Count -gt 0) {
            $existingMarker = Join-Path $AbsoluteOutputDir '.build-all-root'
            if (Test-Path -LiteralPath $existingMarker) {
                Write-Step "cleaning previous build output (marker found): $AbsoluteOutputDir"
            } elseif ($ForceClean) {
                Write-Warn "removing existing non-build OutputDir because -ForceClean was given: $AbsoluteOutputDir"
            } else {
                throw "OutputDir already exists and is not an empty/build-all directory: $AbsoluteOutputDir (pass -ForceClean to remove it, or use another -OutputDir)"
            }
            Remove-Item -LiteralPath $AbsoluteOutputDir -Recurse -Force
        }
    }
    New-Item -ItemType Directory -Force -Path $AbsoluteOutputDir | Out-Null
    # 构建根标记：仅用于本入口生成目录的安全清理判定；不参与产品清单。
    $markerPath = Join-Path $AbsoluteOutputDir '.build-all-root'
    $markerDocument = [ordered]@{
        tool = 'go-build-all build entry'
        version = $Version
        created_at = (Get-Date).ToString('o')
    }
    [System.IO.File]::WriteAllText($markerPath, (($markerDocument | ConvertTo-Json) + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    $currentStage = 'build'
    $toolsDir = Join-Path $AbsoluteOutputDir '_tools'
    New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
    $logPath = Join-Path $AbsoluteOutputDir 'build.log'

    # 版本元数据（可按参数固定，便于复现）。
    if ([string]::IsNullOrWhiteSpace($VersionCommit)) { $VersionCommit = $context.parent_head }
    if ([string]::IsNullOrWhiteSpace($BuildTime)) {
        $BuildTime = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    }

    # ==== 构建工具（源码固定 SHA；不使用工作树遗留二进制）====
    $toolExe = $null
    if (-not [string]::IsNullOrWhiteSpace($ToolPath)) {
        $provided = (Resolve-Path -LiteralPath $ToolPath).Path
        if (-not (Test-Path -LiteralPath $provided)) { throw "ToolPath not found: $ToolPath" }
        $toolExe = $provided
        Write-Step "using provided tool: $toolExe"
    } else {
        $toolExe = Join-Path $toolsDir ("go-build-all-" + $ToolSHA.Substring(0, 12) + ".exe")
        Write-Step "building go-build-all from pinned source $ToolSHA -> _tools/"
        Push-Location $context.tool_root
        try {
            & go build -trimpath -o $toolExe . 2>&1 | ForEach-Object { $StdoutLog.Add([string]$_) ; Write-Host $_ }
            if ($LASTEXITCODE -ne 0) {
                Write-Step "ERROR: go-build-all build failed (exit $LASTEXITCODE)"
                exit 20
            }
        } finally { Pop-Location }
    }
    $toolSHA256 = Get-SHA256Hex $toolExe
    Write-Step "tool sha256=$toolSHA256"

    $loginLDFlags = "-s -w -X github.com/kagurazakayashi/EvernightLogin.version=$Version " +
        "-X github.com/kagurazakayashi/EvernightLogin.commit=$($context.parent_head) " +
        "-X github.com/kagurazakayashi/EvernightLogin.buildTime=$BuildTime"
    $mailLDFlags = "-s -w -X github.com/kagurazakayashi/EvernightMail/internal/version.Version=$Version " +
        "-X github.com/kagurazakayashi/EvernightMail/internal/version.Commit=$($context.mail_head) " +
        "-X github.com/kagurazakayashi/EvernightMail/internal/version.BuildDate=$BuildTime"

    $targetArgument = $context.platforms -join ','
    $loginCommandList = @('cmd/login-server', 'cmd/loginctl', 'cmd/login-backup')
    $mailCommandList = @('cmd/evernightmail')
    if ($Commands -ne '') {
        $override = @($Commands.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
        if ($context.selected_products[0] -eq 'login') { $loginCommandList = $override } else { $mailCommandList = $override }
    }

    $loginOutput = Join-Path $AbsoluteOutputDir 'login'
    $mailOutput = Join-Path $AbsoluteOutputDir 'mail'

    function Invoke-ProductBuild([string]$product, [string]$moduleRoot, [string]$outputRoot,
        [string[]]$commands, [string]$ldflags) {
        $arguments = @(
            '-r', $moduleRoot,
            '-e', ($commands -join ','),
            '-p', $targetArgument,
            '-o', $outputRoot,
            '-P', 'cli',
            '-v', $Version,
            '-A', $Analyze,
            '-l', 'off',
            '-j', "$Jobs",
            '-T', '1200',
            '-trimpath',
            '-buildvcs=false',
            '-L', $ldflags
        )
        Write-Step "invoking go-build-all for $product (commands=$($commands -join ','))"
        $started = Get-Date
        & $toolExe @arguments 2>&1 | ForEach-Object { $StdoutLog.Add([string]$_) ; Write-Host $_ }
        $exitCode = $LASTEXITCODE
        $duration = [int]((Get-Date) - $started).TotalMilliseconds
        $Invocations.Add([ordered]@{
            product = $product; exit_code = $exitCode; duration_ms = $duration;
            module_root = $moduleRoot; output_root = $outputRoot
        })
        return $exitCode
    }

    function Write-FailureSummary([string]$stage, [int]$exitCode, $verification) {
        $summaryPath = Join-Path $AbsoluteOutputDir 'build-summary.json'
        $summary = [ordered]@{
            format = 1
            generated_at = (Get-Date).ToString('o')
            version = $Version
            build_time = $BuildTime
            stage = $stage
            exit_code = $exitCode
            tool = [ordered]@{ commit = $ToolSHA; path = $toolExe; sha256 = $toolSHA256 }
            go = [ordered]@{ version = $context.go_version; goos = $context.goos; goarch = $context.goarch;
                cgo_enabled = '0'; gotoolchain = 'local'; gowork = 'off'; goflags = '-mod=readonly' }
            modules = @(
                [ordered]@{ name = 'EvernightLogin'; root = $repositoryRoot; commit = $context.parent_head }
                [ordered]@{ name = 'EvernightMail'; root = $context.mail_root; commit = $context.mail_head }
            )
            submodule_gitlinks = [ordered]@{ mail = $context.mail_gitlink; tool = $context.tool_gitlink }
            invocations = $Invocations
            verification = $verification
            warnings = $Warnings
            exit_code_note = 'failed before checklist completed'
        }
        Write-JsonFile $summaryPath $summary
        Write-Host "build-summary (partial): $summaryPath"
    }

    $selected = $context.selected_products
    $buildLogin = $selected -contains 'all' -or $selected -contains 'login'
    $buildMail = $selected -contains 'all' -or $selected -contains 'mail'

    if ($buildLogin) {
        $code = Invoke-ProductBuild 'login' $repositoryRoot $loginOutput $loginCommandList $loginLDFlags
        if ($code -ne 0) {
            Write-Step "ERROR: Login build failed (exit $code) -> build-all exit 21"
            Write-FailureSummary 'login-build' 21 $null
            exit 21
        }
    }
    if ($buildMail) {
        $code = Invoke-ProductBuild 'mail' $context.mail_root $mailOutput $mailCommandList $mailLDFlags
        if ($code -ne 0) {
            Write-Step "ERROR: Mail build failed (exit $code) -> build-all exit 22"
            Write-FailureSummary 'mail-build' 22 $null
            exit 22
        }
    }

    # ==== 独立校验 24 项产物 ====
    $verifyJson = Join-Path $AbsoluteOutputDir 'verify-result.json'
    $verification = $null
    $verifyExit = 0
    if ($SkipVerify) {
        Write-Warn "-SkipVerify used: 24-item artifact verification was skipped (diagnosis only)"
    } else {
        $verifyScript = Join-Path $PSScriptRoot 'verify-build.ps1'
        $verifyArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $verifyScript,
            '-BuildRoot', $AbsoluteOutputDir, '-Version', $Version,
            '-ExpectToolSHA', $ToolSHA, '-JsonOut', $verifyJson)
        if ($buildLogin) {
            $verifyArgs += @('-LoginManifest', (Join-Path $loginOutput 'EvernightLogin.manifest.json'))
        }
        if ($buildMail) {
            $verifyArgs += @('-MailManifest', (Join-Path $mailOutput 'EvernightMail.manifest.json'))
        }
        & powershell @verifyArgs | ForEach-Object { $StdoutLog.Add([string]$_) ; Write-Host $_ }
        $verifyExit = $LASTEXITCODE
        if (Test-Path -LiteralPath $verifyJson) {
            $verification = Get-Content -LiteralPath $verifyJson -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($warning in @($verification.warnings)) { Write-Warn ([string]$warning) }
        }
        if ($verifyExit -ne 0) {
            Write-Step "ERROR: artifact verification failed (exit $verifyExit) -> build-all exit $verifyExit"
            Write-FailureSummary 'verify' $verifyExit $verification
            exit $verifyExit
        }
    }

    # ==== 汇总 build-summary.json / checklist.txt ====
    $checklist = @()
    $totals = [ordered]@{ expected = 0; verified = 0; failed = 0 }
    if ($verification) {
        $checklist = @($verification.checklist)
        $totals = $verification.totals
    }
    $summary = [ordered]@{
        format = 1
        generated_at = (Get-Date).ToString('o')
        version = $Version
        build_time = $BuildTime
        stage = 'completed'
        exit_code = 0
        tool = [ordered]@{ commit = $ToolSHA; path = $toolExe; sha256 = $toolSHA256 }
        go = [ordered]@{ version = $context.go_version; goos = $context.goos; goarch = $context.goarch;
            cgo_enabled = '0'; gotoolchain = 'local'; gowork = 'off'; goflags = '-mod=readonly' }
        modules = @(
            [ordered]@{ name = 'EvernightLogin'; root = $repositoryRoot; commit = $context.parent_head; dirty = $context.parent_dirty }
            [ordered]@{ name = 'EvernightMail'; root = $context.mail_root; commit = $context.mail_head; dirty = $context.mail_dirty }
        )
        submodule_gitlinks = [ordered]@{ mail = $context.mail_gitlink; tool = $context.tool_gitlink }
        platforms = $context.platforms
        invocations = $Invocations
        checklist = $checklist
        totals = $totals
        verification = [ordered]@{ exit_code = $verifyExit; manifest_checks = $verification.manifest_checks }
        warnings = $Warnings
    }
    $summaryPath = Join-Path $AbsoluteOutputDir 'build-summary.json'
    Write-JsonFile $summaryPath $summary

    $checklistPath = Join-Path $AbsoluteOutputDir 'checklist.txt'
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("EvernightLogin/EvernightMail one-click build checklist (format=1)")
    $lines.Add("version=$Version tool=$ToolSHA go=$($context.go_version)")
    foreach ($item in $checklist) {
        $lines.Add(("{0}  {1}  {2}/{3}  {4}/{5}  size={6}  sha256={7}  {8}" -f
            $item.status, $item.product, $item.goos, $item.goarch, $item.type, $item.arch,
            $item.size, $item.sha256, $item.path))
    }
    $lines.Add(("TOTAL expected={0} verified={1} failed={2}" -f $totals.expected, $totals.verified, $totals.failed))
    [System.IO.File]::WriteAllText($checklistPath, (($lines -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))

    [System.IO.File]::WriteAllText($logPath, (($StdoutLog -join "`n") + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Step "build-summary: $summaryPath"
    Write-Step "checklist:    $checklistPath"
    Write-Step ("Done. verified={0}/{1} failed={2} warnings={3} exit=0" -f $totals.verified, $totals.expected, $totals.failed, $Warnings.Count)
    exit 0
} catch {
    $stage = if ($null -ne $currentStage) { $currentStage } else { 'internal' }
    $code = 40
    if ($stage -eq 'preflight' -or $stage -eq 'output-dir') { $code = 10 }
    Write-Host ("BUILD-ALL ERROR ({0}): {1}" -f $stage, $_.Exception.Message)
    exit $code
}
