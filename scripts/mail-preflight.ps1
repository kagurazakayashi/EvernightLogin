# EvernightMail submodule preflight (read-only).
#
# Checks the parent-repo .gitmodules entry, the EvernightMail checkout, its
# module metadata, Go toolchain, optional gitlink pinning and (with -Build)
# whether cmd/evernightmail can be built in an external temporary directory.
#
# This script never commits, stages, pushes, fetches, initializes submodules,
# or writes inside the EvernightMail checkout. Build artifacts go to the
# current user's TEMP directory and are removed before exit.
#
# Usage (from the parent repository):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-preflight.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-preflight.ps1 -Build
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-preflight.ps1 -RequireMail -RequirePinned -Build
#
# Exit codes:
#   0  ok (or Mail absent and -RequireMail was not specified; warning printed)
#   1  Mail is present but a check failed (module metadata, git state, build)
#   2  Mail is required (-RequireMail) but the submodule directory is absent
#   3  Mail is present but not pinned to a committed gitlink and
#      -RequirePinned was specified
#
# Windows PowerShell 5.1 and PowerShell 7 compatible. Messages are ASCII.

[CmdletBinding()]
param(
    [switch]$Build,
    [switch]$RequireMail,
    [switch]$RequirePinned,
    [switch]$Quiet,
    [ValidateRange(0, 1024)]
    [int]$Parallel = 0
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$mailDir = Join-Path $root 'EvernightMail'
$failed = $false
$pinnedFailures = $false
$madeTemp = $null

function Write-Info {
    param([string]$Message)
    if (-not $Quiet) { Write-Host $Message }
}
function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}
function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
    $script:failed = $true
}
function Write-PinnedFail {
    param([string]$Message)
    Write-Host "[PIN-FAIL] $Message" -ForegroundColor Yellow
    $script:pinnedFailures = $true
}
function Get-GitOutput {
    param([string[]]$Arguments, [string]$WorkingDirectory)
    try {
        Push-Location $WorkingDirectory
        try {
            $output = & git @Arguments 2>&1
            return [pscustomobject]@{ Code = $LASTEXITCODE; Text = ($output -join "`n").Trim() }
        } finally {
            Pop-Location
        }
    } catch {
        return [pscustomobject]@{ Code = 127; Text = $_.Exception.Message }
    }
}

Write-Info "mail preflight: parent=$root"

# 1) Directory presence.
if (-not (Test-Path -LiteralPath $mailDir -PathType Container)) {
    $hint = "EvernightMail 子模块未初始化。用户需在父仓库执行: git submodule update --init --recursive EvernightMail"
    if ($RequireMail) {
        Write-Fail $hint
        Write-Host "缺少 Mail 时为 required 模式，返回 2。" -ForegroundColor Red
        exit 2
    }
    Write-Warn $hint
    Write-Warn "开发/发布主项目检查可继续；设置 -RequireMail 可把缺失视为失败。"
    exit 0
}

# 2) .gitmodules entry.
$gitmodulesPath = Join-Path $root '.gitmodules'
if (-not (Test-Path -LiteralPath $gitmodulesPath -PathType Leaf)) {
    Write-Fail ".gitmodules 不存在：无法确认 EvernightMail 的注册路径/URL。"
} else {
    $gitmodules = Get-Content -LiteralPath $gitmodulesPath -Raw -ErrorAction SilentlyContinue
    if ($gitmodules -notmatch '(?m)^\s*path\s*=\s*EvernightMail\s*$') {
        Write-Fail ".gitmodules 未声明 path = EvernightMail（目录存在但注册不一致）。"
    }
    if ($gitmodules -notmatch '(?m)^\[submodule\s+"EvernightMail"\]\s*$') {
        Write-Warn ".gitmodules 中未找到 [submodule \"EvernightMail\"] 段，请人工核对。"
    }
    Write-Info ".gitmodules: found EvernightMail entry"
}

# 3) Parent gitlink state (read-only). Untracked .gitmodules / no gitlink means
#    the checkout is not yet a reproducible pinned submodule revision.
$gitlink = Get-GitOutput -Arguments @('ls-files', '--stage', '--', 'EvernightMail') -WorkingDirectory $root
if ($gitlink.Code -ne 0) {
    Write-Warn "无法读取父仓库 gitlink 状态: $($gitlink.Text)"
} elseif ([string]::IsNullOrWhiteSpace($gitlink.Text)) {
    Write-PinnedFail "EvernightMail 未被父仓库跟踪为 gitlink（无 gitlink/可能 .gitmodules 未暂存）；不能称为已固定的可复现版本。"
} else {
    Write-Info "parent gitlink: $($gitlink.Text)"
    if ($gitlink.Text -notmatch '^160000\s+([0-9a-f]{40})\s+0\s+EvernightMail$') {
        Write-PinnedFail "父仓库 EvernightMail 条目不是预期的 160000 gitlink。"
    }
}

# 4) Mail repository state (never writes).
$mailHead = Get-GitOutput -Arguments @('rev-parse', '--verify', 'HEAD') -WorkingDirectory $mailDir
if ($mailHead.Code -ne 0 -or [string]::IsNullOrWhiteSpace($mailHead.Text)) {
    Write-PinnedFail "EvernightMail 仓库尚无提交（HEAD 不存在）；需用户先提交 Mail 成果，再更新父仓库 gitlink。"
} else {
    Write-Info "Mail HEAD: $($mailHead.Text)"
    $mailStatus = Get-GitOutput -Arguments @('status', '--porcelain') -WorkingDirectory $mailDir
    if ($mailStatus.Code -eq 0 -and -not [string]::IsNullOrWhiteSpace($mailStatus.Text)) {
        Write-Warn "EvernightMail 工作树存在未提交改动；未提交目录不得称为可复现版本。"
        Write-PinnedFail "EvernightMail 工作树不干净（-RequirePinned 需要干净且已提交的指针）。"
    }
}

# 5) Module metadata and toolchain.
$mailGoMod = Join-Path $mailDir 'go.mod'
if (-not (Test-Path -LiteralPath $mailGoMod -PathType Leaf)) {
    Write-Fail "EvernightMail/go.mod 不存在；无法判断独立模块。"
} else {
    $goModText = Get-Content -LiteralPath $mailGoMod -Raw
    if ($goModText -notmatch '(?m)^module\s+github\.com/kagurazakayashi/EvernightMail\s*$') {
        Write-Fail "EvernightMail/go.mod 的 module 路径不是 github.com/kagurazakayashi/EvernightMail。"
    }
    $goDirective = 'unknown'
    if ($goModText -match '(?m)^go\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)') { $goDirective = $Matches[1] }
    Write-Info "Mail go directive: $goDirective"
}
$goVersionLine = (& go version 2>&1) -join ' '
if ($LASTEXITCODE -ne 0) {
    Write-Fail "当前 PATH 中的 Go 不可用；Mail 独立构建需要 Go（步骤 137 验收为 Go 1.27+）。"
} else {
    Write-Info "Go toolchain: $goVersionLine"
    if ($goVersionLine -notmatch 'go1\.(2[7-9]|[3-9][0-9])') {
        Write-Warn "当前 Go 版本可能低于 Mail 的 go 1.27 要求；构建可能失败。"
    }
}

# 6) Optional existing binary and external build.
if ($env:EVERNIGHTMAIL_BIN) {
    if (Test-Path -LiteralPath $env:EVERNIGHTMAIL_BIN) {
        Write-Info "EVERNIGHTMAIL_BIN: $env:EVERNIGHTMAIL_BIN"
    } else {
        Write-Warn "EVERNIGHTMAIL_BIN 已设置但文件不存在: $env:EVERNIGHTMAIL_BIN"
    }
}
if ($Build) {
    $cores = [Environment]::ProcessorCount
    $limit = [Math]::Max(1, [Math]::Floor($cores / 2))
    if ($Parallel -eq 0) { $Parallel = $limit }
    elseif ($Parallel -gt $limit) { throw "Concurrency cap is $limit (half of $cores logical processors); refusing $Parallel." }
    $tempBin = Join-Path ([IO.Path]::GetTempPath()) ("evernightmail-preflight-" + [guid]::NewGuid().ToString('N') + ".exe")
    $oldGoToolchain = $env:GOTOOLCHAIN
    $oldCGO = $env:CGO_ENABLED
    $oldGoMaxProcs = $env:GOMAXPROCS
    $oldGoFlags = $env:GOFLAGS
    try {
        $env:GOTOOLCHAIN = 'local'
        $env:CGO_ENABLED = '0'
        $env:GOMAXPROCS = "$Parallel"
        $env:GOFLAGS = '-mod=readonly'
        Push-Location $mailDir
        try {
            & go build -trimpath -buildvcs=false -o $tempBin ./cmd/evernightmail
            if ($LASTEXITCODE -ne 0) {
                Write-Fail "Mail 独立构建失败（go build ./cmd/evernightmail）。"
            } else {
                Write-Info "Mail build ok: $tempBin (temporary; removed after check)"
                $versionText = (& $tempBin version 2>&1) -join "`n"
                if ($versionText.Trim().Length -gt 0) {
                    $firstLine = ($versionText -split "`n")[0].Trim()
                    Write-Info "Mail version: $firstLine"
                }
            }
        } finally {
            Pop-Location
        }
    } finally {
        $env:GOTOOLCHAIN = $oldGoToolchain
        $env:CGO_ENABLED = $oldCGO
        $env:GOMAXPROCS = $oldGoMaxProcs
        $env:GOFLAGS = $oldGoFlags
        if (Test-Path -LiteralPath $tempBin) { Remove-Item -LiteralPath $tempBin -Force -ErrorAction SilentlyContinue }
    }
}

if ($pinnedFailures) {
    if ($RequirePinned) {
        Write-Host 'MAIL PREFLIGHT FAILED (not pinned/clean)' -ForegroundColor Red
        exit 3
    }
    Write-Warn "存在未固定/不干净状态；设置 -RequirePinned 可把它视为失败。"
}
if ($failed) {
    Write-Host 'MAIL PREFLIGHT FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'MAIL PREFLIGHT PASSED' -ForegroundColor Green
exit 0
