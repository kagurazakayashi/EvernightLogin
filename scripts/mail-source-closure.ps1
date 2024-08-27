# EvernightMail 固定版本源码闭包检查（步骤 249，只读）
#
# 用途：在全新临时目录重建父仓库固定提交的源码树，并按
#       「本地交付归档(bundle) -> 本地 Mail 仓库对象 -> 远端」的优先顺序，
#       取得父仓库 gitlink 固定的 EvernightMail 提交；核对实际对象 ID 与工作树是否干净，
#       可选地在该隔离副本上独立构建 Mail，并输出机器可读清单（-ManifestOut）。
#
# 边界：只读。不执行 git add/commit/push；不写父仓库与 Mail 工作树；不初始化/更新用户子模块；
#       不覆盖或推送远端历史；临时文件全部位于 -WorkRoot，默认结束前删除（-Keep 保留）。
#       远端探测失败只记录诊断，不伪造成功；本脚本不要求用户手工装环境。
#
# 诊断码（同时写入 stdout 与清单 diagnostics）：
#   PIN-MISSING              父仓库固定提交没有把 EvernightMail 记录为 gitlink(160000)
#   PIN-MISMATCH             固定指针无法解析/格式异常
#   URL-MISMATCH             .gitmodules 中的 EvernightMail 地址不符合预期
#   BUNDLE-NOT-FOUND         指定/自动发现的交付归档(bundle)不存在
#   BUNDLE-CORRUPT           交付归档校验失败（git bundle verify 非 0）
#   BUNDLE-PIN-MISSING       交付归档有效但不包含固定提交对象
#   LOCAL-OBJECT-MISSING     本地 Mail 仓库缺少固定提交对象（或本地仓库不可用）
#   REMOTE-AUTH-FAILED       远端认证失败
#   REMOTE-OBJECT-MISSING    远端不提供固定提交对象（未广告/不可达）
#   REMOTE-URL-INVALID       远端仓库地址无效或不存在
#   REMOTE-NETWORK-FAILED    远端网络不可达/超时
#   CHECKOUT-MISMATCH        取到的工作树 HEAD 或干净状态与固定指针不符
#   BUILD-FAILED             隔离副本独立构建失败
#
# 退出码：0 通过；1 用法/内部错误；2 固定指针；3 仓库地址；4 交付归档；
#         5 本地缺少对象；6 远端认证；7 远端缺少对象；8 远端网络；9 工作树核对；10 构建。
#
# 用法（在父仓库根目录）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -Build -ManifestOut dist\release\mail-source-closure.json
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -Source local
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -Source remote -AllowRemote -Proxy http://127.0.0.1:23333
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure.ps1 -SelfTest
#
# Windows PowerShell 5.1 与 PowerShell 7 兼容；文件以 UTF-8 BOM 保存，保证 5.1 中文输出正确。

[CmdletBinding()]
param(
    # 父仓库路径，默认本脚本上一级目录（EvernightLogin 根目录）
    # 注意：PowerShell 5.1 在 param 默认值阶段不填充 $PSScriptRoot，故留空后在下方解析
    [string]$ParentRepo = '',
    # 要核对的父仓库固定提交，默认 HEAD；其 gitlink 才是「固定子模块版本」
    [string]$ParentCommit = 'HEAD',
    # 固定提交来源优先级：auto = bundle -> local -> remote(需 -AllowRemote)
    [ValidateSet('auto', 'bundle', 'local', 'remote')]
    [string]$Source = 'auto',
    # 显式指定交付归档；auto 模式会依次尝试 dist/release/EvernightMail-<短号>.bundle 与 dist/release/*.bundle
    [string]$Bundle = '',
    # 本地 Mail 仓库路径，默认 <ParentRepo>/EvernightMail
    [string]$MailRepo = '',
    # 远端地址覆盖；默认取固定提交里 .gitmodules 的 url
    [string]$RemoteUrl = '',
    # 仅访问远端时需要显式允许，避免无意触网
    [switch]$AllowRemote,
    # 远端/网络 git 命令的 HTTP(S) 代理，例如 http://127.0.0.1:23333
    [string]$Proxy = '',
    # .gitmodules 地址的预期正则（默认项目正式远端）
    [string]$ExpectedUrlPattern = 'github\.com[:/]kagurazakayashi/EvernightMail(\.git)?$',
    # 临时工作目录；默认系统 TEMP 下唯一子目录，结束前删除
    [string]$WorkRoot = '',
    # 机器可读清单输出路径；默认 dist/release/mail-source-closure.json
    [string]$ManifestOut = '',
    # 在隔离副本上额外执行 go build/govet 与二进制 version 检查
    [switch]$Build,
    # 额外完整检出父仓库固定版本的整个源码树（慢盘上较慢；默认只取对象并检出 .gitmodules）
    [switch]$FullParentCheckout,
    # 保留临时工作目录（默认删除，避免遗留大文件）
    [switch]$Keep,
    # 单条网络 git 操作超时（秒）
    [ValidateRange(10, 900)]
    [int]$TimeoutSec = 120,
    # 只做失败分类自检，不访问仓库
    [switch]$SelfTest
)

$ErrorActionPreference = 'Continue'
$script:Diagnostics = New-Object System.Collections.ArrayList
$script:Result = [ordered]@{}
$script:WorkRootCreated = $false
$script:WorkRootForCleanup = $null
# -ParentRepo 默认值在 param 阶段无法取 $PSScriptRoot（PowerShell 5.1 行为），在此补全
if ([string]::IsNullOrWhiteSpace($ParentRepo)) { $ParentRepo = Split-Path -Parent $PSScriptRoot }

function Write-InfoLine { param([string]$Message) Write-Host $Message }
function Write-OkLine { param([string]$Message) Write-Host "[ OK ] $Message" -ForegroundColor Green }
function Write-WarnLine { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-FailLine { param([string]$Message) Write-Host "[FAIL] $Message" -ForegroundColor Red }

# 记录一条诊断；返回该诊断码对应的退出码，便于调用点直接 return
function Add-Diag {
    param(
        [ValidateSet('error', 'warning')][string]$Severity = 'error',
        [string]$Code,
        [string]$Message,
        [string]$Hint = '',
        [int]$ExitCode = 1
    )
    [void]$script:Diagnostics.Add([ordered]@{
            severity = $Severity
            code     = $Code
            message  = $Message
            hint     = $Hint
        })
    $line = "$Code`: $Message"
    if ($Severity -eq 'error') { Write-FailLine $line } else { Write-WarnLine $line }
    if ($Hint) { Write-Host "       提示: $Hint" }
    return $ExitCode
}

# 普通 git 调用（不触网、无超时需求）
function Invoke-Git {
    param([string[]]$Arguments, [string]$WorkingDirectory)
    $out = & git -C $WorkingDirectory @Arguments 2>&1
    $text = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
    return [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
}

# 转换单个参数为进程命令行可用的形式（路径可能含空格）
function ConvertTo-QuotedArg {
    param([string]$Value)
    if ($Value -match '[\s"]') {
        return '"' + ($Value -replace '"', '\"') + '"'
    }
    return $Value
}

# 带超时的 git 调用（网络操作使用）；超时返回 Code=-1 并标记 TimedOut
function Invoke-GitTimed {
    param(
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [int]$TimeoutSec,
        [hashtable]$ExtraEnvironment = @{}
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'git'
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-QuotedArg $_ }) -join ' ')
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    foreach ($key in $ExtraEnvironment.Keys) {
        $psi.EnvironmentVariables[$key] = [string]$ExtraEnvironment[$key]
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    try {
        [void]$process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        $exited = $process.WaitForExit($TimeoutSec * 1000)
        if (-not $exited) {
            try { $process.Kill() } catch { }
            [void]$process.WaitForExit(5000)
            return [pscustomobject]@{ Code = -1; Text = "TIMEOUT after ${TimeoutSec}s"; TimedOut = $true }
        }
        $text = ((($outTask.Result) + "`n" + ($errTask.Result))).Trim()
        return [pscustomobject]@{ Code = $process.ExitCode; Text = $text; TimedOut = $false }
    } finally {
        try { $process.Dispose() } catch { }
    }
}

# 把 git 失败文本归类，供「本地缺对象 / 认证失败 / 地址错误 / 网络失败」的清晰诊断使用
function Get-FailureClass {
    param([string]$Text)
    $t = [string]$Text
    if ($t -match '(?i)permission denied \(publickey\)|authentication failed|could not read username|could not read password|terminal prompts disabled|no such identity|host key verification failed') {
        return 'auth'
    }
    if ($t -match '(?i)not our ref|unadvertised object|couldn''t find remote ref|remote ref does not exist|did not send all necessary objects|missing necessary objects') {
        return 'object'
    }
    if ($t -match '(?i)does not appear to be a git repository|repository .*not found|returned error: 404|invalid repository|not a git repository|is this a git repository|no such file or directory') {
        return 'url'
    }
    if ($t -match '(?i)could not resolve host|connection timed out|connection refused|failed to connect|network is unreachable|connection reset|unable to access|timed out') {
        return 'network'
    }
    return 'unknown'
}

# 远端失败分类 -> 诊断码/退出码/修复提示
function Get-RemoteFailureDiagnostic {
    param([string]$Text)
    switch (Get-FailureClass $Text) {
        'auth' {
            return [pscustomobject]@{
                Code = 'REMOTE-AUTH-FAILED'; ExitCode = 6
                Message = '远端认证失败：当前环境没有可用于该仓库的凭据，或凭据被拒绝。'
                Hint = '配置只读凭据后重试，或改用 -Source bundle 交付归档；不要把口令写进脚本、日志或报告。'
            }
        }
        'object' {
            return [pscustomobject]@{
                Code = 'REMOTE-OBJECT-MISSING'; ExitCode = 7
                Message = '远端不提供固定提交对象（未广告/不可达）：固定版本无法从远端取得。'
                Hint = '固定提交尚未推送到远端可达引用；维护者推送后重跑，或使用交付归档(bundle)。不得用旧 main 冒充固定版本。'
            }
        }
        'url' {
            return [pscustomobject]@{
                Code = 'REMOTE-URL-INVALID'; ExitCode = 3
                Message = '远端仓库地址无效或不存在。'
                Hint = '核对 .gitmodules 的 url 与 -RemoteUrl；必要时用 -ExpectedUrlPattern 显式限定。'
            }
        }
        'network' {
            return [pscustomobject]@{
                Code = 'REMOTE-NETWORK-FAILED'; ExitCode = 8
                Message = '远端网络不可达/超时。'
                Hint = '按项目顺序尝试代理(-Proxy)或直连；仍失败时记录阻塞并用 bundle 交付归档。'
            }
        }
        default {
            return [pscustomobject]@{
                Code = 'REMOTE-UNKNOWN-ERROR'; ExitCode = 8
                Message = '远端操作失败，无法归类。'
                Hint = '查看上方 git 原始输出并人工判断；不要把未归类失败当作成功。'
            }
        }
    }
}

# 失败分类自检（不访问网络；含一次真实远端错误文本）
function Invoke-SelfTest {
    $cases = @(
        @{ Name = 'remote object (real captured)'; Text = "fatal: remote error: upload-pack: not our ref aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa"; Expect = 'object' },
        @{ Name = 'remote ref missing'; Text = "fatal: couldn't find remote ref refs/heads/nope"; Expect = 'object' },
        @{ Name = 'ssh auth denied'; Text = "git@github.com: Permission denied (publickey).`nfatal: Could not read from remote repository."; Expect = 'auth' },
        @{ Name = 'https auth failed'; Text = "fatal: Authentication failed for 'https://github.com/x/y.git/'"; Expect = 'auth' },
        @{ Name = 'terminal prompt disabled'; Text = "fatal: could not read Username for 'https://github.com': terminal prompts disabled"; Expect = 'auth' },
        @{ Name = 'repository not found'; Text = "remote: Repository not found.`nfatal: repository 'https://github.com/x/none.git/' not found"; Expect = 'url' },
        @{ Name = 'local dir not repo'; Text = "fatal: '/nonexistent/dir' does not appear to be a git repository"; Expect = 'url' },
        @{ Name = 'dns failure'; Text = "fatal: unable to access 'https://none.invalid/x.git/': Could not resolve host: none.invalid"; Expect = 'network' },
        @{ Name = 'connect timeout'; Text = "fatal: unable to access 'https://x.invalid/': Connection timed out"; Expect = 'network' }
    )
    Write-InfoLine "mail-source-closure self-test: failure classification ($($cases.Count) cases)"
    $failed = 0
    foreach ($case in $cases) {
        $actual = Get-FailureClass $case.Text
        if ($actual -eq $case.Expect) {
            Write-OkLine ("classify {0} -> {1}" -f $case.Name, $actual)
        } else {
            $failed++
            Write-FailLine ("classify {0} -> got '{1}', expected '{2}'" -f $case.Name, $actual, $case.Expect)
        }
    }
    if ($failed -gt 0) {
        Write-FailLine "SELF-TEST FAILED ($failed/$($cases.Count))"
        return 1
    }
    Write-OkLine "SELF-TEST PASSED ($($cases.Count)/$($cases.Count))"
    return 0
}

# 读取父仓库固定提交的 gitlink（160000 commit <sha> EvernightMail）
function Get-GitlinkPin {
    param([string]$Repo, [string]$Commit)
    $ls = Invoke-Git @('ls-tree', $Commit, '--', 'EvernightMail') $Repo
    if ($ls.Code -ne 0) {
        return [pscustomobject]@{ Ok = $false; Reason = 'ls-tree 失败'; Sha = $null; Mode = $null; Text = $ls.Text }
    }
    if ([string]::IsNullOrWhiteSpace($ls.Text)) {
        return [pscustomobject]@{ Ok = $false; Reason = '固定提交中不存在 EvernightMail 条目'; Sha = $null; Mode = $null; Text = '' }
    }
    if ($ls.Text -match '^(\d{6})\s+(\w+)\s+([0-9a-f]{40})\s+(EvernightMail)$') {
        return [pscustomobject]@{ Ok = ($Matches[1] -eq '160000'); Reason = "gitlink 模式为 $($Matches[1])"; Sha = $Matches[3]; Mode = $Matches[1]; Text = $ls.Text }
    }
    return [pscustomobject]@{ Ok = $false; Reason = 'EvernightMail 条目格式异常'; Sha = $null; Mode = $null; Text = $ls.Text }
}

# 交付归档候选：显式 -Bundle > dist/release/EvernightMail-<短号>.bundle > dist/release/*.bundle
function Find-BundleCandidates {
    param([string]$ParentRepo, [string]$PinShort, [string]$Explicit)
    $list = New-Object System.Collections.ArrayList
    if ($Explicit) {
        [void]$list.Add([pscustomobject]@{ Path = $Explicit; Explicit = $true })
        return $list
    }
    $releaseDir = Join-Path $ParentRepo 'dist\release'
    if (Test-Path -LiteralPath $releaseDir -PathType Container) {
        $preferred = Join-Path $releaseDir ("EvernightMail-{0}.bundle" -f $PinShort)
        if (Test-Path -LiteralPath $preferred -PathType Leaf) {
            [void]$list.Add([pscustomobject]@{ Path = $preferred; Explicit = $false })
        }
        foreach ($file in (Get-ChildItem -LiteralPath $releaseDir -Filter '*.bundle' -File | Sort-Object Name)) {
            if ($file.FullName -ne $preferred) {
                [void]$list.Add([pscustomobject]@{ Path = $file.FullName; Explicit = $false })
            }
        }
    }
    return $list
}

# 从 bundle 取得固定提交到目标目录；失败返回退出码
# Severity=warning 用于 auto 模式的非显式候选：失败后仍允许回退到本地对象，但保留诊断记录
function Get-MailFromBundle {
    param([string]$BundlePath, [string]$Pin, [string]$Dest, [string]$Severity = 'error', [string]$RepoDir = '')
    # git bundle verify 必须在一个 git 仓库内执行；优先用已建好的全新临时父仓库
    $verifyDir = if ($RepoDir) { $RepoDir } else { Split-Path -Parent $BundlePath }
    if (-not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) {
        return (Add-Diag -Severity $Severity -Code 'BUNDLE-NOT-FOUND' -Message ("交付归档不存在: {0}" -f $BundlePath) `
                -Hint '用 git -C EvernightMail bundle create <文件> HEAD refs/heads/main 生成，或改用 -Source local。' -ExitCode 4)
    }
    $verify = Invoke-Git @('bundle', 'verify', $BundlePath) $verifyDir
    if ($verify.Code -ne 0) {
        return (Add-Diag -Severity $Severity -Code 'BUNDLE-CORRUPT' -Message ("交付归档校验失败: {0}" -f $BundlePath) `
                -Hint ("git bundle verify 输出: " + ($verify.Text -replace "`n", ' | ')) -ExitCode 4)
    }
    $heads = Invoke-Git @('bundle', 'list-heads', $BundlePath) $verifyDir
    $containsPin = ($heads.Text -split "`n" | Where-Object { $_ -match ('^' + $Pin) }).Count -gt 0
    if (-not $containsPin) {
        # 归档有效但固定提交不在其中：再克隆后判定对象缺失，避免误报
        $probe = Join-Path (Split-Path -Parent $Dest) ("bundle-probe-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        $clone = Invoke-GitTimed @('clone', '--no-hardlinks', '--quiet', $BundlePath, $probe) (Split-Path -Parent $Dest) 120
        $has = $false
        if ($clone.Code -eq 0) {
            # 注意：本机 MSYS2 git 会改写 `^{commit}` 参数，这里不用 rev 语法，改用 cat-file 类型判断
            $check = Invoke-Git @('cat-file', '-e', $Pin) $probe
            if ($check.Code -eq 0) {
                $type = Invoke-Git @('cat-file', '-t', $Pin) $probe
                $has = ($type.Text.Trim() -eq 'commit')
            }
        }
        if (Test-Path -LiteralPath $probe) { Remove-Item -LiteralPath $probe -Recurse -Force -ErrorAction SilentlyContinue }
        if (-not $has) {
            return (Add-Diag -Severity $Severity -Code 'BUNDLE-PIN-MISSING' -Message ("交付归档不包含固定提交 {0}" -f $Pin) `
                    -Hint '归档来自旧版本/其他分支；重新用固定提交生成 bundle，禁止用旧版本冒充固定版本。' -ExitCode 4)
        }
    }
    $clone = Invoke-GitTimed @('clone', '--no-hardlinks', '--quiet', $BundlePath, $Dest) (Split-Path -Parent $Dest) $TimeoutSec
    if ($clone.Code -ne 0) {
        return (Add-Diag -Severity $Severity -Code 'BUNDLE-CORRUPT' -Message ("从交付归档克隆失败: {0}" -f $BundlePath) `
                -Hint ($clone.Text -replace "`n", ' | ') -ExitCode 4)
    }
    $checkout = Invoke-Git @('checkout', '--detach', $Pin) $Dest
    if ($checkout.Code -ne 0) {
        return (Add-Diag -Severity $Severity -Code 'BUNDLE-PIN-MISSING' -Message ("交付归档克隆后无法检出固定提交 {0}" -f $Pin) `
                -Hint ($checkout.Text -replace "`n", ' | ') -ExitCode 4)
    }
    return 0
}

# 从本地 Mail 仓库取得固定提交；本地缺对象是最常见的「不可复现」原因
function Get-MailFromLocal {
    param([string]$RepoPath, [string]$Pin, [string]$Dest, [string]$Severity = 'error')
    if ([string]::IsNullOrWhiteSpace($RepoPath) -or -not (Test-Path -LiteralPath $RepoPath -PathType Container)) {
        return (Add-Diag -Severity $Severity -Code 'LOCAL-OBJECT-MISSING' -Message ("本地 Mail 仓库不存在: {0}" -f $RepoPath) `
                -Hint '设置 -MailRepo 指向本机 EvernightMail 检出目录，或改用 bundle 交付归档。' -ExitCode 5)
    }
    $isRepo = Invoke-Git @('rev-parse', '--git-dir') $RepoPath
    if ($isRepo.Code -ne 0) {
        return (Add-Diag -Severity $Severity -Code 'LOCAL-OBJECT-MISSING' -Message ("本地路径不是 git 仓库: {0}" -f $RepoPath) `
                -Hint '确认 Mail 子模块已初始化；不要用普通目录冒充固定源码。' -ExitCode 5)
    }
    $hasObject = Invoke-Git @('cat-file', '-e', $Pin) $RepoPath
    $objectType = ''
    if ($hasObject.Code -eq 0) { $objectType = (Invoke-Git @('cat-file', '-t', $Pin) $RepoPath).Text.Trim() }
    if ($hasObject.Code -ne 0 -or $objectType -ne 'commit') {
        $typeText = if ($objectType) { $objectType } else { '缺失' }
        return (Add-Diag -Severity $Severity -Code 'LOCAL-OBJECT-MISSING' -Message ("本地 Mail 仓库缺少固定提交对象 {0}（实际: {1}）" -f $Pin, $typeText) `
                -Hint '本地未包含该提交（可能未 fetch/被清理）；从交付归档(bundle)取得，或先由维护者推送后从远端获取。' -ExitCode 5)
    }
    $clone = Invoke-GitTimed @('clone', '--no-hardlinks', '--quiet', $RepoPath, $Dest) (Split-Path -Parent $Dest) $TimeoutSec
    if ($clone.Code -ne 0) {
        return (Add-Diag -Severity $Severity -Code 'LOCAL-OBJECT-MISSING' -Message ("从本地 Mail 仓库克隆失败: {0}" -f $RepoPath) `
                -Hint ($clone.Text -replace "`n", ' | ') -ExitCode 5)
    }
    $checkout = Invoke-Git @('checkout', '--detach', $Pin) $Dest
    if ($checkout.Code -ne 0) {
        return (Add-Diag -Severity $Severity -Code 'LOCAL-OBJECT-MISSING' -Message ("克隆后无法检出固定提交 {0}" -f $Pin) `
                -Hint ($checkout.Text -replace "`n", ' | ') -ExitCode 5)
    }
    return 0
}

# 从远端取得固定提交；需要 -AllowRemote。优先按 SHA fetch，便于直接把「远端无此对象」诊断出来
function Get-MailFromRemote {
    param([string]$Url, [string]$Pin, [string]$Dest, [int]$TimeoutSec, [string]$Proxy)
    if ([string]::IsNullOrWhiteSpace($Url)) {
        return (Add-Diag -Code 'REMOTE-URL-INVALID' -Message '远端地址为空（.gitmodules 未提供 url）' `
                -Hint '修正 .gitmodules 的 EvernightMail url，或用 -RemoteUrl 显式指定。' -ExitCode 3)
    }
    $init = Invoke-Git @('init', '--quiet', $Dest) (Split-Path -Parent $Dest)
    if ($init.Code -ne 0) {
        return (Add-Diag -Code 'REMOTE-UNKNOWN-ERROR' -Message '远端隔离目录初始化失败' -Hint ($init.Text -replace "`n", ' | ') -ExitCode 8)
    }
    $gitArgs = @('-c', 'credential.helper=')
    if ($Proxy) { $gitArgs += @('-c', "http.proxy=$Proxy", '-c', "https.proxy=$Proxy") }
    $gitArgs += @('fetch', '--no-tags', '--quiet', $Url, $Pin)
    $envExtra = @{
        GIT_TERMINAL_PROMPT = '0'
        GIT_SSH_COMMAND     = 'ssh -o BatchMode=yes -o ConnectTimeout=20'
    }
    $fetch = Invoke-GitTimed $gitArgs $Dest $TimeoutSec $envExtra
    if ($fetch.TimedOut) {
        return (Add-Diag -Code 'REMOTE-NETWORK-FAILED' -Message ("远端 git fetch 超时（{0}s）: {1}" -f $TimeoutSec, $Url) `
                -Hint '检查代理/网络，或改用 bundle 交付归档；不要把超时当成功。' -ExitCode 8)
    }
    if ($fetch.Code -ne 0) {
        $diag = Get-RemoteFailureDiagnostic $fetch.Text
        return (Add-Diag -Code $diag.Code -Message ("{0} 远端: {1}" -f $diag.Message, $Url) `
                -Hint ($diag.Hint + " git 原始输出: " + ($fetch.Text -replace "`n", ' | ')) -ExitCode $diag.ExitCode)
    }
    $checkout = Invoke-Git @('checkout', '--detach', $Pin) $Dest
    if ($checkout.Code -ne 0) {
        $diag = Get-RemoteFailureDiagnostic $checkout.Text
        return (Add-Diag -Code $diag.Code -Message ("远端取到对象但检出固定提交 {0} 失败" -f $Pin) `
                -Hint ((($checkout.Text -replace "`n", ' | '))) -ExitCode $diag.ExitCode)
    }
    return 0
}

# 记录实际对象 ID 并按需构建
function Test-ClosureCheckout {
    param([string]$MailDir, [string]$Pin, [bool]$DoBuild)
    $head = Invoke-Git @('rev-parse', '--verify', 'HEAD') $MailDir
    if ($head.Code -ne 0 -or [string]::IsNullOrWhiteSpace($head.Text)) {
        return (Add-Diag -Code 'CHECKOUT-MISMATCH' -Message '隔离副本没有有效 HEAD' -Hint ($head.Text -replace "`n", ' | ') -ExitCode 9)
    }
    $headSha = ($head.Text -split "`n")[0].Trim()
    $tree = (Invoke-Git @('show', '-s', '--format=%T', 'HEAD') $MailDir).Text
    $subject = (Invoke-Git @('show', '-s', '--format=%s', 'HEAD') $MailDir).Text
    $commitDate = (Invoke-Git @('show', '-s', '--format=%cI', 'HEAD') $MailDir).Text
    $commits = (Invoke-Git @('rev-list', '--count', 'HEAD') $MailDir).Text
    $status = Invoke-Git @('status', '--porcelain') $MailDir
    $clean = [string]::IsNullOrWhiteSpace($status.Text)
    $script:Result.checkout = [ordered]@{
        path        = $MailDir
        head        = $headSha
        tree        = $tree
        subject     = $subject
        commit_date = $commitDate
        commits     = $commits
        clean       = $clean
    }
    if ($headSha -ne $Pin) {
        return (Add-Diag -Code 'CHECKOUT-MISMATCH' -Message ("隔离副本 HEAD {0} != 固定提交 {1}" -f $headSha, $Pin) `
                -Hint '来源与父仓库固定指针不一致；不要用其他版本冒充固定版本。' -ExitCode 9)
    }
    if (-not $clean) {
        return (Add-Diag -Code 'CHECKOUT-MISMATCH' -Message '隔离副本工作树不干净（存在未提交改动）' `
                -Hint ("git status 输出: " + ($status.Text -replace "`n", ' | ')) -ExitCode 9)
    }
    Write-OkLine ("fixed mail commit verified: {0} tree={1} commits={2}" -f $headSha, $tree, $commits)
    if (-not $DoBuild) { return 0 }
    if (-not (Test-Path -LiteralPath (Join-Path $MailDir 'go.mod') -PathType Leaf)) {
        return (Add-Diag -Code 'BUILD-FAILED' -Message '隔离副本缺少 go.mod，无法独立构建' -ExitCode 10)
    }
    $cores = [Environment]::ProcessorCount
    $parallel = [Math]::Max(1, [Math]::Floor($cores / 2))
    $envExtra = @{
        GOTOOLCHAIN = 'local'
        CGO_ENABLED = '0'
        GOMAXPROCS  = [string]$parallel
        GOFLAGS     = '-mod=readonly'
    }
    $buildAll = Invoke-ProcessTimed 'go' @('build', './...') $MailDir $TimeoutSec $envExtra
    $buildOk = ($buildAll.Code -eq 0)
    $script:Result.build = [ordered]@{
        ran          = $true
        go_version   = ((Get-Command go -ErrorAction SilentlyContinue) | ForEach-Object { (& go version 2>&1) } | Select-Object -First 1)
        gomaxprocs   = $parallel
        build_all    = $buildAll.Code
        binary_sha256 = $null
        version      = $null
    }
    if (-not $buildOk) {
        return (Add-Diag -Code 'BUILD-FAILED' -Message '隔离副本 go build ./... 失败' `
                -Hint ($buildAll.Text -replace "`n", ' | ') -ExitCode 10)
    }
    $binName = if ($IsWindows -or $PSVersionTable.PSVersion.Major -le 5) { 'evernightmail-closure-check.exe' } else { 'evernightmail-closure-check' }
    $binPath = Join-Path $MailDir $binName
    $buildCmd = Invoke-ProcessTimed 'go' @('build', '-trimpath', '-buildvcs=false', '-o', $binPath, './cmd/evernightmail') $MailDir $TimeoutSec $envExtra
    if ($buildCmd.Code -ne 0) {
        return (Add-Diag -Code 'BUILD-FAILED' -Message '隔离副本 go build ./cmd/evernightmail 失败' `
                -Hint ($buildCmd.Text -replace "`n", ' | ') -ExitCode 10)
    }
    $script:Result.build.binary_sha256 = (Get-FileHash -LiteralPath $binPath -Algorithm SHA256).Hash.ToLower()
    $versionRun = Invoke-ProcessTimed $binPath @('version') $MailDir $TimeoutSec @{}
    $script:Result.build.version = ($versionRun.Text -split "`n")[0].Trim()
    Write-OkLine ("isolated build ok: sha256={0} version={1}" -f $script:Result.build.binary_sha256, $script:Result.build.version)
    return 0
}

# 带超时的通用进程调用（go 构建使用；输出合并 stdout/stderr）
function Invoke-ProcessTimed {
    param(
        [string]$FileName,
        [string[]]$Arguments,
        [string]$WorkingDirectory,
        [int]$TimeoutSec,
        [hashtable]$ExtraEnvironment = @{}
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FileName
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-QuotedArg $_ }) -join ' ')
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    foreach ($key in $ExtraEnvironment.Keys) {
        $psi.EnvironmentVariables[$key] = [string]$ExtraEnvironment[$key]
    }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    try {
        [void]$process.Start()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSec * 1000)) {
            try { $process.Kill() } catch { }
            [void]$process.WaitForExit(5000)
            return [pscustomobject]@{ Code = -1; Text = "TIMEOUT after ${TimeoutSec}s"; TimedOut = $true }
        }
        $text = ((($outTask.Result) + "`n" + ($errTask.Result))).Trim()
        return [pscustomobject]@{ Code = $process.ExitCode; Text = $text; TimedOut = $false }
    } finally {
        try { $process.Dispose() } catch { }
    }
}

# 写机器可读清单：记录父提交、gitlink、实际对象 ID、来源交付归档摘要与诊断
function Write-ClosureManifest {
    param([string]$Path, [int]$ExitCode, [string]$ResultText)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        $dir = Split-Path -Parent $Path
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $manifest = [ordered]@{
            tool          = 'scripts/mail-source-closure.ps1'
            step          = 249
            generated_at  = (Get-Date).ToString('o')
            platform      = [ordered]@{ os = [Environment]::OSVersion.VersionString; ps = $PSVersionTable.PSVersion.ToString(); git = (& git --version 2>&1) }
            arguments     = [ordered]@{ source = $Source; parent_commit = $ParentCommit; allow_remote = [bool]$AllowRemote; build = [bool]$Build; full_parent_checkout = [bool]$FullParentCheckout }
            parent        = $script:Result.parent
            submodule     = $script:Result.submodule
            delivery      = $script:Result.delivery
            checkout      = $script:Result.checkout
            build         = $script:Result.build
            diagnostics   = @($script:Diagnostics)
            result        = $ResultText
            exit_code     = $ExitCode
        }
        $json = ($manifest | ConvertTo-Json -Depth 8 -Compress:$false)
        [System.IO.File]::WriteAllText($Path, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
        Write-InfoLine "manifest: $Path"
    } catch {
        Write-WarnLine ("清单写入失败: " + $_.Exception.Message)
    }
}

function Invoke-ClosureCheck {
    # 1) 父仓库与固定提交
    $parentFull = [System.IO.Path]::GetFullPath($ParentRepo)
    if (-not (Test-Path -LiteralPath $parentFull -PathType Container)) {
        return (Add-Diag -Code 'PARENT-NOT-FOUND' -Message ("父仓库路径不存在: {0}" -f $parentFull) `
                -Hint '用 -ParentRepo 指定 EvernightLogin 根目录。' -ExitCode 1)
    }
    $isParentRepo = Invoke-Git @('rev-parse', '--git-dir') $parentFull
    if ($isParentRepo.Code -ne 0) {
        return (Add-Diag -Code 'PARENT-NOT-FOUND' -Message ("不是 git 仓库: {0}" -f $parentFull) -ExitCode 1)
    }
    $rev = Invoke-Git @('rev-parse', '--verify', $ParentCommit) $parentFull
    if ($rev.Code -ne 0) {
        return (Add-Diag -Code 'PIN-MISMATCH' -Message ("无法解析父仓库固定提交: {0}" -f $ParentCommit) `
                -Hint ($rev.Text -replace "`n", ' | ') -ExitCode 2)
    }
    $parentSha = ($rev.Text -split "`n")[0].Trim()
    $parentType = (Invoke-Git @('cat-file', '-t', $parentSha) $parentFull).Text.Trim()
    if ($parentType -ne 'commit') {
        return (Add-Diag -Code 'PIN-MISMATCH' -Message ("父仓库固定版本不是提交对象（类型: {0}）" -f $parentType) `
                -Hint '用父仓库提交（而非 tag/树对象）作为 -ParentCommit。' -ExitCode 2)
    }
    $parentTree = (Invoke-Git @('show', '-s', '--format=%T', $parentSha) $parentFull).Text
    $parentSubject = (Invoke-Git @('show', '-s', '--format=%s', $parentSha) $parentFull).Text
    $parentDate = (Invoke-Git @('show', '-s', '--format=%cI', $parentSha) $parentFull).Text
    $script:Result.parent = [ordered]@{
        repo = $parentFull; commit = $parentSha; tree = $parentTree; subject = $parentSubject; commit_date = $parentDate
    }
    Write-InfoLine ("parent fixed commit: {0} ({1})" -f $parentSha, $parentSubject)

    # 2) 固定指针与 .gitmodules（从固定提交读取，避免工作树脏状态混入）
    $pin = Get-GitlinkPin $parentFull $parentSha
    if (-not $pin.Ok) {
        return (Add-Diag -Code 'PIN-MISSING' -Message ("父仓库固定提交 {0} 没有把 EvernightMail 固定为 160000 gitlink：{1}" -f $parentSha, $pin.Reason) `
                -Hint '先在父仓库把 EvernightMail gitlink 指向 Mail 提交（保持 .gitmodules 正确）后再核对；不要用未固定的工作树冒充可复现版本。' -ExitCode 2)
    }
    $pinSha = $pin.Sha
    $gitmodulesText = (Invoke-Git @('show', ($parentSha + ':.gitmodules')) $parentFull).Text
    $subUrl = ''
    $subBranch = ''
    if ($gitmodulesText -match '(?ms)^\s*\[submodule\s+"EvernightMail"\]\s*(.*?)(?=^\s*\[|\z)') {
        $block = $Matches[1]
        if ($block -match '(?m)^\s*url\s*=\s*(.+?)\s*$') { $subUrl = $Matches[1].Trim() }
        if ($block -match '(?m)^\s*branch\s*=\s*(.+?)\s*$') { $subBranch = $Matches[1].Trim() }
    }
    $script:Result.submodule = [ordered]@{
        name = 'EvernightMail'; path = 'EvernightMail'; gitlink_mode = $pin.Mode; gitlink_commit = $pinSha
        url = $subUrl; branch = $subBranch
    }
    if ([string]::IsNullOrWhiteSpace($subUrl)) {
        return (Add-Diag -Code 'URL-MISMATCH' -Message '固定提交的 .gitmodules 没有 EvernightMail url' `
                -Hint '修正 .gitmodules 后重新提交父仓库。' -ExitCode 3)
    }
    if ($subUrl -notmatch $ExpectedUrlPattern) {
        return (Add-Diag -Code 'URL-MISMATCH' -Message ("EvernightMail 地址不符合预期: {0}" -f $subUrl) `
                -Hint ("期望匹配: {0}；确认没有被改到错误仓库/个人分支。" -f $ExpectedUrlPattern) -ExitCode 3)
    }
    Write-OkLine ("pinned gitlink: {0} url={1}" -f $pinSha, $subUrl)

    # 3) 建立全新临时目录，用「全新 git 仓库 + 只抓取固定提交」重建父仓库固定版本。
    #    说明：父仓库源码树默认只检出 .gitmodules（固定对象已完整取到）；不在慢盘上重建
    #    1600+ 个文件，子模块则完整物化并核对。需要完整父源码树时加 -FullParentCheckout。
    $workRoot = $WorkRoot
    if ([string]::IsNullOrWhiteSpace($workRoot)) {
        $workRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("evernight-mail-closure-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    }
    $workRoot = [System.IO.Path]::GetFullPath($workRoot)
    if (Test-Path -LiteralPath $workRoot) {
        return (Add-Diag -Code 'WORKROOT-EXISTS' -Message ("临时目录已存在，为避免误删请换一个: {0}" -f $workRoot) -ExitCode 1)
    }
    New-Item -ItemType Directory -Path $workRoot -Force | Out-Null
    $script:WorkRootCreated = $true
    $script:WorkRootForCleanup = $workRoot
    $freshParent = Join-Path $workRoot 'parent'
    $initParent = Invoke-Git @('init', '--quiet', $freshParent) $workRoot
    if ($initParent.Code -ne 0) {
        return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message '临时父仓库初始化失败' `
                -Hint ($initParent.Text -replace "`n", ' | ') -ExitCode 1)
    }
    # 依次尝试：浅抓取固定版本 -> 完整抓取固定版本 -> 浅抓取 HEAD 后核对固定对象是否已随历史取到
    $fetchVariants = @(
        @('fetch', '--no-tags', '--depth', '1', $parentFull, $ParentCommit),
        @('fetch', '--no-tags', $parentFull, $ParentCommit),
        @('fetch', '--no-tags', '--depth', '1', $parentFull, 'HEAD')
    )
    $fetched = $false
    $fetchError = ''
    foreach ($variant in $fetchVariants) {
        $attempt = Invoke-GitTimed $variant $freshParent $TimeoutSec
        if ($attempt.Code -eq 0) { $fetched = $true; break }
        $fetchError = $attempt.Text
    }
    if (-not $fetched) {
        return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message ("父仓库固定版本无法取到全新临时仓库: {0}" -f $parentSha) `
                -Hint ($fetchError -replace "`n", ' | ') -ExitCode 1)
    }
    $freshType = (Invoke-Git @('cat-file', '-t', $parentSha) $freshParent).Text.Trim()
    if ($freshType -ne 'commit') {
        return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message ("全新临时仓库中没有父仓库固定提交对象 {0}（类型: {1}）" -f $parentSha, $freshType) `
                -Hint '父仓库对象可能被清理/未推送；不能据此宣称可复现。' -ExitCode 1)
    }
    $freshTree = (Invoke-Git @('show', '-s', '--format=%T', $parentSha) $freshParent).Text.Trim()
    if ($freshTree -ne $parentTree) {
        return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message '全新临时仓库中的父固定提交树与源仓库不一致' `
                -Hint ("fresh={0} source={1}" -f $freshTree, $parentTree) -ExitCode 1)
    }
    if ($FullParentCheckout) {
        $coAll = Invoke-GitTimed @('checkout', '-f', '--quiet', $parentSha) $freshParent $TimeoutSec
        if ($coAll.Code -ne 0) {
            return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message '完整检出父仓库固定版本失败' `
                    -Hint ($coAll.Text -replace "`n", ' | ') -ExitCode 1)
        }
    }
    # 至少检出固定提交的 .gitmodules，证明全新副本可物化该文件
    $coGitmodules = Invoke-Git @('checkout', '-f', $parentSha, '--', '.gitmodules') $freshParent
    if ($coGitmodules.Code -ne 0) {
        return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message '无法从全新临时仓库检出固定提交的 .gitmodules' `
                -Hint ($coGitmodules.Text -replace "`n", ' | ') -ExitCode 1)
    }
    $freshModulesPath = Join-Path $freshParent '.gitmodules'
    if (-not (Test-Path -LiteralPath $freshModulesPath -PathType Leaf)) {
        return (Add-Diag -Code 'PARENT-CLONE-FAILED' -Message '全新临时仓库的 .gitmodules 未落盘' -ExitCode 1)
    }
    $freshModules = Get-Content -LiteralPath $freshModulesPath -Raw
    $freshPin = Get-GitlinkPin $freshParent $parentSha
    if (-not $freshPin.Ok -or $freshPin.Sha -ne $pinSha) {
        return (Add-Diag -Code 'CHECKOUT-MISMATCH' -Message '全新父仓库副本中的 gitlink 与固定值不一致' `
                -Hint ("fresh={0} source={1}" -f $freshPin.Sha, $pinSha) -ExitCode 9)
    }
    if ($freshModules -notmatch [regex]::Escape($subUrl)) {
        return (Add-Diag -Code 'URL-MISMATCH' -Message '全新父仓库副本的 .gitmodules 中找不到固定 url' `
                -Hint ("期望: {0}" -f $subUrl) -ExitCode 3)
    }
    $script:Result.parent.fresh_repo = $freshParent
    $script:Result.parent.fresh_clone_gitlink = $freshPin.Sha
    $script:Result.parent.fresh_tree_verified = $true
    $script:Result.parent.full_checkout = [bool]$FullParentCheckout
    Write-OkLine 'fresh parent snapshot materialized from fixed commit (objects + .gitmodules)'

    # 4) 按优先级取得固定子模块
    $mailDest = Join-Path $freshParent 'EvernightMail'
    if (Test-Path -LiteralPath $mailDest) { Remove-Item -LiteralPath $mailDest -Recurse -Force -ErrorAction SilentlyContinue }
    $pinShort = $pinSha.Substring(0, 7)
    $localRepo = $MailRepo
    if ([string]::IsNullOrWhiteSpace($localRepo)) { $localRepo = Join-Path $parentFull 'EvernightMail' }
    $remoteTarget = $RemoteUrl
    if ([string]::IsNullOrWhiteSpace($remoteTarget)) { $remoteTarget = $subUrl }

    $sourceUsed = ''
    $locator = ''
    $lastExit = 0
    # 优先级 1：交付归档(bundle)。显式 -Bundle 失败即失败；auto 发现的候选失败只告警并继续回退。
    if ($Source -eq 'bundle' -or $Source -eq 'auto') {
        $candidates = Find-BundleCandidates $parentFull $pinShort $Bundle
        if ($candidates.Count -eq 0) {
            if ($Source -eq 'bundle' -or $Bundle) {
                $lastExit = Add-Diag -Code 'BUNDLE-NOT-FOUND' -Message '未找到 EvernightMail 交付归档(bundle)' `
                    -Hint '用 -Bundle 指定，或先生成 dist/release/EvernightMail-<短号>.bundle。' -ExitCode 4
            }
        } else {
            foreach ($candidate in $candidates) {
                $severity = if ($candidate.Explicit -or $Source -eq 'bundle') { 'error' } else { 'warning' }
                $tryExit = Get-MailFromBundle $candidate.Path $pinSha $mailDest $severity $freshParent
                if ($tryExit -eq 0) { $sourceUsed = 'bundle'; $locator = $candidate.Path; $lastExit = 0; break }
                $lastExit = $tryExit
                if ($candidate.Explicit -or $Source -eq 'bundle') { break }
                Write-WarnLine ("候选归档不可用，尝试下一个: {0}" -f $candidate.Path)
            }
        }
    }
    # 优先级 2：本地 Mail 仓库对象（离线可用，但要求本地真的含固定提交）
    if ($sourceUsed -eq '' -and ($Source -eq 'local' -or $Source -eq 'auto')) {
        $severity = if ($Source -eq 'local') { 'error' } else { 'warning' }
        $tryExit = Get-MailFromLocal $localRepo $pinSha $mailDest $severity
        if ($tryExit -eq 0) { $sourceUsed = 'local'; $locator = $localRepo; $lastExit = 0 } else { $lastExit = $tryExit }
    }
    # 优先级 3：远端（仅 -AllowRemote；auto 模式作为最后回退）
    if ($sourceUsed -eq '' -and ($Source -eq 'remote' -or ($Source -eq 'auto' -and $AllowRemote))) {
        if (-not $AllowRemote) {
            $lastExit = Add-Diag -Code 'REMOTE-NOT-ALLOWED' -Message '远端取源需要显式 -AllowRemote' `
                -Hint '确认允许访问远端后加 -AllowRemote；否则用 bundle 交付归档。' -ExitCode 8
        } else {
            $tryExit = Get-MailFromRemote $remoteTarget $pinSha $mailDest $TimeoutSec $Proxy
            if ($tryExit -eq 0) { $sourceUsed = 'remote'; $locator = $remoteTarget; $lastExit = 0 } else { $lastExit = $tryExit }
        }
    }
    if ($sourceUsed -eq '' -and $lastExit -eq 0) {
        $lastExit = Add-Diag -Code 'SOURCE-UNAVAILABLE' -Message '没有可用的固定源码来源（bundle / 本地对象 / 远端）' `
            -Hint '生成 bundle 交付归档，或确认本地 Mail 仓库含固定提交；远端需要 -AllowRemote。' -ExitCode 8
    }
    if ($lastExit -ne 0) { return $lastExit }

    $delivery = [ordered]@{ source = $sourceUsed; locator = $locator; bundle_sha256 = $null; bundle_bytes = $null; bundle_refs = @() }
    if ($sourceUsed -eq 'bundle') {
        $delivery.bundle_sha256 = (Get-FileHash -LiteralPath $locator -Algorithm SHA256).Hash.ToLower()
        $delivery.bundle_bytes = (Get-Item -LiteralPath $locator).Length
        $delivery.bundle_refs = @(((Invoke-Git @('bundle', 'list-heads', $locator) $freshParent).Text -split "`n") | Where-Object { $_ })
        $delivery.sha256_verified_by_reclone = $true
    }
    $script:Result.delivery = $delivery
    Write-OkLine ("mail source: {0} -> {1}" -f $sourceUsed, $locator)

    # 5) 核对实际对象 ID / 干净状态 / 可选构建
    $exit = Test-ClosureCheckout $mailDest $pinSha ([bool]$Build)
    return $exit
}

# 主流程：统一在 finally 中写清单并清理临时目录
$exitCode = 1
try {
    if ($SelfTest) {
        $exitCode = Invoke-SelfTest
    } else {
        Write-InfoLine ("mail source closure check: parent={0} commit={1} source={2}" -f $ParentRepo, $ParentCommit, $Source)
        $exitCode = Invoke-ClosureCheck
    }
} catch {
    $exitCode = Add-Diag -Code 'INTERNAL-ERROR' -Message ('未处理异常: ' + $_.Exception.Message) -Hint ($_.ScriptStackTrace) -ExitCode 1
} finally {
    $manifestPath = $ManifestOut
    if ([string]::IsNullOrWhiteSpace($manifestPath) -and -not $SelfTest) {
        $manifestPath = Join-Path ([System.IO.Path]::GetFullPath($ParentRepo)) 'dist\release\mail-source-closure.json'
    }
    if (-not $SelfTest) {
        $resultText = if ($exitCode -eq 0) { 'PASS' } else { 'FAIL' }
        Write-ClosureManifest $manifestPath $exitCode $resultText
        if ($script:WorkRootCreated -and -not $Keep) {
            foreach ($path in @($script:WorkRootForCleanup)) {
                if ($path -and (Test-Path -LiteralPath $path)) {
                    try { Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop } catch { Write-WarnLine ("临时目录清理失败: " + $path + " :: " + $_.Exception.Message) }
                }
            }
        } elseif ($script:WorkRootCreated -and $Keep) {
            Write-InfoLine ("临时目录保留(-Keep): " + $script:WorkRootForCleanup)
        }
        if ($exitCode -eq 0) { Write-Host 'MAIL SOURCE CLOSURE: PASS' -ForegroundColor Green }
        else { Write-Host ("MAIL SOURCE CLOSURE: FAIL (exit {0})" -f $exitCode) -ForegroundColor Red }
    }
}
exit $exitCode
