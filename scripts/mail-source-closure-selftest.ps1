# mail-source-closure.ps1 的场景自检（步骤 249）
#
# 用临时目录与合成数据验证源码闭包检查的正常成功与失败边界：
#   1) 真实父仓库 + 交付归档(bundle) 的完整成功（可选含隔离构建）
#   2) 父仓库固定指针指向本地缺失对象  -> LOCAL-OBJECT-MISSING (exit 5)
#   3) .gitmodules 指向错误仓库地址      -> URL-MISMATCH (exit 3)
#   4) 显式交付归档损坏                  -> BUNDLE-CORRUPT (exit 4)
#   5) 交付归档来自旧版本(缺少固定提交)  -> BUNDLE-PIN-MISSING (exit 4)
#   6) 临时目录已存在                    -> WORKROOT-EXISTS (exit 1)
#   7) 回环假 git HTTP 服务返回 401      -> REMOTE-AUTH-FAILED (exit 6)
#   8) 回环假 git HTTP 服务返回 404      -> REMOTE-URL-INVALID (exit 3)
#   9) 回环未监听端口                    -> REMOTE-NETWORK-FAILED (exit 8)
#  10) 真实远端缺少固定对象（需 -IncludeNetwork，经 -Proxy）
#  11) 失败分类自检（主脚本 -SelfTest）
#
# 只读边界：不修改父仓库/Mail 仓库的工作树与历史；合成父仓库、假服务与临时 bundle 都在
# 一次性临时目录内创建并在结束时删除。不要求用户手工装环境。
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure-selftest.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure-selftest.ps1 -IncludeNetwork -Proxy http://127.0.0.1:23333
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\mail-source-closure-selftest.ps1 -WorkRoot P:\go\tmp\r11-249-selftest
#
# 退出码：0 全部通过（或仅网络场景按 -IncludeNetwork 跳过）；1 存在失败。

[CmdletBinding()]
param(
    [string]$ParentRepo = '',
    [string]$Bundle = '',
    [string]$WorkRoot = '',
    [switch]$IncludeNetwork,
    [switch]$SkipBuild,
    [string]$Proxy = '',
    [ValidateRange(10, 600)]
    [int]$TimeoutSec = 120
)

$ErrorActionPreference = 'Continue'
$mainScript = Join-Path $PSScriptRoot 'mail-source-closure.ps1'
$script:Results = New-Object System.Collections.ArrayList

function Write-InfoLine { param([string]$Message) Write-Host $Message }
function Write-OkLine { param([string]$Message) Write-Host "[PASS] $Message" -ForegroundColor Green }
function Write-FailLine { param([string]$Message) Write-Host "[FAIL] $Message" -ForegroundColor Red }
function Write-SkipLine { param([string]$Message) Write-Host "[SKIP] $Message" -ForegroundColor Yellow }

# 记录场景结果：PASS / FAIL / SKIP
function Add-Result {
    param([string]$Name, [ValidateSet('PASS', 'FAIL', 'SKIP')][string]$Status, [string]$Detail)
    [void]$script:Results.Add([pscustomobject]@{ Name = $Name; Status = $Status; Detail = $Detail })
    switch ($Status) {
        'PASS' { Write-OkLine ("{0}: {1}" -f $Name, $Detail) }
        'SKIP' { Write-SkipLine ("{0}: {1}" -f $Name, $Detail) }
        default { Write-FailLine ("{0}: {1}" -f $Name, $Detail) }
    }
}

# 以 Windows PowerShell 5.1 运行主脚本，确保兼容性同时得到真实退出码与输出
function Invoke-ClosureScript {
    param([string[]]$Arguments)
    $out = & powershell -NoProfile -ExecutionPolicy Bypass -File $mainScript @Arguments 2>&1
    $text = (($out | ForEach-Object { "$_" }) -join "`n").Trim()
    return [pscustomobject]@{ Exit = $LASTEXITCODE; Output = $text }
}

# 读取清单中的诊断码（清单不存在时返回空）
function Get-ManifestCodes {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return @() }
    try {
        $text = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
        $manifest = $text | ConvertFrom-Json
        return @($manifest.diagnostics | ForEach-Object { $_.code })
    } catch { return @() }
}

# 断言场景：退出码与关键诊断码都必须命中
function Assert-Scenario {
    param(
        [string]$Name,
        [object]$Run,
        [int]$ExpectedExit,
        [string[]]$ExpectedCodes = @(),
        [string]$ManifestPath = '',
        [string]$Detail = ''
    )
    $problems = @()
    if ($Run.Exit -ne $ExpectedExit) { $problems += "exit=$($Run.Exit) expected=$ExpectedExit" }
    $codes = @(Get-ManifestCodes $ManifestPath)
    foreach ($expected in $ExpectedCodes) {
        if ($codes -notcontains $expected) { $problems += "diag '$expected' missing (actual: $($codes -join ','))" }
    }
    $head = if ($Detail) { $Detail } else { ($Run.Output -split "`n" | Select-Object -First 1) }
    if ($problems.Count -gt 0) {
        $snippet = (($Run.Output -split "`n") | Where-Object { $_ -match '\[FAIL\]|\[WARN\]' } | Select-Object -First 3) -join ' | '
        Add-Result $Name 'FAIL' ("{0}; {1}; {2}" -f ($problems -join '; '), $head, $snippet)
    } else {
        Add-Result $Name 'PASS' ("{0}; exit={1}; diag={2}" -f $head, $Run.Exit, ($codes -join ','))
    }
}

# 用 git fast-import 合成父仓库提交（不在任何正式仓库上执行 add/commit）
function New-SyntheticParent {
    param([string]$Dir, [string]$GitlinkSha, [string]$Url)
    $init = & git init --quiet $Dir 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git init 失败: $init" }
    $modules = "[submodule `"EvernightMail`"]`n`tpath = EvernightMail`n`turl = $Url`nbranch = main`n"
    $message = "synthetic parent for mail-source-closure selftest`n"
    $modulesBytes = [System.Text.Encoding]::UTF8.GetByteCount($modules)
    $messageBytes = [System.Text.Encoding]::UTF8.GetByteCount($message)
    $stream = "blob`nmark :1`ndata $modulesBytes`n" + $modules +
    "commit refs/heads/main`nauthor closure-selftest <selftest@example.invalid> 1700000000 +0800`ncommitter closure-selftest <selftest@example.invalid> 1700000000 +0800`ndata $messageBytes`n" +
    $message + "M 100644 :1 .gitmodules`nM 160000 $GitlinkSha EvernightMail`n`n"
    $streamFile = Join-Path (Split-Path -Parent $Dir) ("fast-import-" + [guid]::NewGuid().ToString('N').Substring(0, 6) + ".txt")
    [System.IO.File]::WriteAllBytes($streamFile, [System.Text.Encoding]::UTF8.GetBytes($stream))
    try {
        $gitArgLine = '-C "{0}" fast-import --quiet' -f $Dir
        $proc = Start-Process -FilePath 'git' -ArgumentList $gitArgLine -RedirectStandardInput $streamFile -NoNewWindow -PassThru -Wait
        if ($proc.ExitCode -ne 0) { throw "git fast-import 失败, exit=$($proc.ExitCode)" }
    } finally {
        Remove-Item -LiteralPath $streamFile -Force -ErrorAction SilentlyContinue
    }
    $sym = & git -C $Dir symbolic-ref HEAD refs/heads/main 2>&1
    if ($LASTEXITCODE -ne 0) { throw "git symbolic-ref 失败: $sym" }
    $head = & git -C $Dir rev-parse --verify HEAD 2>&1
    if ($LASTEXITCODE -ne 0) { throw "合成父仓库没有 HEAD: $head" }
}

# 回环假 git HTTP 服务：固定返回指定状态码，用于认证/地址错误诊断
function Start-FakeGitHttpServer {
    param([int]$StatusCode, [string]$Reason, [string[]]$Headers = @())
    $probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port
    $probe.Stop()
    $headerText = ($Headers -join "`n")
    $job = Start-Job -ArgumentList $port, $StatusCode, $Reason, $headerText -ScriptBlock {
        param($port, $statusCode, $reason, $headerText)
        try {
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $port)
            $listener.Start()
            Write-Output 'READY'
            $deadline = (Get-Date).AddSeconds(25)
            $served = 0
            while ((Get-Date) -lt $deadline -and $served -lt 10) {
                if (-not $listener.Pending()) { Start-Sleep -Milliseconds 50; continue }
                $client = $listener.AcceptTcpClient()
                $served++
                try {
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 3000
                    $reader = New-Object System.IO.StreamReader($stream)
                    [void]$reader.ReadLine()
                    while ($true) {
                        $line = $reader.ReadLine()
                        if ($null -eq $line -or $line -eq '') { break }
                    }
                    $sb = New-Object System.Text.StringBuilder
                    [void]$sb.Append("HTTP/1.1 $statusCode $reason`r`n")
                    if ($headerText) { foreach ($h in ($headerText -split "`n")) { [void]$sb.Append("$h`r`n") } }
                    [void]$sb.Append("Content-Length: 0`r`nConnection: close`r`n`r`n")
                    $bytes = [System.Text.Encoding]::ASCII.GetBytes($sb.ToString())
                    $stream.Write($bytes, 0, $bytes.Length)
                    $stream.Flush()
                } catch { } finally { $client.Close() }
            }
            $listener.Stop()
        } catch { }
    }
    $ready = $false
    for ($i = 0; $i -lt 60; $i++) {
        if ((Get-Job -Id $job.Id -ErrorAction SilentlyContinue).State -eq 'Completed') { break }
        $output = Receive-Job -Id $job.Id -Keep 2>$null
        if (($output | ForEach-Object { "$_" }) -contains 'READY') { $ready = $true; break }
        Start-Sleep -Milliseconds 100
    }
    return [pscustomobject]@{ Port = $port; Job = $job; Ready = $ready }
}

function Stop-FakeGitHttpServer {
    param([object]$Server)
    if ($null -eq $Server) { return }
    try { Stop-Job -Id $Server.Job.Id -ErrorAction SilentlyContinue } catch { }
    try { Remove-Job -Id $Server.Job.Id -Force -ErrorAction SilentlyContinue } catch { }
}

# 取得一个当前未监听的本地端口（先绑定再释放）
function Get-ClosedLoopbackPort {
    $probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $probe.Start()
    $port = ([System.Net.IPEndPoint]$probe.LocalEndpoint).Port
    $probe.Stop()
    return $port
}

# ---------- 主流程 ----------

if ([string]::IsNullOrWhiteSpace($ParentRepo)) { $ParentRepo = Split-Path -Parent $PSScriptRoot }
$ParentRepo = [System.IO.Path]::GetFullPath($ParentRepo)
if (-not (Test-Path -LiteralPath $mainScript -PathType Leaf)) {
    Write-FailLine "找不到主脚本: $mainScript"
    exit 1
}
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("evernight-mail-closure-selftest-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
}
$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path -LiteralPath $WorkRoot) {
    Write-FailLine "临时目录已存在，为避免误删请换一个: $WorkRoot"
    exit 1
}
New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null

$fakeServers = New-Object System.Collections.ArrayList
$successWorkRoot = Join-Path $WorkRoot 'scenario-success'
$manifestSuccess = Join-Path $WorkRoot 'manifest-success.json'

try {
    # 0) 失败分类自检
    $classify = & powershell -NoProfile -ExecutionPolicy Bypass -File $mainScript -SelfTest 2>&1
    if ($LASTEXITCODE -eq 0) {
        $line = ($classify | Where-Object { $_ -match 'SELF-TEST PASSED' } | Select-Object -First 1)
        Add-Result 'classification' 'PASS' ("$line")
    } else {
        Add-Result 'classification' 'FAIL' (($classify | Select-Object -Last 2) -join ' | ')
    }

    # 1) 正常成功：真实父仓库 + 交付归档
    $argsSuccess = @('-ParentRepo', $ParentRepo, '-Source', 'auto', '-WorkRoot', $successWorkRoot, '-ManifestOut', $manifestSuccess, '-Build')
    if ($Bundle) { $argsSuccess += @('-Bundle', $Bundle) }
    if ($SkipBuild) { $argsSuccess = @($argsSuccess | Where-Object { $_ -ne '-Build' }) }
    $run = Invoke-ClosureScript $argsSuccess
    Assert-Scenario 'success-bundle' $run 0 @() $manifestSuccess 'real parent + bundle + isolated checkout'
    if (Test-Path -LiteralPath $manifestSuccess) {
        try {
            $manifest = [System.IO.File]::ReadAllText($manifestSuccess, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
            $pin = $manifest.submodule.gitlink_commit
            $head = $manifest.checkout.head
            if ($manifest.result -ne 'PASS' -or $pin -ne $head) {
                Add-Result 'success-manifest-objects' 'FAIL' ("result=$($manifest.result) gitlink=$pin checkout=$head")
            } else {
                Add-Result 'success-manifest-objects' 'PASS' ("gitlink=checkout=$pin tree=$($manifest.checkout.tree) source=$($manifest.delivery.source)")
            }
        } catch {
            Add-Result 'success-manifest-objects' 'FAIL' ("清单解析失败: " + $_.Exception.Message)
        }
    } else {
        Add-Result 'success-manifest-objects' 'FAIL' '成功场景没有生成清单'
    }

    # 2) 本地缺少固定对象
    $synMissing = Join-Path $WorkRoot 'syn-missing-object'
    New-SyntheticParent -Dir $synMissing -GitlinkSha ('d' * 40) -Url 'git@github.com:kagurazakayashi/EvernightMail.git'
    $manifestMissing = Join-Path $WorkRoot 'manifest-missing-object.json'
    $run = Invoke-ClosureScript @('-ParentRepo', $synMissing, '-Source', 'local', '-MailRepo', (Join-Path $ParentRepo 'EvernightMail'),
        '-WorkRoot', (Join-Path $WorkRoot 'scenario-missing-object'), '-ManifestOut', $manifestMissing)
    Assert-Scenario 'local-object-missing' $run 5 @('LOCAL-OBJECT-MISSING') $manifestMissing 'local repo lacks pinned commit'

    # 3) 仓库地址错误
    $synUrl = Join-Path $WorkRoot 'syn-wrong-url'
    New-SyntheticParent -Dir $synUrl -GitlinkSha ('a' * 40) -Url 'git@github.com:someone-else/NotEvernightMail.git'
    $manifestUrl = Join-Path $WorkRoot 'manifest-wrong-url.json'
    $run = Invoke-ClosureScript @('-ParentRepo', $synUrl, '-Source', 'local', '-MailRepo', (Join-Path $ParentRepo 'EvernightMail'),
        '-WorkRoot', (Join-Path $WorkRoot 'scenario-wrong-url'), '-ManifestOut', $manifestUrl)
    Assert-Scenario 'url-mismatch' $run 3 @('URL-MISMATCH') $manifestUrl '.gitmodules points to wrong repo'

    # 4) 交付归档损坏
    $corruptBundle = Join-Path $WorkRoot 'corrupt.bundle'
    Set-Content -LiteralPath $corruptBundle -Value 'this is not a git bundle' -Encoding ASCII
    $manifestCorrupt = Join-Path $WorkRoot 'manifest-corrupt-bundle.json'
    $run = Invoke-ClosureScript @('-ParentRepo', $ParentRepo, '-Source', 'bundle', '-Bundle', $corruptBundle,
        '-WorkRoot', (Join-Path $WorkRoot 'scenario-corrupt-bundle'), '-ManifestOut', $manifestCorrupt)
    Assert-Scenario 'bundle-corrupt' $run 4 @('BUNDLE-CORRUPT') $manifestCorrupt 'corrupted delivery archive'

    # 5) 交付归档缺少固定提交（用远端 main 旧版本生成，仅作负向样本）
    $oldBundle = Join-Path $WorkRoot 'old-main.bundle'
    $mailRepo = Join-Path $ParentRepo 'EvernightMail'
    $bundleMake = & git -C $mailRepo bundle create $oldBundle refs/remotes/origin/main 2>&1
    if ($LASTEXITCODE -ne 0) {
        Add-Result 'bundle-pin-missing' 'FAIL' ("无法生成旧版本样本 bundle: " + (($bundleMake | Select-Object -First 2) -join ' | '))
    } else {
        $manifestOld = Join-Path $WorkRoot 'manifest-old-bundle.json'
        $run = Invoke-ClosureScript @('-ParentRepo', $ParentRepo, '-Source', 'bundle', '-Bundle', $oldBundle,
            '-WorkRoot', (Join-Path $WorkRoot 'scenario-old-bundle'), '-ManifestOut', $manifestOld)
        Assert-Scenario 'bundle-pin-missing' $run 4 @('BUNDLE-PIN-MISSING') $manifestOld 'archive from old main lacks pinned commit'
    }

    # 6) 临时目录已存在
    $existing = Join-Path $WorkRoot 'scenario-existing'
    New-Item -ItemType Directory -Path $existing -Force | Out-Null
    $manifestExisting = Join-Path $WorkRoot 'manifest-existing.json'
    $run = Invoke-ClosureScript @('-ParentRepo', $ParentRepo, '-WorkRoot', $existing, '-ManifestOut', $manifestExisting)
    Assert-Scenario 'workroot-exists' $run 1 @('WORKROOT-EXISTS') $manifestExisting 'refuse to reuse non-empty target'

    # 7) 回环假服务：401 -> 认证失败
    $authServer = Start-FakeGitHttpServer -StatusCode 401 -Reason 'Unauthorized' -Headers @('WWW-Authenticate: Basic realm="selftest"')
    [void]$fakeServers.Add($authServer)
    if (-not $authServer.Ready) {
        Add-Result 'remote-auth-failed' 'FAIL' "假 401 服务未就绪"
    } else {
        $manifestAuth = Join-Path $WorkRoot 'manifest-auth.json'
        $run = Invoke-ClosureScript @('-ParentRepo', $ParentRepo, '-Source', 'remote', '-AllowRemote',
            '-RemoteUrl', "http://127.0.0.1:$($authServer.Port)/repo.git",
            '-WorkRoot', (Join-Path $WorkRoot 'scenario-auth'), '-ManifestOut', $manifestAuth, '-TimeoutSec', '60')
        Assert-Scenario 'remote-auth-failed' $run 6 @('REMOTE-AUTH-FAILED') $manifestAuth 'loopback 401 -> auth diagnostic'
    }

    # 8) 回环假服务：404 -> 仓库地址无效
    $urlServer = Start-FakeGitHttpServer -StatusCode 404 -Reason 'Not Found'
    [void]$fakeServers.Add($urlServer)
    if (-not $urlServer.Ready) {
        Add-Result 'remote-url-invalid' 'FAIL' "假 404 服务未就绪"
    } else {
        $manifestRUrl = Join-Path $WorkRoot 'manifest-remote-url.json'
        $run = Invoke-ClosureScript @('-ParentRepo', $ParentRepo, '-Source', 'remote', '-AllowRemote',
            '-RemoteUrl', "http://127.0.0.1:$($urlServer.Port)/repo.git",
            '-WorkRoot', (Join-Path $WorkRoot 'scenario-remote-url'), '-ManifestOut', $manifestRUrl, '-TimeoutSec', '60')
        Assert-Scenario 'remote-url-invalid' $run 3 @('REMOTE-URL-INVALID') $manifestRUrl 'loopback 404 -> url diagnostic'
    }

    # 9) 回环未监听端口 -> 网络诊断
    $closedPort = Get-ClosedLoopbackPort
    $manifestNet = Join-Path $WorkRoot 'manifest-network.json'
    $run = Invoke-ClosureScript @('-ParentRepo', $ParentRepo, '-Source', 'remote', '-AllowRemote',
        '-RemoteUrl', "http://127.0.0.1:$closedPort/repo.git",
        '-WorkRoot', (Join-Path $WorkRoot 'scenario-network'), '-ManifestOut', $manifestNet, '-TimeoutSec', '60')
    Assert-Scenario 'remote-network-failed' $run 8 @('REMOTE-NETWORK-FAILED') $manifestNet 'closed loopback port -> network diagnostic'

    # 10) 真实远端缺少固定对象（需要网络；按代理顺序访问）
    if (-not $IncludeNetwork) {
        Add-Result 'remote-object-missing' 'SKIP' '需要 -IncludeNetwork 才访问真实远端'
    } else {
        $manifestRemote = Join-Path $WorkRoot 'manifest-remote-object.json'
        $remoteArgs = @('-ParentRepo', $ParentRepo, '-Source', 'remote', '-AllowRemote',
            '-RemoteUrl', 'https://github.com/kagurazakayashi/EvernightMail.git',
            '-WorkRoot', (Join-Path $WorkRoot 'scenario-remote-object'), '-ManifestOut', $manifestRemote, '-TimeoutSec', '90')
        if ($Proxy) { $remoteArgs += @('-Proxy', $Proxy) }
        $run = Invoke-ClosureScript $remoteArgs
        $codes = @(Get-ManifestCodes $manifestRemote)
        if ($codes -contains 'REMOTE-OBJECT-MISSING') {
            Add-Result 'remote-object-missing' 'PASS' 'real remote lacks pinned unreachable object -> object diagnostic'
        } elseif ($codes -contains 'REMOTE-URL-INVALID' -or $codes -contains 'REMOTE-NETWORK-FAILED' -or $codes -contains 'REMOTE-AUTH-FAILED') {
            Add-Result 'remote-object-missing' 'SKIP' ("网络/认证条件未满足，已记录诊断: " + ($codes -join ','))
        } else {
            Add-Result 'remote-object-missing' 'FAIL' ("expected REMOTE-OBJECT-MISSING, actual: " + ($codes -join ','))
        }
    }
} catch {
    Add-Result 'selftest-harness' 'FAIL' ('未处理异常: ' + $_.Exception.Message)
} finally {
    foreach ($server in $fakeServers) { Stop-FakeGitHttpServer $server }
    # 清理临时目录（含脚本自身已清理后仍残留的隔离副本）
    if (Test-Path -LiteralPath $WorkRoot) {
        try { Remove-Item -LiteralPath $WorkRoot -Recurse -Force -ErrorAction Stop } catch { Write-SkipLine ("临时目录清理失败: " + $_.Exception.Message) }
    }
}

$passed = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
$failed = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
$skipped = @($script:Results | Where-Object { $_.Status -eq 'SKIP' }).Count
Write-InfoLine ''
Write-InfoLine ("mail-source-closure selftest: PASS={0} FAIL={1} SKIP={2}" -f $passed, $failed, $skipped)
if ($failed -gt 0) {
    Write-Host 'MAIL SOURCE CLOSURE SELFTEST: FAILED' -ForegroundColor Red
    exit 1
}
Write-Host 'MAIL SOURCE CLOSURE SELFTEST: PASSED' -ForegroundColor Green
exit 0
