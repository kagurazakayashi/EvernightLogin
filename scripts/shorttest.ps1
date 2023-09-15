# EvernightLogin 无人值守短测试统一入口（Windows PowerShell 5.1 / PowerShell 7）。
#
# 本脚本是第 10 轮步骤 203 建立的统一短测试入口：所有领域短测试都通过它启动，
# 由入口统一负责：
#   - 临时数据目录（%TEMP% 下唯一目录，默认结束时删除，-KeepArtifacts 保留）；
#   - 动态回环端口（端口由场景绑定 127.0.0.1:0 取得，入口在结束后验证释放）；
#   - 合成用户/秘密（场景内生成随机密码，入口不打印、结果 JSON 不含秘密）；
#   - 总超时（-TimeoutSeconds 覆盖构建+运行+清理，超时强制结束整棵子进程树）；
#   - 子进程退出与清理（记录退出码/超时/剩余进程，只终止本次创建的进程）；
#   - 结构化 JSON 结果（stdout 单行 JSON，可选 -Out 写文件）。
#
# 场景登记在 scripts/shorttest/scenarios.json；场景实现是 Go 程序，只使用公开
# 入口（本步的 login-server-smoke 复用真实 login-server CLI），不复制业务逻辑。
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -List
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario login-server-smoke
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario login-server-smoke -TimeoutSeconds 240 -Out docs\acceptance\evidence\step203\shorttest.json
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 -Scenario harness-timeout -TimeoutSeconds 15
#
# 退出码：0=场景 PASS；1=场景 FAIL/TIMEOUT；2=参数/未知场景；3=环境/构建/注册表错误。
# 只读约束：不执行 git 写操作、不写仓库数据库、不访问外网（仅 127.0.0.1）。
[CmdletBinding()]
param(
    # 场景 id；省略时必须同时给 -List。
    [string]$Scenario = "",
    # 列出已登记场景（输出 JSON，退出码 0）。
    [switch]$List,
    # 入口总超时（秒），覆盖构建 + 场景运行 + 清理。
    [int]$TimeoutSeconds = 180,
    # 保留临时目录用于排查（默认无论成功失败都清理，证据保存在结果 JSON 中）。
    [switch]$KeepArtifacts,
    # 可选：把统一结果 JSON 写到该路径（相对仓库根或绝对路径）。
    [string]$Out = ""
)

$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 的 stdout 默认使用 ANSI 编码；统一 UTF-8 便于机器解析。
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$script:startedAt = Get-Date
$script:repoRoot = Split-Path -Parent $PSScriptRoot
$script:resultSchema = "evernight.shorttest.result/v1"
$script:scenarioRegistry = Join-Path $PSScriptRoot "shorttest\scenarios.json"
$script:scriptExitCode = 3

# ---------------------------------------------------------------- 基础工具

# 截取日志尾部（限制结果 JSON 体积；秘密值不进入日志由场景保证）。
function Get-LogTail {
    param([string]$Text, [int]$Limit = 2000)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $value = $Text.Trim()
    if ($value.Length -le $Limit) { return $value }
    return "..." + $value.Substring($value.Length - $Limit)
}

# 只读读取 git 信息；git 不可用时返回空字符串（不阻塞短测试）。
function Get-GitValue {
    param([string[]]$Arguments)
    $git = Get-Command git.exe -ErrorAction SilentlyContinue
    if ($null -eq $git) { $git = Get-Command git -ErrorAction SilentlyContinue }
    if ($null -eq $git) { return "" }
    try {
        $output = & $git.Source -C $script:repoRoot @Arguments 2>$null
        if ($LASTEXITCODE -ne 0) { return "" }
        return (($output | Out-String).Trim())
    } catch {
        return ""
    }
}

# 输出错误并终止脚本（不抛异常，保证每次都以结构化 JSON 结束）。
function Stop-Entry {
    param(
        [int]$ExitCode,
        [string]$Message,
        [hashtable]$Fields = @{}
    )
    $script:scriptExitCode = $ExitCode
    $payload = [ordered]@{
        schema    = $script:resultSchema
        status    = if ($ExitCode -eq 0) { "PASS" } else { "ERROR" }
        error     = $Message
        exit_code = $ExitCode
    }
    foreach ($key in $Fields.Keys) { $payload[$key] = $Fields[$key] }
    Write-ResultPayload -Payload $payload
    throw [System.Management.Automation.RuntimeException]("__shorttest_stop__")
}

# 把结果 JSON 写到 stdout（单行）并按需写文件。
function Write-ResultPayload {
    param([System.Collections.IDictionary]$Payload)
    $json = $Payload | ConvertTo-Json -Compress -Depth 16
    [Console]::Out.WriteLine($json)
    if ($Out -ne "") {
        $outPath = $Out
        if (-not [System.IO.Path]::IsPathRooted($outPath)) {
            $outPath = Join-Path $script:repoRoot $outPath
        }
        $parent = Split-Path -Parent $outPath
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            $null = New-Item -ItemType Directory -Path $parent -Force
        }
        [System.IO.File]::WriteAllText($outPath, $json + "`n", (New-Object System.Text.UTF8Encoding($false)))
        [Console]::Error.WriteLine("结果 JSON: $outPath")
    }
}

# 计算入口剩余预算（毫秒）；保留清理时间。
function Get-RemainingMilliseconds {
    param([int]$ReserveMilliseconds = 3000)
    $elapsed = ((Get-Date) - $script:startedAt).TotalMilliseconds
    $remaining = ($TimeoutSeconds * 1000) - $elapsed - $ReserveMilliseconds
    if ($remaining -lt 0) { return 0 }
    return [int]$remaining
}

# 计算并发预算：不超过逻辑处理器一半，最少 1（本机 4 逻辑 CPU -> 2）。
function Get-ConcurrencyBudget {
    $cores = [Environment]::ProcessorCount
    if ($cores -lt 1) { return 1 }
    $budget = [Math]::Floor($cores / 2)
    if ($budget -lt 1) { $budget = 1 }
    return [int]$budget
}

# 参数引用：含空白/特殊字符时用双引号包裹。
function Quote-Argument {
    param([string]$Value)
    if ($Value -match '^[A-Za-z0-9_\./\\:=+\-@]+$') { return $Value }
    $escaped = $Value.Replace('"', '\"')
    return '"' + $escaped + '"'
}

# 构造子进程（重定向输出，异步读取，避免管道死锁）。
function New-ChildProcess {
    param([string]$Exe, [string[]]$Arguments)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $quoted = @()
    foreach ($argument in $Arguments) { $quoted += (Quote-Argument $argument) }
    $psi.Arguments = ($quoted -join " ")
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.WorkingDirectory = $script:repoRoot
    # Windows PowerShell 5.1 默认用 ANSI 编码读取子进程输出；统一按 UTF-8 解码，
    # 保证场景 JSON 中的中文证据不会乱码。
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    $psi.StandardOutputEncoding = $utf8
    $psi.StandardErrorEncoding = $utf8
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $psi
    return $process
}

# 同步执行子进程并收集输出；超时则结束整棵进程树。
function Invoke-ChildCapture {
    param(
        [string]$Exe,
        [string[]]$Arguments,
        [int]$TimeoutMilliseconds,
        [string]$Label
    )
    $started = Get-Date
    $process = New-ChildProcess -Exe $Exe -Arguments $Arguments
    try {
        $null = $process.Start()
    } catch {
        return [ordered]@{
            label = $Label; exit_code = -1; timed_out = $false; duration_ms = 0
            stdout = ""; stderr = ("启动失败: " + $_.Exception.Message)
        }
    }
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    if ($TimeoutMilliseconds -lt 1000) { $TimeoutMilliseconds = 1000 }
    $exited = $process.WaitForExit($TimeoutMilliseconds)
    $timedOut = $false
    if (-not $exited) {
        $timedOut = $true
        Stop-ProcessTree -Process $process
    } else {
        $null = $process.WaitForExit()
    }
    $stdout = Wait-OutputTask -Task $outTask
    $stderr = Wait-OutputTask -Task $errTask
    $exitCode = -1
    try { $exitCode = $process.ExitCode } catch { $exitCode = -1 }
    $duration = ((Get-Date) - $started).TotalMilliseconds
    return [ordered]@{
        label = $Label; exit_code = $exitCode; timed_out = $timedOut
        duration_ms = [int]$duration; stdout = $stdout; stderr = $stderr
    }
}

# 有界等待异步输出任务完成。
function Wait-OutputTask {
    param($Task)
    try {
        if ($Task.Wait(5000)) { return $Task.Result }
    } catch {
        return ""
    }
    return ""
}

# 结束子进程及其整棵进程树（只作用于入口自己启动的 PID）。
function Stop-ProcessTree {
    param([System.Diagnostics.Process]$Process)
    if ($null -eq $Process) { return }
    $pidValue = -1
    try { $pidValue = $Process.Id } catch { $pidValue = -1 }
    if ($pidValue -gt 0) {
        $taskkill = Get-Command taskkill.exe -ErrorAction SilentlyContinue
        if ($null -ne $taskkill) {
            try { $null = & $taskkill.Source /PID $pidValue /T /F 2>&1 } catch { }
        }
    }
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
    } catch { }
    try { $null = $Process.WaitForExit(15000) } catch { }
}

# 返回路径下的普通文件数量。
function Get-FileCount {
    param([string]$Root)
    if (-not (Test-Path -LiteralPath $Root)) { return 0 }
    return @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue).Count
}

# 尝试绑定回环端口以验证监听已释放。
function Test-PortReleased {
    param([int]$Port)
    if ($Port -le 0) { return $false }
    $deadline = (Get-Date).AddSeconds(5)
    while ((Get-Date) -lt $deadline) {
        $listener = $null
        try {
            $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
            $listener.Start()
            $listener.Stop()
            return $true
        } catch {
            if ($null -ne $listener) { try { $listener.Stop() } catch { } }
        }
        Start-Sleep -Milliseconds 150
    }
    return $false
}

# 清除可能覆盖配置的 LOGIN_* 环境变量（只影响入口子进程环境）。
function Remove-LoginEnvironment {
    try {
        $overrides = @(Get-ChildItem Env: | Where-Object { $_.Name -like "LOGIN_*" })
        foreach ($item in $overrides) {
            Remove-Item -LiteralPath ("Env:" + $item.Name) -ErrorAction SilentlyContinue
        }
    } catch { }
}

# ---------------------------------------------------------------- 主流程

$exitCode = 3
$workRoot = $null
$trackedProcess = $null
$scenarioWorkDir = $null
$scenarioResultPath = $null

try {
    # 参数校验（拒绝路径：非法超时/缺少场景/未知场景都输出结构化 ERROR）。
    if ($TimeoutSeconds -lt 5 -or $TimeoutSeconds -gt 1800) {
        Stop-Entry -ExitCode 2 -Message ("-TimeoutSeconds 必须在 5..1800 之间，实际 " + $TimeoutSeconds)
    }
    if (-not (Test-Path -LiteralPath $script:scenarioRegistry -PathType Leaf)) {
        Stop-Entry -ExitCode 3 -Message ("缺少场景注册表: " + $script:scenarioRegistry)
    }
    $registryRaw = Get-Content -LiteralPath $script:scenarioRegistry -Raw -Encoding UTF8
    $registry = $registryRaw | ConvertFrom-Json
    if ($registry.schema -ne "evernight.shorttest.scenarios/v1") {
        Stop-Entry -ExitCode 3 -Message ("场景注册表 schema 非法: " + $registry.schema)
    }
    $scenarios = @($registry.scenarios)

    if ($List) {
        $listPayload = [ordered]@{
            schema    = "evernight.shorttest.scenarios/v1"
            status    = "PASS"
            exit_code = 0
            scenarios = $scenarios
        }
        Write-ResultPayload -Payload $listPayload
        $script:scriptExitCode = 0
        throw [System.Management.Automation.RuntimeException]("__shorttest_stop__")
    }
    if ($Scenario -eq "") {
        Stop-Entry -ExitCode 2 -Message "缺少 -Scenario 参数；用 -List 查看已登记场景" -Fields @{
            available = @($scenarios | ForEach-Object { $_.id })
        }
    }
    $selected = @($scenarios | Where-Object { $_.id -eq $Scenario })
    if ($selected.Count -eq 0) {
        Stop-Entry -ExitCode 2 -Message ("未知场景: " + $Scenario) -Fields @{
            available = @($scenarios | ForEach-Object { $_.id })
        }
    }
    $selected = $selected[0]

    $cores = [Environment]::ProcessorCount
    $budget = Get-ConcurrencyBudget
    Remove-LoginEnvironment
    $env:GOTOOLCHAIN = "local"
    $env:CGO_ENABLED = "0"
    $env:GOMAXPROCS = "$budget"

    # 临时工作根目录：唯一、位于系统 TEMP；结束按 -KeepArtifacts 清理。
    $stamp = (Get-Date).ToString("yyyyMMddHHmmss")
    $suffix = -join ((1..6) | ForEach-Object { "{0:x}" -f (Get-Random -Maximum 16) })
    $workRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("evernight-shorttest-" + $stamp + "-" + $suffix)
    $null = New-Item -ItemType Directory -Path $workRoot -Force
    $scenarioWorkDir = Join-Path $workRoot "data"
    $scenarioResultPath = Join-Path $workRoot "scenario-result.json"
    $buildLogPath = Join-Path $workRoot "build.log"
    $scenarioExe = Join-Path $workRoot ("scenario-" + ($selected.id -replace '[^A-Za-z0-9_.-]', '_') + ".exe")
    $serverExe = Join-Path $workRoot "login-server.exe"

    $goExe = "go"
    $goVersion = ""
    $versionResult = Invoke-ChildCapture -Exe $goExe -Arguments @("version") -TimeoutMilliseconds 20000 -Label "go-version"
    if ($versionResult.exit_code -eq 0) { $goVersion = $versionResult.stdout.Trim() }

    # 构建场景程序（Go build 缓存使复用成本低）。
    $buildLines = New-Object System.Collections.Generic.List[string]
    $buildLines.Add("== go build scenario: " + $selected.program)
    $buildTimeout = [Math]::Min([Math]::Max((Get-RemainingMilliseconds -ReserveMilliseconds 20000), 10000), 240000)
    $scenarioBuild = Invoke-ChildCapture -Exe $goExe -Arguments @("build", "-trimpath", "-p", "$budget", "-o", $scenarioExe, $selected.program) -TimeoutMilliseconds $buildTimeout -Label "build-scenario"
    $buildLines.Add("exit=" + $scenarioBuild.exit_code + " timed_out=" + $scenarioBuild.timed_out)
    if ($scenarioBuild.stderr) { $buildLines.Add($scenarioBuild.stderr.Trim()) }
    if ($scenarioBuild.exit_code -ne 0) {
        [System.IO.File]::WriteAllText($buildLogPath, ($buildLines -join "`n"))
        Stop-Entry -ExitCode 3 -Message ("构建场景程序失败: " + $selected.program) -Fields @{
            build = [ordered]@{ exit_code = $scenarioBuild.exit_code; timed_out = $scenarioBuild.timed_out; log_tail = (Get-LogTail $scenarioBuild.stderr 1500) }
        }
    }

    if ($selected.needs_server_binary) {
        $buildLines.Add("== go build ./cmd/login-server")
        $serverTimeout = [Math]::Min([Math]::Max((Get-RemainingMilliseconds -ReserveMilliseconds 45000), 15000), 300000)
        $serverBuild = Invoke-ChildCapture -Exe $goExe -Arguments @("build", "-trimpath", "-p", "$budget", "-o", $serverExe, "./cmd/login-server") -TimeoutMilliseconds $serverTimeout -Label "build-login-server"
        $buildLines.Add("exit=" + $serverBuild.exit_code + " timed_out=" + $serverBuild.timed_out)
        if ($serverBuild.stderr) { $buildLines.Add($serverBuild.stderr.Trim()) }
        if ($serverBuild.exit_code -ne 0) {
            [System.IO.File]::WriteAllText($buildLogPath, ($buildLines -join "`n"))
            Stop-Entry -ExitCode 3 -Message "构建 ./cmd/login-server 失败" -Fields @{
                build = [ordered]@{ exit_code = $serverBuild.exit_code; timed_out = $serverBuild.timed_out; log_tail = (Get-LogTail $serverBuild.stderr 1500) }
            }
        }
    }
    [System.IO.File]::WriteAllText($buildLogPath, ($buildLines -join "`n"))

    # 计算场景运行预算并替换参数模板。
    $remaining = Get-RemainingMilliseconds -ReserveMilliseconds 8000
    if ($remaining -lt 5000) {
        Stop-Entry -ExitCode 1 -Message "总超时预算耗尽，未启动场景（构建过慢）" -Fields @{
            scenario = [ordered]@{ id = $selected.id; title = $selected.title }
            logs = [ordered]@{ build_log_tail = (Get-LogTail (($buildLines -join "`n")) 2000) }
            cleanup = [ordered]@{ workdir = $workRoot; workdir_removed = $false }
        }
    }
    $childTimeoutMs = [Math]::Min($remaining, [int]($selected.timeout_seconds) * 1000)
    $childTimeoutSeconds = [Math]::Floor($childTimeoutMs / 1000)
    $arguments = @()
    foreach ($argument in @($selected.arguments)) {
        $value = [string]$argument
        $value = $value.Replace("{workdir}", $scenarioWorkDir)
        $value = $value.Replace("{server}", $serverExe)
        $value = $value.Replace("{timeout}", "$childTimeoutSeconds")
        $value = $value.Replace("{result}", $scenarioResultPath)
        $arguments += $value
    }

    # 运行场景子进程（入口只终止本次创建的进程树）。
    $scenarioProcess = New-ChildProcess -Exe $scenarioExe -Arguments $arguments
    $runStarted = Get-Date
    $runError = ""
    try {
        $null = $scenarioProcess.Start()
        $trackedProcess = $scenarioProcess
    } catch {
        Stop-Entry -ExitCode 1 -Message ("启动场景进程失败: " + $_.Exception.Message) -Fields @{
            scenario = [ordered]@{ id = $selected.id; title = $selected.title }
            cleanup = [ordered]@{ workdir = $workRoot; workdir_removed = $false }
        }
    }
    $scenarioOutTask = $scenarioProcess.StandardOutput.ReadToEndAsync()
    $scenarioErrTask = $scenarioProcess.StandardError.ReadToEndAsync()
    $scenarioExited = $scenarioProcess.WaitForExit([int]$childTimeoutMs)
    $scenarioTimedOut = $false
    if (-not $scenarioExited) {
        $scenarioTimedOut = $true
        Stop-ProcessTree -Process $scenarioProcess
    } else {
        try { $null = $scenarioProcess.WaitForExit() } catch { }
    }
    $scenarioStdout = Wait-OutputTask -Task $scenarioOutTask
    $scenarioStderr = Wait-OutputTask -Task $scenarioErrTask
    $scenarioDurationMs = ((Get-Date) - $runStarted).TotalMilliseconds
    $scenarioExitCode = -1
    try { $scenarioExitCode = $scenarioProcess.ExitCode } catch { $scenarioExitCode = -1 }

    # 解析场景结构化结果；缺失/非法 JSON 视为失败（不把"没输出"当成功）。
    $scenarioJson = $null
    $scenarioStatus = ""
    if ($scenarioStdout -and $scenarioStdout.Trim().StartsWith("{")) {
        try {
            $scenarioJson = $scenarioStdout.Trim() | ConvertFrom-Json
            $scenarioStatus = [string]$scenarioJson.status
        } catch {
            $runError = "场景输出不是合法 JSON: " + $_.Exception.Message
        }
    } elseif ($scenarioTimedOut) {
        $runError = "场景在入口超时内未结束，已强制结束进程树"
    } else {
        $runError = "场景未输出结构化 JSON 结果"
    }
    if ($scenarioJson -ne $null -and $scenarioStatus -eq "FAIL" -and $scenarioJson.error) {
        $runError = [string]$scenarioJson.error
    }

    # 清理与证据：临时目录、端口、进程。
    $spawnedPids = @()
    if ($scenarioJson -ne $null -and $scenarioJson.spawned_pids) { $spawnedPids = @($scenarioJson.spawned_pids) }
    $port = 0
    if ($scenarioJson -ne $null -and $scenarioJson.port) { $port = [int]$scenarioJson.port }
    $processesRemaining = @()
    if ($null -ne $trackedProcess) {
        try {
            if (-not $trackedProcess.HasExited) { $processesRemaining += $trackedProcess.Id }
        } catch { }
    }
    foreach ($pidValue in $spawnedPids) {
        $existing = Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue
        if ($null -ne $existing) { $processesRemaining += [int]$pidValue }
    }
    foreach ($pidValue in @($processesRemaining)) {
        try { Stop-Process -Id ([int]$pidValue) -Force -ErrorAction SilentlyContinue } catch { }
    }
    Start-Sleep -Milliseconds 200
    $stillRemaining = @()
    foreach ($pidValue in @($processesRemaining)) {
        if ($null -ne (Get-Process -Id ([int]$pidValue) -ErrorAction SilentlyContinue)) {
            $stillRemaining += [int]$pidValue
        }
    }
    $portReleased = Test-PortReleased -Port $port

    $workDirRemoved = $false
    $workDirFiles = Get-FileCount $workRoot
    if ($KeepArtifacts) {
        [Console]::Error.WriteLine("保留临时目录: $workRoot")
    } else {
        try {
            Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction Stop
            $workDirRemoved = -not (Test-Path -LiteralPath $workRoot)
        } catch {
            $workDirRemoved = $false
            [Console]::Error.WriteLine("清理临时目录失败: " + $_.Exception.Message)
        }
    }

    # 汇总统一状态。
    $status = "FAIL"
    if ($scenarioTimedOut) {
        $status = "TIMEOUT"
    } elseif ($scenarioJson -ne $null -and $scenarioStatus -eq "PASS" -and -not $runError) {
        $status = "PASS"
    }
    if ($status -eq "PASS" -and ($stillRemaining.Count -gt 0 -or (-not $portReleased -and $port -gt 0) -or -not $workDirRemoved)) {
        $status = "FAIL"
        if (-not $runError) { $runError = "清理校验失败（进程/端口/临时目录）" }
    }
    if ($status -eq "PASS") { $exitCode = 0 } else { $exitCode = 1 }

    $checks = @()
    if ($scenarioJson -ne $null -and $scenarioJson.checks) { $checks = @($scenarioJson.checks) }
    $scenarioInfo = [ordered]@{ id = $selected.id; title = $selected.title; timeout_seconds = $childTimeoutSeconds; covers = @($selected.covers) }
    $environment = [ordered]@{
        platform          = [System.Environment]::OSVersion.VersionString
        os                = if ($IsWindows -or ($env:OS -eq "Windows_NT")) { "windows" } else { "other" }
        arch              = if ([Environment]::Is64BitProcess) { "64bit" } else { "32bit" }
        powershell        = $PSVersionTable.PSVersion.ToString()
        go_version        = $goVersion
        logical_cpus      = $cores
        concurrency_budget = $budget
        gomaxprocs        = $env:GOMAXPROCS
        cgo_enabled       = $env:CGO_ENABLED
        repo_root         = $script:repoRoot
        repo_head         = (Get-GitValue -Arguments @("rev-parse", "HEAD"))
        repo_dirty        = ((Get-GitValue -Arguments @("status", "--porcelain")).Trim() -ne "")
        started_at        = $script:startedAt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        ended_at          = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        duration_ms       = [int](((Get-Date) - $script:startedAt).TotalMilliseconds)
    }
    $cleanup = [ordered]@{
        workdir           = $workRoot
        workdir_files     = $workDirFiles
        workdir_removed   = $workDirRemoved
        artifacts_kept    = [bool]$KeepArtifacts
        port              = $port
        port_release_checked = ($port -gt 0)
        port_released     = $portReleased
        tracked_processes = @($processesRemaining)
        processes_remaining = @($stillRemaining)
    }
    $payload = [ordered]@{
        schema          = $script:resultSchema
        status          = $status
        exit_code       = $exitCode
        scenario        = $scenarioInfo
        environment     = $environment
        checks          = $checks
        scenario_exit_code = $scenarioExitCode
        scenario_duration_ms = [int]$scenarioDurationMs
        scenario_result = $scenarioJson
        cleanup         = $cleanup
        logs            = [ordered]@{
            stdout_tail = (Get-LogTail $scenarioStdout 3000)
            stderr_tail = (Get-LogTail $scenarioStderr 3000)
            build_log_tail = (Get-LogTail (($buildLines -join "`n")) 2000)
        }
        error           = $runError
    }
    Write-ResultPayload -Payload $payload
    [Console]::Error.WriteLine(("场景 " + $selected.id + ": " + $status + " (exit=" + $scenarioExitCode + ", duration_ms=" + [int]$scenarioDurationMs + ")"))
    $script:scriptExitCode = $exitCode
} catch {
    if ($_.Exception.Message -eq "__shorttest_stop__") {
        # Stop-Entry 已完成结构化输出，按记录退出码结束。
    } else {
        $script:scriptExitCode = 3
        try {
            $payload = [ordered]@{
                schema = $script:resultSchema
                status = "ERROR"
                error  = ("入口内部错误: " + $_.Exception.Message)
                exit_code = 3
                cleanup = [ordered]@{ workdir = $workRoot; workdir_removed = $false }
            }
            Write-ResultPayload -Payload $payload
        } catch { }
    }
}

# 无论何种路径，都不留下入口自己的临时目录（除非显式保留已输出提示）。
if ($workRoot -and (Test-Path -LiteralPath $workRoot) -and -not $KeepArtifacts) {
    try { Remove-Item -LiteralPath $workRoot -Recurse -Force -ErrorAction SilentlyContinue } catch { }
}

exit $script:scriptExitCode
