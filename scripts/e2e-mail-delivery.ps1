# 步骤 139 真实邮件投递 E2E：独立 EvernightMail 夹具 + 真实 SMTPSender + login-server 装配冒烟。
# 不向公网外发；全部为临时目录/回环端口/自动测试 CA；失败返回非零。
[CmdletBinding()]
param(
    [string]$MailBin = $env:EVERNIGHTMAIL_BIN,
    [string]$RepoRoot = '',
    [int]$TimeoutSeconds = 240
)

$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) {
    $scriptPath = $MyInvocation.MyCommand.Path
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $scriptPath)
}
if (-not $RepoRoot) { Write-Host 'FAIL prereq.repo-root: 无法解析仓库根目录'; exit 1 }
$script:pass = 0
$script:fail = 0
$script:notTested = 0
$script:processes = @()
$script:tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("login-mail-e2e-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$script:ports = @()

function Fail([string]$id, [string]$detail) {
    $script:fail++
    Write-Host ("FAIL {0}: {1}" -f $id, $detail)
}
function Pass([string]$id, [string]$detail = "") {
    $script:pass++
    Write-Host ("PASS {0}: {1}" -f $id, $detail)
}
function NotTested([string]$id, [string]$detail) {
    $script:notTested++
    Write-Host ("NOT_TESTED {0}: {1}" -f $id, $detail)
}
function FreePort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}
function Wait-Port([int]$port, [int]$timeoutMs = 30000) {
    $deadline = (Get-Date).AddMilliseconds($timeoutMs)
    while ((Get-Date) -lt $deadline) {
        $client = $null
        try {
            $client = [System.Net.Sockets.TcpClient]::new()
            $client.Connect('127.0.0.1', $port)
            return $true
        } catch {
            Start-Sleep -Milliseconds 200
        } finally {
            if ($client) { $client.Dispose() }
        }
    }
    return $false
}
function Stop-OwnedProcesses {
    foreach ($process in $script:processes) {
        try {
            if ($process -and -not $process.HasExited) {
                $process.Kill($true)
                $null = $process.WaitForExit(10000)
            }
        } catch {
            Write-Host "WARN cleanup: $($_.Exception.Message)"
        }
    }
    $script:processes = @()
}
function Assert-PortReleased([int]$port) {
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

try {
    New-Item -ItemType Directory -Path $script:tempRoot -Force | Out-Null
    if (-not $MailBin) {
        $MailBin = Join-Path $env:TEMP 'asm-final/evernightmail.exe'
        if (-not (Test-Path -LiteralPath $MailBin)) {
            $MailBin = 'P:/go/tmp/asm-final/evernightmail.exe'
        }
    }
    if (-not (Test-Path -LiteralPath $MailBin)) {
        Fail 'prereq.mail-binary' "找不到 EvernightMail 可执行文件：$MailBin（可通过 -MailBin 或 EVERNIGHTMAIL_BIN 指定）"
        throw "缺少 Mail 夹具"
    }
    Pass 'prereq.mail-binary' $MailBin

    $goExe = (Get-Command go -ErrorAction Stop).Source
    $loginExe = Join-Path $script:tempRoot 'login-server.exe'
    Push-Location $RepoRoot
    try {
        & $goExe build -o $loginExe ./cmd/login-server 2>&1 | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "login-server 构建失败" }
    } finally {
        Pop-Location
    }
    Pass 'prereq.login-server-build' $loginExe

    # ---- EvernightMail 夹具：STARTTLS SMTP + 自签测试 CA + tester 用户 ----
    $smtpPort = FreePort; $script:ports += $smtpPort
    $mailHttpPort = FreePort; $script:ports += $mailHttpPort
    $mailData = (Join-Path $script:tempRoot 'mail-data') -replace '\\', '/'
    $mailConfigPath = Join-Path $script:tempRoot 'EvernightMail.yaml'
    $mailYaml = @"
version: 1
server: {hostname: mail.final.test, data_dir: '$mailData', log_dir: '$mailData/logs', shutdown_timeout: 5s}
listeners:
  - {id: smtp, protocol: smtp, address: "127.0.0.1:$smtpPort", tls: starttls, cert: local-test, enabled: true}
  - {id: admin, protocol: http, address: "127.0.0.1:$mailHttpPort", tls: disabled, enabled: true}
tls:
  mode: auto
  identities:
    - {id: local-test, mode: auto, sans: {dns: [localhost], ip: [127.0.0.1]}, validity: 720h}
  ca: {dir: '$mailData/certs', validity: 87600h, export_path: '$mailData/certs/ca.crt'}
storage: {mail_root: '$mailData/mail', timezone: UTC, fsync: false, repair_on_start: true}
logging: {level: info, server_log: '$mailData/logs/server.log'}
admin: {username: admin, password: admin-test-pass, mode: required}
web: {enabled: false}
users:
  defaults: {auth: {smtp: required, imap: required, pop3: required}}
  items:
    - {id: usr_11111111111111111111111111111111, login_name: tester, password: test-pass, enabled: true, auth: {smtp: required, imap: required, pop3: required}}
protocols:
  smtp: {allow_anonymous_mail: false, max_message_bytes: 1048576, max_connections: 8, read_timeout: 30s, session_timeout: 5m}
delivery: {unknown_recipient: reject}
faults: {enabled: false}
"@
    Set-Content -LiteralPath $mailConfigPath -Value $mailYaml -Encoding UTF8
    $script:processes += Start-Process -FilePath $MailBin -ArgumentList @('serve', '--config', $mailConfigPath) `
        -WorkingDirectory $script:tempRoot -PassThru -RedirectStandardOutput (Join-Path $script:tempRoot 'mail.out.log') `
        -RedirectStandardError (Join-Path $script:tempRoot 'mail.err.log')
    if (-not (Wait-Port $smtpPort 45000)) {
        Fail 'mail.start' "SMTP 未监听；stderr=" + ((Get-Content -LiteralPath (Join-Path $script:tempRoot 'mail.err.log') -Raw -ErrorAction SilentlyContinue) -replace "`r?`n", ' ')
        throw "Mail 未就绪"
    }
    $mailCA = Join-Path $mailData 'certs/ca.crt'
    $deadline = (Get-Date).AddSeconds(30)
    while (-not (Test-Path -LiteralPath $mailCA) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 300 }
    if (-not (Test-Path -LiteralPath $mailCA)) { Fail 'mail.ca' '自动测试 CA 未生成'; throw "缺少测试 CA" }
    Pass 'mail.start' "smtp=127.0.0.1:$smtpPort ca=$mailCA"

    # ---- 真实 SMTPSender 回归（Go 测试，环境变量注入）----
    $env:MAIL_E2E_ADDR = "127.0.0.1:$smtpPort"
    $env:MAIL_E2E_CA = ($mailCA -replace '\\', '/')
    $env:MAIL_E2E_USER = 'tester'
    $env:MAIL_E2E_PASSWORD = 'test-pass'
    Push-Location $RepoRoot
    try {
        $sendOutput = & $goExe test -count=1 -timeout 120s -run 'TestMailE2EReal' ./internal/mailer 2>&1
        $sendExit = $LASTEXITCODE
    } finally {
        Pop-Location
        Remove-Item Env:MAIL_E2E_ADDR, Env:MAIL_E2E_CA, Env:MAIL_E2E_USER, Env:MAIL_E2E_PASSWORD -ErrorAction SilentlyContinue
    }
    if ($sendExit -eq 0) {
        Pass 'delivery.real-starttls' 'STARTTLS + 信任测试 CA 真实发送成功；错误凭据永久 AUTH 失败；错误根 TLS 失败不降级'
    } else {
        Fail 'delivery.real-starttls' (($sendOutput | Out-String) -replace "`r?`n", ' ').Substring(0, [Math]::Min(600, (($sendOutput | Out-String) -replace "`r?`n", ' ').Length))
    }

    # ---- login-server 装配冒烟（mail.enabled=true，真实 Mail 地址/CA/env 密码）----
    $loginPort = FreePort; $script:ports += $loginPort
    $loginConfigPath = Join-Path $script:tempRoot 'login.yaml'
    $loginYaml = @"
server:
  listen_addr: "127.0.0.1:$loginPort"
  public_base_url: "http://127.0.0.1:$loginPort"
  shutdown_timeout_seconds: 5
logging: {level: info, format: text}
database:
  driver: sqlite
  path: "$(($script:tempRoot -replace '\\','/'))/login.db"
  wal: true
  busy_timeout_ms: 5000
mail:
  enabled: true
  smtp:
    addr: "127.0.0.1:$smtpPort"
    host: "localhost"
    tls_mode: starttls
    trusted_roots: ["$($mailCA -replace '\\','/')"]
    username: "tester"
    password: "env:LOGIN_MAIL_SMTP_PASSWORD"
    timeout_seconds: 10
  from:
    address: "tester@mail.final.test"
    name: "EvernightLogin"
  app_name: "EvernightLogin"
  delivery: {max_attempts: 3, timeout_seconds: 120}
"@
    Set-Content -LiteralPath $loginConfigPath -Value $loginYaml -Encoding UTF8
    $masterKeyFile = Join-Path $script:tempRoot 'master.key'
    $keyBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($keyBytes)
    [System.IO.File]::WriteAllText($masterKeyFile, [Convert]::ToBase64String($keyBytes))
    $initPasswordFile = Join-Path $script:tempRoot 'init-password.txt'
    Set-Content -LiteralPath $initPasswordFile -Value 'Root-Test-Password-139!' -Encoding UTF8
    $env:LOGIN_MAIL_SMTP_PASSWORD = 'test-pass'
    try {
        Push-Location $script:tempRoot
        try {
            & $loginExe init --config $loginConfigPath --master-key-file $masterKeyFile --password-file $initPasswordFile --operator mail-e2e 2>&1 | Out-File (Join-Path $script:tempRoot 'login-init.log')
            $initExit = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($initExit -eq 0) {
            Pass 'login.init' 'login-server init 成功'
        } else {
            Fail 'login.init' ('exit=' + $initExit + ' ' + ((Get-Content -LiteralPath (Join-Path $script:tempRoot 'login-init.log') -Raw) -replace "`r?`n", ' '))
        }
        $script:processes += Start-Process -FilePath $loginExe -ArgumentList @('serve', '--config', $loginConfigPath, '--master-key-file', $masterKeyFile) `
            -WorkingDirectory $script:tempRoot -PassThru -RedirectStandardOutput (Join-Path $script:tempRoot 'login.out.log') `
            -RedirectStandardError (Join-Path $script:tempRoot 'login.err.log')
        if (Wait-Port $loginPort 45000) {
            Pass 'login.serve-mail-enabled' 'login-server 使用真实 mail 配置启动并监听'
        } else {
            Fail 'login.serve-mail-enabled' ((Get-Content -LiteralPath (Join-Path $script:tempRoot 'login.err.log') -Raw -ErrorAction SilentlyContinue) -replace "`r?`n", ' ')
        }
    } finally {
        Remove-Item Env:LOGIN_MAIL_SMTP_PASSWORD -ErrorAction SilentlyContinue
    }

    NotTested 'login.actual-reset-send' '本脚本未创建带已验证邮箱的用户，因此未通过业务找回流程触发真实邮件；真实发送由 delivery.real-starttls 覆盖，业务接线属步骤 140'
    NotTested 'mail.restart-orphan-reconcile-e2e' 'Reconcile 由单元测试覆盖（status_test.go），未在本 E2E 中构造孤儿记录'
    NotTested 'mail.tls-implicit' '本脚本仅覆盖 STARTTLS；implicit 由导入测试建立的可选夹具另行验证'
} catch {
    Fail 'e2e.unhandled' $_.Exception.Message
} finally {
    Stop-OwnedProcesses
    $released = $true
    foreach ($port in $script:ports) {
        if (-not (Assert-PortReleased $port)) { $released = $false; Write-Host "WARN port $port 未释放" }
    }
    if (-not $released) { Fail 'cleanup.ports' '部分端口未释放' } else { Pass 'cleanup.ports' '全部回环端口已释放' }
    if (Test-Path -LiteralPath $script:tempRoot) {
        Remove-Item -LiteralPath $script:tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$total = $script:pass + $script:fail + $script:notTested
Write-Host ("SUMMARY PASS={0} FAIL={1} NOT_TESTED={2} total={3}" -f $script:pass, $script:fail, $script:notTested, $total)
if ($script:fail -gt 0) { exit 1 }
exit 0
