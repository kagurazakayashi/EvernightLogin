# E2E smoke test for the real login-server process (Windows PowerShell 5.1+).
#
# Builds login-server/loginctl/loginte2e, creates a throw-away directory with a
# SQLite database, runs the real `login-server init` (root password from a
# protected random temporary file, never printed) and then drives several real
# `login-server serve` instances over a loopback random port:
#
#   run A  normal mode, protocol endpoints and admin JSON API disabled
#   run B  --enable-protocol --enable-admin-api
#   run M  maintenance mode after `loginctl maintenance-enter`
#   run F  normal mode again after `loginctl maintenance-exit`
#
# It verifies health/openapi/login page, OAuth/OIDC discovery+JWKS, protocol
# disabled 404s, admin API disabled 404 / anonymous 401, the loginte2e
# discovery/jwks suites, single-instance database lock rejection, bounded
# graceful shutdown on Ctrl+Break, maintenance-mode 503s, CLI online command
# exit codes, loginctl diag/validate commands, access log writing, and finally
# that no process, port or repository database side effect is left behind.
#
# The repository database (database/login.db) is never opened or modified.
#
# Reason for the generated helper: Windows PowerShell cannot create a process
# in a new console process group and deliver Ctrl+Break to it (no CREATE_NEW_
# PROCESS_GROUP / GenerateConsoleCtrlEvent exposure). A tiny standard-library
# Go helper is generated under the temporary directory (with the normal Go
# toolchain that this test already requires) to start a child in its own
# process group, send Ctrl+Break (the Go runtime maps it to os.Interrupt, the
# same signal context as SIGINT/SIGTERM handling) and report the exit code.
# The helper is removed together with the temporary directory.
#
# Read-only with respect to the repository: it only reads the repository and
# never calls git. No network access beyond 127.0.0.1. No external mail/webhook
# is triggered. All outputs are sanitized: passwords and test session secrets
# are never printed.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1 -KeepArtifacts
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\e2e-login-server.ps1 -TimeoutSeconds 600
#
# Output: a structured result.json (plus raw process logs) under the temporary
# work directory, and a PASS/FAIL/NOT_TESTED summary in the terminal.
#   -KeepArtifacts keeps the temporary work directory even on success.
#   By default a passing run deletes the temporary directory; a failing run
#   keeps it (minimal sanitized evidence) and prints the path.
#
# Exit codes: 0 = no failures; 1 = at least one failure (including timeout).

[CmdletBinding()]
param(
    [switch]$KeepArtifacts,

    [ValidateRange(30, 1800)]
    [int]$TimeoutSeconds = 300
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$script:startedAt = Get-Date
$script:deadline = $script:startedAt.AddSeconds($TimeoutSeconds)
$script:checks = New-Object System.Collections.Generic.List[object]
$script:children = New-Object System.Collections.Generic.List[object]
$script:passCount = 0
$script:failCount = 0
$script:notTestedCount = 0
$script:childSeq = 0
$script:secretValues = New-Object System.Collections.Generic.List[string]
$script:workRoot = $null
$script:helperExe = $null
$script:httpClient = $null
$script:goExe = $null
$script:abortReason = ""

# ---------------------------------------------------------------- environment

# MSYS2/Cygwin shells can export both NO_PROXY and no_proxy (and mixed-case
# proxy variants). .NET ProcessStartInfo cannot materialise such an environment
# dictionary, which breaks process creation from PowerShell. Normalise them.
function Remove-CaseDuplicateEnvironment {
    try {
        $groups = [Environment]::GetEnvironmentVariables().Keys |
            Group-Object { $_.ToString().ToUpperInvariant() }
        foreach ($group in $groups) {
            if ($group.Count -gt 1) {
                foreach ($name in $group.Group) {
                    Remove-Item -LiteralPath ("Env:" + $name) -ErrorAction SilentlyContinue
                }
            }
        }
    } catch {
        # Best effort: a normal environment has no duplicates.
    }
}

# Remove LOGIN_* configuration overrides so the generated YAML is authoritative.
function Remove-LoginEnvironment {
    try {
        $overrides = Get-ChildItem Env: | Where-Object { $_.Name -like "LOGIN_*" }
        foreach ($item in $overrides) {
            Remove-Item -LiteralPath ("Env:" + $item.Name) -ErrorAction SilentlyContinue
        }
    } catch {
        # Best effort only.
    }
}

# ---------------------------------------------------------------- utilities

# Replace known test secrets in any text that may reach the terminal or JSON.
function Protect-Text {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $value = $Text
    foreach ($secret in $script:secretValues) {
        if (-not [string]::IsNullOrEmpty($secret)) {
            $value = $value.Replace($secret, "[REDACTED]")
        }
    }
    return $value
}

# Collapse and truncate a text snippet for evidence fields.
function Format-Snippet {
    param([string]$Text, [int]$Limit = 400)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $flat = ($Text -replace "\r", " " -replace "\n", " ").Trim()
    $flat = Protect-Text $flat
    if ($flat.Length -gt $Limit) {
        return $flat.Substring(0, $Limit) + "..."
    }
    return $flat
}

function Read-Utf8Text {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    try {
        return [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    } catch {
        return ""
    }
}

# Parse a JSON document, tolerating leading/trailing human readable lines.
function ConvertFrom-JsonText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try {
        return ($Text | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        # Fall through to brace extraction.
    }
    $start = $Text.IndexOf("{")
    $end = $Text.LastIndexOf("}")
    if ($start -ge 0 -and $end -gt $start) {
        $slice = $Text.Substring($start, $end - $start + 1)
        try {
            return ($slice | ConvertFrom-Json -ErrorAction Stop)
        } catch {
            return $null
        }
    }
    return $null
}

# Generate a random test-only password / test secret (never printed).
# Character set avoids quotes/backticks so the value is safe inside a file.
function New-TestPassword {
    param([int]$Length = 28)
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*-_=+"
    $bytes = New-Object byte[] $Length
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    $builder = New-Object System.Text.StringBuilder
    foreach ($value in $bytes) {
        [void]$builder.Append($alphabet[($value % $alphabet.Length)])
    }
    return $builder.ToString()
}

function Get-JsonValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

# Summarize failed cases of a loginte2e --json report (case=detail; ...).
function Get-FailedCaseText {
    param($ReportJson)
    $results = Get-JsonValue $ReportJson "results"
    if ($null -eq $results) { return "" }
    $parts = @()
    foreach ($item in @($results)) {
        if ((Get-JsonValue $item "status") -eq "fail") {
            $parts += ((Get-JsonValue $item "case") + "=" + [string](Get-JsonValue $item "detail"))
        }
    }
    return ($parts -join "; ")
}

function Add-Check {
    param(
        [string]$Id,
        [string]$Name,
        [ValidateSet("PASS", "FAIL", "NOT_TESTED")]
        [string]$Status,
        [string]$Evidence = "",
        [string]$Detail = ""
    )
    $entry = New-Object psobject
    $entry | Add-Member -MemberType NoteProperty -Name id -Value $Id
    $entry | Add-Member -MemberType NoteProperty -Name name -Value $Name
    $entry | Add-Member -MemberType NoteProperty -Name status -Value $Status
    $entry | Add-Member -MemberType NoteProperty -Name evidence -Value (Protect-Text $Evidence)
    $entry | Add-Member -MemberType NoteProperty -Name detail -Value (Protect-Text $Detail)
    $script:checks.Add($entry) | Out-Null

    $text = "[$Status] $Id - $Name"
    switch ($Status) {
        "PASS" {
            $script:passCount = $script:passCount + 1
            Write-Host $text
        }
        "FAIL" {
            $script:failCount = $script:failCount + 1
            Write-Host $text -ForegroundColor Red
            if (-not [string]::IsNullOrWhiteSpace($Detail)) {
                Write-Host ("       reason: " + (Format-Snippet $Detail 300)) -ForegroundColor DarkRed
            }
        }
        "NOT_TESTED" {
            $script:notTestedCount = $script:notTestedCount + 1
            Write-Host $text -ForegroundColor DarkYellow
        }
    }
}

function Add-Pass {
    param([string]$Id, [string]$Name, [string]$Evidence = "")
    Add-Check -Id $Id -Name $Name -Status "PASS" -Evidence $Evidence
}

function Add-Fail {
    param([string]$Id, [string]$Name, [string]$Evidence = "", [string]$Detail = "")
    Add-Check -Id $Id -Name $Name -Status "FAIL" -Evidence $Evidence -Detail $Detail
}

function Add-NotTested {
    param([string]$Id, [string]$Name, [string]$Detail = "")
    Add-Check -Id $Id -Name $Name -Status "NOT_TESTED" -Detail $Detail
}

function Get-RemainingMilliseconds {
    param([int]$Cap = 120000)
    $remaining = [int]($script:deadline - (Get-Date)).TotalMilliseconds
    if ($remaining -lt 1000) { return 1000 }
    if ($remaining -gt $Cap) { return $Cap }
    return $remaining
}

function Assert-TimeBudget {
    param([string]$Phase)
    if ((Get-Date) -ge $script:deadline) {
        throw ("global timeout of $TimeoutSeconds s reached during phase $Phase")
    }
}

# ---------------------------------------------------------------- process harness

# Invoke the generated helper synchronously and return exit code / output.
function Invoke-Helper {
    param([string[]]$HelperArgs)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $text = (& $script:helperExe @HelperArgs 2>&1 | Out-String)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    $result = New-Object psobject
    $result | Add-Member -MemberType NoteProperty -Name ExitCode -Value $code
    $result | Add-Member -MemberType NoteProperty -Name Output -Value $text.Trim()
    return $result
}

function Start-TrackedChild {
    param(
        [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$Label = "child",
        [string]$WorkingDirectory = ""
    )
    $script:childSeq = $script:childSeq + 1
    $sequence = $script:childSeq
    $logDir = Join-Path $script:workRoot "logs"
    $child = New-Object psobject
    $child | Add-Member -MemberType NoteProperty -Name Label -Value $Label
    $child | Add-Member -MemberType NoteProperty -Name Pid -Value 0
    $child | Add-Member -MemberType NoteProperty -Name OutFile -Value (Join-Path $logDir ("proc-$sequence-" + $Label + ".out"))
    $child | Add-Member -MemberType NoteProperty -Name ErrFile -Value (Join-Path $logDir ("proc-$sequence-" + $Label + ".err"))
    $child | Add-Member -MemberType NoteProperty -Name PidFile -Value (Join-Path $logDir ("proc-$sequence-" + $Label + ".pid"))
    $child | Add-Member -MemberType NoteProperty -Name ResultFile -Value (Join-Path $logDir ("proc-$sequence-" + $Label + ".result.json"))
    $child | Add-Member -MemberType NoteProperty -Name Exe -Value $Exe
    $child | Add-Member -MemberType NoteProperty -Name Reaped -Value $false

    $helperArgs = @("start", "--exe", $Exe, "--out", $child.OutFile,
        "--err", $child.ErrFile, "--pid", $child.PidFile)
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $helperArgs += @("--dir", $WorkingDirectory)
    }
    $helperArgs += @("--")
    $helperArgs += $Arguments
    $helper = Invoke-Helper $helperArgs
    if ($helper.ExitCode -ne 0) {
        throw ("failed to start " + $Label + ": " + (Format-Snippet $helper.Output))
    }
    $pidText = Read-Utf8Text $child.PidFile
    if ($pidText -notmatch "(\d+)") {
        throw ("failed to read pid of " + $Label)
    }
    $child.Pid = [int]$Matches[1]
    $script:children.Add($child) | Out-Null
    return $child
}

function Wait-TrackedChild {
    param($Child, [int]$TimeoutMs = 30000)
    if ($Child.Reaped) { return $true }
    $waitMs = Get-RemainingMilliseconds -Cap $TimeoutMs
    if ($waitMs -lt 1000) { $waitMs = 1000 }
    $helper = Invoke-Helper @("wait", "--pid", "$($Child.Pid)",
        "--timeout-ms", "$waitMs", "--result", $Child.ResultFile)
    if ($helper.ExitCode -ne 0) { return $false }
    $raw = Read-Utf8Text $Child.ResultFile
    $result = ConvertFrom-JsonText $raw
    if ($null -eq $result) { return $false }
    if ($null -ne (Get-JsonValue $result "exited") -and [bool](Get-JsonValue $result "exited")) {
        $Child.Reaped = $true
        return $true
    }
    return $false
}

function Get-TrackedChildExitCode {
    param($Child)
    $raw = Read-Utf8Text $Child.ResultFile
    $result = ConvertFrom-JsonText $raw
    if ($null -eq $result) { return $null }
    return (Get-JsonValue $result "exit_code")
}

function Stop-TrackedChild {
    param($Child, [int]$TimeoutMs = 10000)
    if ($null -eq $Child -or $Child.Reaped) { return }
    $null = Invoke-Helper @("kill", "--pid", "$($Child.Pid)")
    $null = Wait-TrackedChild -Child $Child -TimeoutMs $TimeoutMs
    if (-not $Child.Reaped) {
        try {
            Stop-Process -Id $Child.Pid -Force -ErrorAction SilentlyContinue
        } catch {
            # Ignore: the process may already be gone.
        }
    }
}

# Start a short lived command, wait for it (bounded) and return its result.
function Invoke-SyncChild {
    param(
        [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$Label = "sync",
        [int]$TimeoutMs = 60000,
        [string]$WorkingDirectory = ""
    )
    $child = Start-TrackedChild -Exe $Exe -Arguments $Arguments -Label $Label -WorkingDirectory $WorkingDirectory
    $exited = Wait-TrackedChild -Child $child -TimeoutMs $TimeoutMs
    $result = New-Object psobject
    $result | Add-Member -MemberType NoteProperty -Name Exited -Value $exited
    $result | Add-Member -MemberType NoteProperty -Name ExitCode -Value $null
    if ($exited) {
        $result.ExitCode = Get-TrackedChildExitCode $child
    } else {
        Stop-TrackedChild $child
    }
    $result | Add-Member -MemberType NoteProperty -Name StdOut -Value (Read-Utf8Text $child.OutFile)
    $result | Add-Member -MemberType NoteProperty -Name StdErr -Value (Read-Utf8Text $child.ErrFile)
    $result | Add-Member -MemberType NoteProperty -Name Child -Value $child
    return $result
}

# Bootstrap a command before the process harness exists (used for the Go builds).
# .NET Process with an explicit wait timeout is used because Windows PowerShell
# 5.1 loses Start-Process -PassThru ExitCode when WaitForExit(ms) is used.
function Invoke-BootstrapCommand {
    param(
        [string]$Exe,
        [string[]]$Arguments = @(),
        [string]$Label = "bootstrap",
        [int]$TimeoutMs = 180000,
        [string]$WorkingDirectory = ""
    )
    $script:childSeq = $script:childSeq + 1
    $sequence = $script:childSeq
    $logDir = Join-Path $script:workRoot "logs"
    $outPath = Join-Path $logDir ("bootstrap-" + $sequence + "-" + $Label + ".out")
    $errPath = Join-Path $logDir ("bootstrap-" + $sequence + "-" + $Label + ".err")
    $result = New-Object psobject
    $result | Add-Member -MemberType NoteProperty -Name Exited -Value $false
    $result | Add-Member -MemberType NoteProperty -Name ExitCode -Value $null
    $result | Add-Member -MemberType NoteProperty -Name TimedOut -Value $false

    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $Exe
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $info.WorkingDirectory = $WorkingDirectory
    }
    $info.Arguments = ($Arguments | ForEach-Object {
            if ($_ -match "\s") { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
        }) -join " "
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $info
    if (-not $process.Start()) {
        $result.TimedOut = $false
        $result.ExitCode = -1
        return $result
    }
    $stdoutText = $process.StandardOutput.ReadToEnd()
    $stderrText = $process.StandardError.ReadToEnd()
    $finished = $process.WaitForExit($TimeoutMs)
    if (-not $finished) {
        try { $process.Kill() } catch { }
        $result.TimedOut = $true
    } elseif ($process.HasExited) {
        $result.Exited = $true
        $result.ExitCode = $process.ExitCode
    }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($outPath, $stdoutText, $encoding)
    [System.IO.File]::WriteAllText($errPath, $stderrText, $encoding)
    $result | Add-Member -MemberType NoteProperty -Name StdOut -Value $stdoutText
    $result | Add-Member -MemberType NoteProperty -Name StdErr -Value $stderrText
    $result | Add-Member -MemberType NoteProperty -Name OutFile -Value $outPath
    $result | Add-Member -MemberType NoteProperty -Name ErrFile -Value $errPath
    $process.Dispose()
    return $result
}

# ---------------------------------------------------------------- HTTP helpers

function Get-HttpResult {
    param([string]$Url, [int]$TimeoutMs = 15000)
    $result = New-Object psobject
    $result | Add-Member -MemberType NoteProperty -Name Status -Value 0
    $result | Add-Member -MemberType NoteProperty -Name Body -Value ""
    $result | Add-Member -MemberType NoteProperty -Name Error -Value ""
    try {
        $request = New-Object System.Net.Http.HttpRequestMessage
        $request.Method = [System.Net.Http.HttpMethod]::Get
        $request.RequestUri = New-Object System.Uri($Url)
        $task = $script:httpClient.SendAsync($request)
        if (-not $task.Wait($TimeoutMs)) {
            $result.Error = "request timeout"
            return $result
        }
        $response = $task.Result
        try {
            $result.Status = [int]$response.StatusCode
            $result.Body = $response.Content.ReadAsStringAsync().Result
        } finally {
            $response.Dispose()
            $request.Dispose()
        }
    } catch {
        $result.Error = $_.Exception.GetBaseException().Message
    }
    return $result
}

function Wait-ServerReady {
    param([string]$HealthUrl, [int]$TimeoutMs = 30000)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $lastStatus = -1
    $lastError = ""
    while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
        if ((Get-Date) -ge $script:deadline) { break }
        $response = Get-HttpResult -Url $HealthUrl -TimeoutMs 3000
        if ($response.Status -eq 200) {
            $ready = New-Object psobject
            $ready | Add-Member -MemberType NoteProperty -Name Ready -Value $true
            $ready | Add-Member -MemberType NoteProperty -Name ElapsedMs -Value ([int]$watch.ElapsedMilliseconds)
            $ready | Add-Member -MemberType NoteProperty -Name LastStatus -Value 200
            $ready | Add-Member -MemberType NoteProperty -Name LastError -Value ""
            return $ready
        }
        $lastStatus = $response.Status
        $lastError = $response.Error
        Start-Sleep -Milliseconds 150
    }
    $failed = New-Object psobject
    $failed | Add-Member -MemberType NoteProperty -Name Ready -Value $false
    $failed | Add-Member -MemberType NoteProperty -Name ElapsedMs -Value ([int]$watch.ElapsedMilliseconds)
    $failed | Add-Member -MemberType NoteProperty -Name LastStatus -Value $lastStatus
    $failed | Add-Member -MemberType NoteProperty -Name LastError -Value $lastError
    return $failed
}

function Test-PortFree {
    param([int]$Port)
    $listener = $null
    try {
        $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        return $false
    } finally {
        if ($null -ne $listener) {
            try { $listener.Stop() } catch { }
        }
    }
}

function Wait-PortFree {
    param([int]$Port, [int]$TimeoutMs = 10000)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($watch.ElapsedMilliseconds -lt $TimeoutMs) {
        if (Test-PortFree -Port $Port) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return (Test-PortFree -Port $Port)
}

function New-FreeLoopbackPort {
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    return $port
}

# ---------------------------------------------------------------- ACL helpers

function Invoke-Icacls {
    param([string[]]$Arguments)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $text = (& icacls.exe @Arguments 2>&1 | Out-String)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldPreference
    }
    $result = New-Object psobject
    $result | Add-Member -MemberType NoteProperty -Name ExitCode -Value $code
    $result | Add-Member -MemberType NoteProperty -Name Output -Value $text
    return $result
}

# Restrict a file to the current user, SYSTEM and Administrators only (the same
# whitelist internal/secrets.CheckProtectedFile accepts on Windows).
function Set-ProtectedFileAcl {
    param([string]$Path)
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $result = Invoke-Icacls @($Path, "/inheritance:r",
        "/grant:r", ("*" + $me + ":(F)"),
        "/grant:r", "*S-1-5-18:(F)",
        "/grant:r", "*S-1-5-32-544:(F)")
    if ($result.ExitCode -ne 0) {
        throw ("icacls failed for protected file: " + (Format-Snippet $result.Output))
    }
}

# Deliberately loosen a file so internal/secrets protection checks must reject it.
function Set-UnprotectedFileAcl {
    param([string]$Path)
    $null = Invoke-Icacls @($Path, "/grant", "*S-1-5-32-545:(R)")
}

# ---------------------------------------------------------------- result writing

function Write-ResultJson {
    param([string]$Path, [bool]$Completed)
    $hostInfo = New-Object psobject
    $hostInfo | Add-Member -MemberType NoteProperty -Name os -Value ("Windows " + [Environment]::OSVersion.Version.ToString())
    $hostInfo | Add-Member -MemberType NoteProperty -Name powershell -Value $PSVersionTable.PSVersion.ToString()
    $hostInfo | Add-Member -MemberType NoteProperty -Name go -Value $script:goVersion
    $hostInfo | Add-Member -MemberType NoteProperty -Name logical_processors -Value $script:logicalProcessors
    $hostInfo | Add-Member -MemberType NoteProperty -Name gomaxprocs -Value $script:gomaxprocs
    $hostInfo | Add-Member -MemberType NoteProperty -Name cgo_enabled -Value "0"

    $summary = New-Object psobject
    $summary | Add-Member -MemberType NoteProperty -Name pass -Value $script:passCount
    $summary | Add-Member -MemberType NoteProperty -Name fail -Value $script:failCount
    $summary | Add-Member -MemberType NoteProperty -Name not_tested -Value $script:notTestedCount
    $summary | Add-Member -MemberType NoteProperty -Name total -Value ($script:passCount + $script:failCount + $script:notTestedCount)

    $document = New-Object psobject
    $document | Add-Member -MemberType NoteProperty -Name tool -Value "e2e-login-server"
    $document | Add-Member -MemberType NoteProperty -Name result_version -Value 1
    $document | Add-Member -MemberType NoteProperty -Name completed -Value $Completed
    $document | Add-Member -MemberType NoteProperty -Name started_at -Value $script:startedAt.ToUniversalTime().ToString("o")
    $document | Add-Member -MemberType NoteProperty -Name finished_at -Value (Get-Date).ToUniversalTime().ToString("o")
    $document | Add-Member -MemberType NoteProperty -Name duration_ms -Value ([int]((Get-Date) - $script:startedAt).TotalMilliseconds)
    $document | Add-Member -MemberType NoteProperty -Name host -Value $hostInfo
    $document | Add-Member -MemberType NoteProperty -Name repo -Value $script:repoRoot
    $document | Add-Member -MemberType NoteProperty -Name work_root -Value $script:workRoot
    $document | Add-Member -MemberType NoteProperty -Name config -Value $script:configSummary
    $document | Add-Member -MemberType NoteProperty -Name summary -Value $summary
    $failedChecks = New-Object System.Collections.Generic.List[string]
    foreach ($check in $script:checks.ToArray()) {
        if ($check.status -eq "FAIL") { $failedChecks.Add($check.id) | Out-Null }
    }
    $document | Add-Member -MemberType NoteProperty -Name checks -Value $script:checks.ToArray()
    $document | Add-Member -MemberType NoteProperty -Name failed_checks -Value $failedChecks.ToArray()
    $document | Add-Member -MemberType NoteProperty -Name limitations -Value @($script:limitations)

    $json = $document | ConvertTo-Json -Depth 8
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $json, $encoding)
}

# ---------------------------------------------------------------- main

try {
    Remove-CaseDuplicateEnvironment
    Remove-LoginEnvironment

    $script:logicalProcessors = [Environment]::ProcessorCount
    $script:gomaxprocs = [Math]::Max(1, [int][Math]::Floor($script:logicalProcessors / 2))
    $env:GOMAXPROCS = "$($script:gomaxprocs)"
    $env:CGO_ENABLED = "0"

    $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
    if (-not (Test-Path -LiteralPath (Join-Path $script:repoRoot "go.mod"))) {
        throw ("not a login repository root (go.mod missing): " + $script:repoRoot)
    }

    $goCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $goCommand) {
        throw "go toolchain not found in PATH"
    }
    $script:goExe = $goCommand.Source

    $stamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $suffix = [guid]::NewGuid().ToString("N").Substring(0, 8)
    $script:workRoot = Join-Path $env:TEMP ("login-e2e-" + $stamp + "-" + $suffix)
    New-Item -ItemType Directory -Path $script:workRoot -Force | Out-Null
    $binDir = Join-Path $script:workRoot "bin"
    $dataDir = Join-Path $script:workRoot "data"
    $secretsDir = Join-Path $script:workRoot "secrets"
    $logsDir = Join-Path $script:workRoot "logs"
    $nativeDir = Join-Path $script:workRoot "native"
    foreach ($directory in @($binDir, $dataDir, $secretsDir, $logsDir, $nativeDir)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    # Loopback HTTP client: never use a proxy and never follow redirects, so the
    # status codes asserted below are the real endpoint responses.
    Add-Type -AssemblyName System.Net.Http
    $httpHandler = New-Object System.Net.Http.HttpClientHandler
    $httpHandler.UseProxy = $false
    $httpHandler.AllowAutoRedirect = $false
    $script:httpClient = New-Object System.Net.Http.HttpClient($httpHandler)
    $script:httpClient.Timeout = [TimeSpan]::FromSeconds(20)

    Write-Host "login-server end-to-end smoke test"
    Write-Host ("  repo:           " + $script:repoRoot)
    Write-Host ("  work directory: " + $script:workRoot)
    Write-Host ("  timeout:        " + $TimeoutSeconds + " s (deadline enforced)")
    Write-Host ("  concurrency:    GOMAXPROCS=" + $script:gomaxprocs + " CGO_ENABLED=0 (half of " +
        $script:logicalProcessors + " logical processors)")
    Write-Host ""

    # Record the repository database state; it must not change.
    $repoDatabase = Join-Path $script:repoRoot "database\login.db"
    $repoDatabaseExisted = Test-Path -LiteralPath $repoDatabase
    $repoDatabaseHashBefore = ""
    if ($repoDatabaseExisted) {
        $repoDatabaseHashBefore = (Get-FileHash -LiteralPath $repoDatabase -Algorithm SHA256).Hash
    }

    $script:limitations = @(
        "Real strong-authenticated management session (Passkey/MFA) is not obtainable unattended; admin JSON API is verified for anonymous rejection only.",
        "OAuth/OIDC authcode, token, device and QR suites need a registered OAuth client and a real browser session cookie; no non-interactive client registration path exists in this build.",
        "TLS/mTLS, reverse proxy behavior and real email/webhook delivery are out of scope (loopback plain HTTP, local delivery disabled by design).",
        "On Windows only Ctrl+Break (delivered as os.Interrupt, the same cancel context used for SIGINT/SIGTERM) is exercised; a CTRL_CLOSE/SIGTERM delivery would close the harness console and is not attempted.",
        "A single random loopback port is selected before startup; a concurrent port theft is reported as a startup failure rather than retried."
    )

    $script:configSummary = New-Object psobject
    $script:configSummary | Add-Member -MemberType NoteProperty -Name listen_addr -Value ""
    $script:configSummary | Add-Member -MemberType NoteProperty -Name protocol_issuer -Value ""
    $script:configSummary | Add-Member -MemberType NoteProperty -Name admin_api_prefix -Value "/admin/v1"
    $script:configSummary | Add-Member -MemberType NoteProperty -Name tls -Value "disabled"
    $script:configSummary | Add-Member -MemberType NoteProperty -Name passkey -Value "disabled"
    $script:configSummary | Add-Member -MemberType NoteProperty -Name registration -Value "disabled"
    $script:configSummary | Add-Member -MemberType NoteProperty -Name database -Value "temporary SQLite"
    $script:configSummary | Add-Member -MemberType NoteProperty -Name email_outbound -Value "disabled by product design"

    Add-Pass "env.normalized" "environment prepared for isolated loopback testing" `
        ("GOMAXPROCS=" + $script:gomaxprocs + " CGO_ENABLED=0")

    # ------------------------------------------------------------ build phase

    Write-Host ""
    Write-Host "phase: build"
    $script:goVersion = ""
    $goVersionResult = Invoke-BootstrapCommand -Exe $script:goExe -Arguments @("version") `
        -Label "go-version" -TimeoutMs 30000
    if ($goVersionResult.Exited -and $goVersionResult.ExitCode -eq 0) {
        $script:goVersion = Format-Snippet $goVersionResult.StdOut 200
    }

    $loginServerExe = Join-Path $binDir "login-server.exe"
    $loginctlExe = Join-Path $binDir "loginctl.exe"
    $loginte2eExe = Join-Path $binDir "loginte2e.exe"
    $buildTimeout = Get-RemainingMilliseconds -Cap 180000

    $buildResult = Invoke-BootstrapCommand -Exe $script:goExe -WorkingDirectory $script:repoRoot `
        -Label "build-login-server" -TimeoutMs $buildTimeout `
        -Arguments @("build", "-trimpath", "-p", "3", "-o", $loginServerExe, "./cmd/login-server")
    if ($buildResult.Exited -and $buildResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $loginServerExe)) {
        Add-Pass "build.login-server" "built login-server from ./cmd/login-server" `
            ("size=" + (Get-Item -LiteralPath $loginServerExe).Length + " bytes")
    } else {
        Add-Fail "build.login-server" "build login-server" ("exit=" + $buildResult.ExitCode) `
            (Format-Snippet ($buildResult.StdErr + " " + $buildResult.StdOut) 600)
    }

    $buildResult = Invoke-BootstrapCommand -Exe $script:goExe -WorkingDirectory $script:repoRoot `
        -Label "build-loginctl" -TimeoutMs $buildTimeout `
        -Arguments @("build", "-trimpath", "-p", "3", "-o", $loginctlExe, "./cmd/loginctl")
    if ($buildResult.Exited -and $buildResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $loginctlExe)) {
        Add-Pass "build.loginctl" "built loginctl online/local CLI" `
            ("size=" + (Get-Item -LiteralPath $loginctlExe).Length + " bytes")
    } else {
        Add-Fail "build.loginctl" "build loginctl" ("exit=" + $buildResult.ExitCode) `
            (Format-Snippet ($buildResult.StdErr + " " + $buildResult.StdOut) 600)
    }

    $buildResult = Invoke-BootstrapCommand -Exe $script:goExe -WorkingDirectory $script:repoRoot `
        -Label "build-loginte2e" -TimeoutMs $buildTimeout `
        -Arguments @("build", "-trimpath", "-p", "3", "-o", $loginte2eExe, "./tools/loginte2e")
    if ($buildResult.Exited -and $buildResult.ExitCode -eq 0 -and (Test-Path -LiteralPath $loginte2eExe)) {
        Add-Pass "build.loginte2e" "built loginte2e E2E protocol/admin client" `
            ("size=" + (Get-Item -LiteralPath $loginte2eExe).Length + " bytes")
    } else {
        Add-Fail "build.loginte2e" "build loginte2e" ("exit=" + $buildResult.ExitCode) `
            (Format-Snippet ($buildResult.StdErr + " " + $buildResult.StdOut) 600)
    }

    # Generate the tiny stdlib-only process harness.
    $helperSourcePath = Join-Path $nativeDir "e2e-proc.go"
    $helperSource = @'
//go:build windows

// e2e-proc is a tiny Windows process harness generated by
// scripts/e2e-login-server.ps1. It starts a console child in its own process
// group (CREATE_NEW_PROCESS_GROUP), delivers Ctrl+Break (mapped by the Go
// runtime to os.Interrupt) and reports the child exit code. Standard library
// only; it is deleted together with the temporary work directory.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procGenerateConsoleCtrlEvent = kernel32.NewProc("GenerateConsoleCtrlEvent")
	procAttachConsole            = kernel32.NewProc("AttachConsole")
	procFreeConsole              = kernel32.NewProc("FreeConsole")
)

const (
	ctrlBreakEvent      = 1
	createNewProcessGrp = 0x00000200
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: e2e-proc start|signal|wait|kill ...")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "start":
		os.Exit(runStart(os.Args[2:]))
	case "signal":
		os.Exit(runSignal(os.Args[2:]))
	case "wait":
		os.Exit(runWait(os.Args[2:]))
	case "kill":
		os.Exit(runKill(os.Args[2:]))
	default:
		fmt.Fprintln(os.Stderr, "e2e-proc: unknown mode")
		os.Exit(2)
	}
}

func runStart(args []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	exe := fs.String("exe", "", "executable path")
	dir := fs.String("dir", "", "working directory")
	outPath := fs.String("out", "", "stdout file")
	errPath := fs.String("err", "", "stderr file")
	pidPath := fs.String("pid", "", "pid file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	childArgs := fs.Args()
	if *exe == "" || *pidPath == "" || *outPath == "" || *errPath == "" {
		fmt.Fprintln(os.Stderr, "e2e-proc start: --exe/--out/--err/--pid are required")
		return 2
	}
	outFile, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e-proc start: open stdout:", err)
		return 1
	}
	defer outFile.Close()
	errFile, err := os.OpenFile(*errPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e-proc start: open stderr:", err)
		return 1
	}
	defer errFile.Close()
	cmd := exec.Command(*exe, childArgs...)
	if *dir != "" {
		cmd.Dir = *dir
	}
	cmd.Stdout = outFile
	cmd.Stderr = errFile
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createNewProcessGrp}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-proc start:", err)
		return 1
	}
	pid := cmd.Process.Pid
	if err := os.WriteFile(*pidPath, []byte(fmt.Sprintf("%d\n", pid)), 0o600); err != nil {
		_ = cmd.Process.Kill()
		fmt.Fprintln(os.Stderr, "e2e-proc start: write pid:", err)
		return 1
	}
	fmt.Printf("pid=%d\n", pid)
	_ = cmd.Process.Release()
	return 0
}

func runSignal(args []string) int {
	fs := flag.NewFlagSet("signal", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "target pid / process group id")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pid <= 0 {
		fmt.Fprintln(os.Stderr, "e2e-proc signal: --pid is required")
		return 2
	}
	ok, _, callErr := procGenerateConsoleCtrlEvent.Call(uintptr(ctrlBreakEvent), uintptr(*pid))
	if ok != 0 {
		fmt.Println("signal=sent")
		return 0
	}
	// The target may own a separate console (when the launcher had no console):
	// attach to it, then signal console group 0 (all processes of that console).
	attached, _, attachErr := procAttachConsole.Call(uintptr(*pid))
	if attached == 0 {
		fmt.Fprintf(os.Stderr, "e2e-proc signal: GenerateConsoleCtrlEvent failed: %v; AttachConsole failed: %v\n",
			callErr, attachErr)
		return 1
	}
	ok2, _, callErr2 := procGenerateConsoleCtrlEvent.Call(uintptr(ctrlBreakEvent), 0)
	_, _, _ = procFreeConsole.Call()
	if ok2 == 0 {
		fmt.Fprintln(os.Stderr, "e2e-proc signal: GenerateConsoleCtrlEvent after attach failed:", callErr2)
		return 1
	}
	fmt.Println("signal=sent-after-attach")
	return 0
}

type waitResult struct {
	Exited   bool   `json:"exited"`
	ExitCode int    `json:"exit_code"`
	Detail   string `json:"detail,omitempty"`
}

func runWait(args []string) int {
	fs := flag.NewFlagSet("wait", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "target pid")
	timeoutMS := fs.Int("timeout-ms", 30000, "timeout milliseconds")
	resultPath := fs.String("result", "", "json result file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pid <= 0 || *resultPath == "" {
		fmt.Fprintln(os.Stderr, "e2e-proc wait: --pid and --result are required")
		return 2
	}
	result := waitResult{}
	process, err := os.FindProcess(*pid)
	if err != nil {
		result.Detail = "FindProcess failed"
		writeResult(*resultPath, result)
		return 0
	}
	done := make(chan *os.ProcessState, 1)
	go func() {
		state, _ := process.Wait()
		done <- state
	}()
	select {
	case state := <-done:
		result.Exited = true
		if state != nil {
			result.ExitCode = state.ExitCode()
		}
	case <-time.After(time.Duration(*timeoutMS) * time.Millisecond):
		result.Exited = false
		result.Detail = "timeout"
	}
	writeResult(*resultPath, result)
	return 0
}

func runKill(args []string) int {
	fs := flag.NewFlagSet("kill", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "target pid")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pid <= 0 {
		fmt.Fprintln(os.Stderr, "e2e-proc kill: --pid is required")
		return 2
	}
	process, err := os.FindProcess(*pid)
	if err != nil {
		// Already gone is fine for cleanup.
		return 0
	}
	if err := process.Kill(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-proc kill:", err)
		return 1
	}
	return 0
}

func writeResult(path string, result waitResult) {
	payload, _ := json.Marshal(result)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "e2e-proc wait: write result:", err)
	}
}
'@
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($helperSourcePath, $helperSource, $encoding)

    $script:helperExe = Join-Path $nativeDir "e2e-proc.exe"
    $helperBuild = Invoke-BootstrapCommand -Exe $script:goExe -WorkingDirectory $nativeDir `
        -Label "build-helper" -TimeoutMs (Get-RemainingMilliseconds -Cap 120000) `
        -Arguments @("build", "-trimpath", "-p", "3", "-o", $script:helperExe, "e2e-proc.go")
    if ($helperBuild.Exited -and $helperBuild.ExitCode -eq 0 -and (Test-Path -LiteralPath $script:helperExe)) {
        Add-Pass "build.process-harness" "built the temporary process harness (Ctrl+Break delivery)" `
            ("size=" + (Get-Item -LiteralPath $script:helperExe).Length + " bytes")
    } else {
        Add-Fail "build.process-harness" "build the temporary process harness" ("exit=" + $helperBuild.ExitCode) `
            (Format-Snippet ($helperBuild.StdErr + " " + $helperBuild.StdOut) 600)
    }

    if ($script:failCount -gt 0) {
        throw "build phase failed"
    }

    # ------------------------------------------------------------ config + init

    Write-Host ""
    Write-Host "phase: configuration, protected password file, first init"

    $port = New-FreeLoopbackPort
    $serverBaseUrl = "http://127.0.0.1:$port"
    $healthUrl = $serverBaseUrl + "/healthz"
    $databasePath = Join-Path $dataDir "login.db"
    $databasePathYaml = $databasePath -replace "\\", "/"
    $configPath = Join-Path $script:workRoot "login.yaml"
    $configYaml = @"
server:
  listen_addr: "127.0.0.1:$port"
  shutdown_timeout_seconds: 5
logging:
  level: "info"
  format: "text"
database:
  driver: sqlite
  path: "$databasePathYaml"
  wal: true
  busy_timeout_ms: 5000
protocol:
  issuer: "$serverBaseUrl"
"@
    [System.IO.File]::WriteAllText($configPath, $configYaml, $encoding)
    $script:configSummary.listen_addr = "127.0.0.1:$port"
    $script:configSummary.protocol_issuer = $serverBaseUrl

    $passwordFile = Join-Path $secretsDir "init-password.txt"
    $password = New-TestPassword
    $script:secretValues.Add($password) | Out-Null
    [System.IO.File]::WriteAllText($passwordFile, $password, $encoding)
    Set-ProtectedFileAcl -Path $passwordFile
    $masterKeyFile = Join-Path $secretsDir "master.key"
    $maintenanceStateDir = Join-Path $script:workRoot "data-maintenance"
    $operatorId = "e2e-smoke"

    $passwordAcl = Invoke-Icacls @($passwordFile)
    $aclLeaks = @("BUILTIN\Users", "NT AUTHORITY\Authenticated Users", "Everyone", "S-1-1-0", "S-1-5-32-545")
    $aclLeakFound = $false
    foreach ($marker in $aclLeaks) {
        if ($passwordAcl.Output -match [regex]::Escape($marker)) { $aclLeakFound = $true }
    }
    if ($passwordAcl.ExitCode -eq 0 -and -not $aclLeakFound) {
        Add-Pass "config.protected-password-file" "random root password stored in a protected temporary file" `
            "only current user/SYSTEM/Administrators hold access; value never printed"
    } else {
        Add-Fail "config.protected-password-file" "protected temporary password file" `
            (Format-Snippet $passwordAcl.Output 300) "unexpected principal in password file ACL"
    }

    Assert-TimeBudget "init"
    $initResult = Invoke-SyncChild -Exe $loginServerExe -Label "init" -TimeoutMs (Get-RemainingMilliseconds -Cap 120000) `
        -Arguments @("init", "--config", $configPath, "--master-key-file", $masterKeyFile,
            "--password-file", $passwordFile, "--operator", $operatorId)
    $initText = $initResult.StdOut + " " + $initResult.StdErr
    if ($initResult.Exited -and $initResult.ExitCode -eq 0 -and $initText -match "setup_verified") {
        Add-Pass "init.first-run" "login-server init created the unique root in a fresh SQLite database" `
            (Format-Snippet $initResult.StdOut 500)
    } else {
        Add-Fail "init.first-run" "login-server init first run" `
            ("exit=" + $initResult.ExitCode + "; " + (Format-Snippet $initResult.StdOut 300)) `
            (Format-Snippet $initResult.StdErr 600)
    }
    if ($initText.Contains($password)) {
        Add-Fail "init.no-password-echo" "init must not echo the root password" "" "password appeared in init output"
    } else {
        Add-Pass "init.no-password-echo" "init output does not contain the generated password" ""
    }

    Assert-TimeBudget "repeat init"
    $repeatInit = Invoke-SyncChild -Exe $loginServerExe -Label "init-repeat" -TimeoutMs (Get-RemainingMilliseconds -Cap 120000) `
        -Arguments @("init", "--config", $configPath, "--master-key-file", $masterKeyFile,
            "--password-file", $passwordFile, "--operator", $operatorId)
    $repeatText = $repeatInit.StdOut + " " + $repeatInit.StdErr
    if ($repeatInit.Exited -and $repeatInit.ExitCode -ne 0) {
        Add-Pass "init.repeat-rejected" "repeated init is rejected without rebuilding root" `
            ("exit=" + $repeatInit.ExitCode + "; " + (Format-Snippet $repeatText 200))
    } else {
        Add-Fail "init.repeat-rejected" "repeated init must be rejected" `
            ("exit=" + $repeatInit.ExitCode) (Format-Snippet $repeatText 400)
    }

    if (-not (Test-Path -LiteralPath $databasePath)) {
        throw "init did not create the temporary database"
    }

    $accessLogNormal = Join-Path $logsDir "access-normal.log"
    $accessLogProtocol = Join-Path $logsDir "access-protocol.log"
    $accessLogMaintenance = Join-Path $logsDir "access-maintenance.log"
    $accessLogFinal = Join-Path $logsDir "access-final.log"

    $serveCommonArgs = @("serve", "--config", $configPath, "--master-key-file", $masterKeyFile)
    $serveFeatureArgs = @("--enable-protocol", "--enable-admin-api")

    # Helper: start a serve instance, wait for health, and register the result.
    function Start-ServeInstance {
        param(
            [string]$Label,
            [string]$AccessLogPath,
            [string[]]$ExtraArguments = @(),
            [int]$PortToWait = $port
        )
        $arguments = @()
        $arguments += $serveCommonArgs
        $arguments += $ExtraArguments
        $arguments += @("--access-log", $AccessLogPath)
        $child = Start-TrackedChild -Exe $loginServerExe -Arguments $arguments -Label $Label
        $ready = Wait-ServerReady -HealthUrl ("http://127.0.0.1:" + $PortToWait + "/healthz") `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 30000)
        $instance = New-Object psobject
        $instance | Add-Member -MemberType NoteProperty -Name Child -Value $child
        $instance | Add-Member -MemberType NoteProperty -Name Ready -Value $ready.Ready
        $instance | Add-Member -MemberType NoteProperty -Name StartupMs -Value $ready.ElapsedMs
        $instance | Add-Member -MemberType NoteProperty -Name HealthStatus -Value $ready.LastStatus
        $instance | Add-Member -MemberType NoteProperty -Name HealthError -Value $ready.LastError
        return $instance
    }

    # Helper: stop a serve instance with Ctrl+Break and verify bounded shutdown.
    function Stop-ServeInstance {
        param($Instance, [int]$ShutdownTimeoutSeconds = 5)
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $signal = Invoke-Helper @("signal", "--pid", "$($Instance.Child.Pid)")
        $waitBudget = $ShutdownTimeoutSeconds * 1000 + 15000
        $exited = Wait-TrackedChild -Child $Instance.Child -TimeoutMs $waitBudget
        $durationMs = [int]$watch.ElapsedMilliseconds
        $exitCode = $null
        if ($exited) { $exitCode = Get-TrackedChildExitCode $Instance.Child }
        $stop = New-Object psobject
        $stop | Add-Member -MemberType NoteProperty -Name SignalExitCode -Value $signal.ExitCode
        $stop | Add-Member -MemberType NoteProperty -Name SignalOutput -Value $signal.Output
        $stop | Add-Member -MemberType NoteProperty -Name Exited -Value $exited
        $stop | Add-Member -MemberType NoteProperty -Name ExitCode -Value $exitCode
        $stop | Add-Member -MemberType NoteProperty -Name DurationMs -Value $durationMs
        return $stop
    }

    # ------------------------------------------------------------ run A: normal

    Write-Host ""
    Write-Host "phase: normal serve (protocol/admin API disabled)"
    Assert-TimeBudget "serve normal"

    $normal = Start-ServeInstance -Label "serve-normal" -AccessLogPath $accessLogNormal
    if ($normal.Ready) {
        Add-Pass "serve.start-normal" "real login-server serve listens and answers /healthz" `
            ("pid=" + $normal.Child.Pid + " startup=" + $normal.StartupMs + " ms")
    } else {
        Add-Fail "serve.start-normal" "serve normal startup" `
            ("health status=" + $normal.HealthStatus + " error=" + (Format-Snippet $normal.HealthError 200)) `
            (Format-Snippet (Read-Utf8Text $normal.Child.ErrFile) 600)
    }

    if ($normal.Ready) {
        $health = Get-HttpResult -Url $healthUrl
        $healthJson = ConvertFrom-JsonText $health.Body
        $healthOk = ($health.Status -eq 200) -and
            ($null -ne (Get-JsonValue $healthJson "status")) -and
            ((Get-JsonValue $healthJson "status") -eq "ok")
        if ($healthOk) {
            Add-Pass "http.healthz" "GET /healthz returns 200 with status ok" (Format-Snippet $health.Body 200)
        } else {
            Add-Fail "http.healthz" "GET /healthz" ("status=" + $health.Status) (Format-Snippet $health.Body 300)
        }

        $openapi = Get-HttpResult -Url ($serverBaseUrl + "/openapi.json")
        $openapiJson = ConvertFrom-JsonText $openapi.Body
        $openapiOk = ($openapi.Status -eq 200) -and ($null -ne (Get-JsonValue $openapiJson "openapi")) -and
            ($null -ne (Get-JsonValue $openapiJson "paths"))
        if ($openapiOk) {
            Add-Pass "http.openapi" "GET /openapi.json returns a minimal OpenAPI document" `
                ("openapi=" + (Get-JsonValue $openapiJson "openapi"))
        } else {
            Add-Fail "http.openapi" "GET /openapi.json" ("status=" + $openapi.Status) (Format-Snippet $openapi.Body 300)
        }

        $loginPage = Get-HttpResult -Url ($serverBaseUrl + "/login")
        if ($loginPage.Status -eq 200 -and $loginPage.Body.Length -gt 0) {
            Add-Pass "ui.login-page" "built-in login page is served" `
                ("status=200 bytes=" + $loginPage.Body.Length)
        } else {
            Add-Fail "ui.login-page" "GET /login" ("status=" + $loginPage.Status) (Format-Snippet $loginPage.Body 300)
        }

        $discoveryOff = Get-HttpResult -Url ($serverBaseUrl + "/.well-known/openid-configuration")
        $jwksOff = Get-HttpResult -Url ($serverBaseUrl + "/jwks")
        if ($discoveryOff.Status -eq 404 -and $jwksOff.Status -eq 404) {
            Add-Pass "protocol.disabled-404" "OAuth/OIDC endpoints return 404 when protocol is disabled" `
                "discovery=404 jwks=404"
        } else {
            Add-Fail "protocol.disabled-404" "protocol endpoints must be 404 when disabled" `
                ("discovery=" + $discoveryOff.Status + " jwks=" + $jwksOff.Status)
        }

        $adminOff = Get-HttpResult -Url ($serverBaseUrl + "/admin/v1/meta")
        if ($adminOff.Status -eq 404) {
            Add-Pass "admin-api.disabled-404" "admin JSON API returns 404 when not enabled" "status=404"
        } else {
            Add-Fail "admin-api.disabled-404" "admin JSON API must be 404 when disabled" `
                ("status=" + $adminOff.Status)
        }

        Assert-TimeBudget "cli local commands"
        $validate = Invoke-SyncChild -Exe $loginctlExe -Label "cli-config-validate" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 60000) `
            -Arguments @("config", "validate", "--config", $configPath, "--json")
        if ($validate.Exited -and $validate.ExitCode -eq 0) {
            Add-Pass "cli.config-validate" "loginctl config validate accepts the generated YAML" `
                (Format-Snippet $validate.StdOut 300)
        } else {
            Add-Fail "cli.config-validate" "loginctl config validate" ("exit=" + $validate.ExitCode) `
                (Format-Snippet ($validate.StdOut + " " + $validate.StdErr) 400)
        }

        $diagHealth = Invoke-SyncChild -Exe $loginctlExe -Label "cli-diag-health" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 60000) `
            -Arguments @("diag", "health", "--config", $configPath, "--state-dir", $maintenanceStateDir,
                "--keyring-file", $masterKeyFile, "--json")
        $diagJson = ConvertFrom-JsonText $diagHealth.StdOut
        $diagData = Get-JsonValue $diagJson "data"
        $diagStatus = Get-JsonValue $diagData "status"
        if ($diagHealth.Exited -and $diagHealth.ExitCode -eq 0 -and $diagStatus -eq "ok") {
            Add-Pass "cli.diag-health" "loginctl diag health reports ok against the real database and maintenance state" `
                (Format-Snippet $diagHealth.StdOut 300)
        } else {
            Add-Fail "cli.diag-health" "loginctl diag health" ("exit=" + $diagHealth.ExitCode + " status=" + $diagStatus) `
                (Format-Snippet ($diagHealth.StdOut + " " + $diagHealth.StdErr) 400)
        }

        # Second serve instance against the same database must be rejected.
        Assert-TimeBudget "second instance"
        $secondLog = Join-Path $logsDir "access-second.log"
        $secondArgs = @()
        $secondArgs += $serveCommonArgs
        $secondArgs += @("--access-log", $secondLog)
        $second = Start-TrackedChild -Exe $loginServerExe -Arguments $secondArgs -Label "serve-second"
        $secondExited = Wait-TrackedChild -Child $second -TimeoutMs (Get-RemainingMilliseconds -Cap 25000)
        $secondExitCode = $null
        if ($secondExited) { $secondExitCode = Get-TrackedChildExitCode $second } else { Stop-TrackedChild $second }
        $secondErr = Read-Utf8Text $second.ErrFile
        $firstStillHealthy = (Get-HttpResult -Url $healthUrl).Status -eq 200
        if ($secondExited -and $secondExitCode -eq 1 -and $firstStillHealthy) {
            Add-Pass "single-instance.rejected" "second login-server on the same SQLite database is rejected (exit 1)" `
                (Format-Snippet $secondErr 300)
        } else {
            Add-Fail "single-instance.rejected" "second serve must be rejected without disturbing the first" `
                ("exit=" + $secondExitCode + " firstHealthy=" + $firstStillHealthy) `
                (Format-Snippet $secondErr 400)
        }

        # Bounded graceful shutdown on Ctrl+Break.
        Assert-TimeBudget "graceful stop normal"
        $stopNormal = Stop-ServeInstance -Instance $normal -ShutdownTimeoutSeconds 5
        $portFree = Wait-PortFree -Port $port -TimeoutMs 10000
        if ($stopNormal.Exited -and $stopNormal.ExitCode -eq 0 -and $portFree) {
            Add-Pass "shutdown.ctrl-break-normal" "Ctrl+Break triggers bounded graceful shutdown (exit 0) and releases the port" `
                ("shutdown=" + $stopNormal.DurationMs + " ms; port released")
        } else {
            Add-Fail "shutdown.ctrl-break-normal" "Ctrl+Break graceful shutdown" `
                ("exited=" + $stopNormal.Exited + " exit=" + $stopNormal.ExitCode +
                    " duration=" + $stopNormal.DurationMs + "ms portFree=" + $portFree) `
                (Format-Snippet (Read-Utf8Text $normal.Child.ErrFile) 600)
        }

        # Access log evidence is read after shutdown because the rotating writer
        # flushes buffered records when the process closes the file.
        $accessText = Read-Utf8Text $accessLogNormal
        $accessSanitized = $true
        foreach ($secret in $script:secretValues) {
            if (-not [string]::IsNullOrEmpty($secret) -and $accessText.Contains($secret)) { $accessSanitized = $false }
        }
        if ((Test-Path -LiteralPath $accessLogNormal) -and $accessText.Length -gt 0 -and $accessSanitized) {
            Add-Pass "access-log.written" "file access log was written for real requests and contains no test secrets" `
                ("bytes=" + $accessText.Length)
        } else {
            Add-Fail "access-log.written" "file access log evidence" ("bytes=" + $accessText.Length) `
                "access log missing/empty or contained a test secret"
        }
    }

    # ------------------------------------------------------------ run B: protocol + admin API

    Write-Host ""
    Write-Host "phase: protocol endpoints and admin JSON API enabled"
    Assert-TimeBudget "serve protocol/admin"

    $protocolRun = Start-ServeInstance -Label "serve-protocol" -AccessLogPath $accessLogProtocol `
        -ExtraArguments $serveFeatureArgs
    if ($protocolRun.Ready) {
        Add-Pass "serve.start-protocol-admin" "serve starts with --enable-protocol --enable-admin-api" `
            ("pid=" + $protocolRun.Child.Pid + " startup=" + $protocolRun.StartupMs + " ms")
    } else {
        Add-Fail "serve.start-protocol-admin" "serve startup with protocol/admin API" `
            ("health status=" + $protocolRun.HealthStatus) (Format-Snippet (Read-Utf8Text $protocolRun.Child.ErrFile) 600)
    }

    if ($protocolRun.Ready) {
        $discovery = Get-HttpResult -Url ($serverBaseUrl + "/.well-known/openid-configuration")
        $discoveryJson = ConvertFrom-JsonText $discovery.Body
        $issuer = Get-JsonValue $discoveryJson "issuer"
        $jwksUri = Get-JsonValue $discoveryJson "jwks_uri"
        $authorizeEndpoint = Get-JsonValue $discoveryJson "authorization_endpoint"
        if ($discovery.Status -eq 200 -and $issuer -eq $serverBaseUrl -and
            $jwksUri -eq ($serverBaseUrl + "/jwks") -and
            $authorizeEndpoint -eq ($serverBaseUrl + "/oauth/authorize")) {
            Add-Pass "protocol.discovery" "OIDC discovery is served and issuer/endpoints match the running instance" `
                ("issuer=" + $issuer + " jwks_uri=" + $jwksUri)
        } else {
            Add-Fail "protocol.discovery" "OIDC discovery document" `
                ("status=" + $discovery.Status + " issuer=" + $issuer + " jwks_uri=" + $jwksUri) `
                (Format-Snippet $discovery.Body 500)
        }

        $jwks = Get-HttpResult -Url ($serverBaseUrl + "/jwks")
        $jwksJson = ConvertFrom-JsonText $jwks.Body
        $jwksKeysProperty = $null
        if ($null -ne $jwksJson) { $jwksKeysProperty = $jwksJson.PSObject.Properties["keys"] }
        $keyCount = 0
        if ($null -ne $jwksKeysProperty -and $null -ne $jwksKeysProperty.Value) {
            $keyCount = @($jwksKeysProperty.Value).Count
        }
        if ($jwks.Status -eq 200 -and $null -ne $jwksKeysProperty) {
            Add-Pass "protocol.jwks-reachable" "JWKS is served with a syntactically valid key set document" `
                ("status=200 keys=" + $keyCount)
        } else {
            Add-Fail "protocol.jwks-reachable" "JWKS endpoint" ("status=" + $jwks.Status) `
                (Format-Snippet $jwks.Body 300)
        }
        if ($keyCount -ge 1) {
            $firstKey = @($jwksKeysProperty.Value)[0]
            Add-Pass "protocol.jwks-signing-key" "JWKS publishes at least one signing key" `
                ("keys=" + $keyCount + " kty=" + (Get-JsonValue $firstKey "kty"))
        } else {
            Add-Fail "protocol.jwks-signing-key" "JWKS publishes a signing key for ID Token verification" `
                ("status=" + $jwks.Status + " keys=" + $keyCount) `
                ("Fresh instance publishes an empty key set: token signing keys are bootstrapped lazily at " +
                    "the first token issuance (internal/token ensureActiveKey), so OIDC clients cannot verify " +
                    "ID tokens before that. This is a product gap found by this smoke test, not a harness " +
                    "defect. body=" + (Format-Snippet $jwks.Body 200))
        }

        Assert-TimeBudget "loginte2e suites"
        $e2eDiscovery = Invoke-SyncChild -Exe $loginte2eExe -Label "loginte2e-discovery" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 90000) `
            -Arguments @("discovery", "--server", $serverBaseUrl, "--json")
        $e2eDiscoveryJson = ConvertFrom-JsonText $e2eDiscovery.StdOut
        $e2eDiscoverySummary = Get-JsonValue $e2eDiscoveryJson "summary"
        $e2eDiscoveryFail = Get-JsonValue $e2eDiscoverySummary "fail"
        $e2eDiscoveryPass = Get-JsonValue $e2eDiscoverySummary "pass"
        if ($e2eDiscovery.Exited -and $e2eDiscovery.ExitCode -eq 0 -and
            $null -ne $e2eDiscoveryFail -and [int]$e2eDiscoveryFail -eq 0 -and
            $null -ne $e2eDiscoveryPass -and [int]$e2eDiscoveryPass -ge 1) {
            Add-Pass "loginte2e.discovery" "loginte2e discovery suite passes against the real process" `
                ("pass=" + $e2eDiscoveryPass + " fail=" + $e2eDiscoveryFail + " exit=0")
        } else {
            $e2eDiscoveryFailedCases = Get-FailedCaseText $e2eDiscoveryJson
            Add-Fail "loginte2e.discovery" "loginte2e discovery suite" `
                ("exit=" + $e2eDiscovery.ExitCode + " pass=" + $e2eDiscoveryPass + " fail=" + $e2eDiscoveryFail +
                    " failed_cases=[" + $e2eDiscoveryFailedCases + "]") `
                (Format-Snippet ($e2eDiscovery.StdOut + " " + $e2eDiscovery.StdErr) 800)
        }

        $e2eJwks = Invoke-SyncChild -Exe $loginte2eExe -Label "loginte2e-jwks" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 90000) `
            -Arguments @("jwks", "--server", $serverBaseUrl, "--json")
        $e2eJwksJson = ConvertFrom-JsonText $e2eJwks.StdOut
        $e2eJwksSummary = Get-JsonValue $e2eJwksJson "summary"
        $e2eJwksFail = Get-JsonValue $e2eJwksSummary "fail"
        $e2eJwksPass = Get-JsonValue $e2eJwksSummary "pass"
        $e2eJwksSkip = Get-JsonValue $e2eJwksSummary "skip"
        if ($e2eJwks.Exited -and $e2eJwks.ExitCode -eq 0 -and
            $null -ne $e2eJwksFail -and [int]$e2eJwksFail -eq 0 -and
            $null -ne $e2eJwksPass -and [int]$e2eJwksPass -ge 1) {
            Add-Pass "loginte2e.jwks" "loginte2e JWKS suite passes; session-dependent cases are skipped as documented" `
                ("pass=" + $e2eJwksPass + " fail=" + $e2eJwksFail + " skip=" + $e2eJwksSkip + " exit=0")
        } else {
            $e2eJwksFailedCases = Get-FailedCaseText $e2eJwksJson
            Add-Fail "loginte2e.jwks" "loginte2e JWKS suite" `
                ("exit=" + $e2eJwks.ExitCode + " pass=" + $e2eJwksPass + " fail=" + $e2eJwksFail +
                    " failed_cases=[" + $e2eJwksFailedCases + "]") `
                (Format-Snippet ($e2eJwks.StdOut + " " + $e2eJwks.StdErr) 800)
        }

        $adminAnonymous = Get-HttpResult -Url ($serverBaseUrl + "/admin/v1/meta")
        $adminAnonymousJson = ConvertFrom-JsonText $adminAnonymous.Body
        $adminCode = Get-JsonValue $adminAnonymousJson "code"
        if ($adminAnonymous.Status -eq 401 -and $adminCode -eq "AUTH_FAILED") {
            Add-Pass "admin-api.anonymous-401" "admin JSON API rejects anonymous requests with 401 AUTH_FAILED" `
                (Format-Snippet $adminAnonymous.Body 200)
        } else {
            Add-Fail "admin-api.anonymous-401" "admin JSON API anonymous rejection" `
                ("status=" + $adminAnonymous.Status + " code=" + $adminCode) `
                (Format-Snippet $adminAnonymous.Body 300)
        }

        # CLI online command exit codes.
        Assert-TimeBudget "cli online"
        $fakeSessionFile = Join-Path $secretsDir "fake-session.txt"
        $fakeSessionSecret = New-TestPassword
        $script:secretValues.Add($fakeSessionSecret) | Out-Null
        [System.IO.File]::WriteAllText($fakeSessionFile, $fakeSessionSecret, $encoding)
        Set-ProtectedFileAcl -Path $fakeSessionFile

        $unprotectedSessionFile = Join-Path $secretsDir "fake-session-unprotected.txt"
        [System.IO.File]::WriteAllText($unprotectedSessionFile, $fakeSessionSecret, $encoding)
        Set-UnprotectedFileAcl -Path $unprotectedSessionFile

        $cliNoSession = Invoke-SyncChild -Exe $loginctlExe -Label "cli-online-no-session" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 60000) `
            -Arguments @("tasks", "get", "task_absent", "--server", $serverBaseUrl)
        if ($cliNoSession.Exited -and $cliNoSession.ExitCode -eq 2) {
            Add-Pass "cli.online-missing-session" "online CLI without --session-file exits 2 (usage; stable, documented)" `
                ("exit=2; " + (Format-Snippet ($cliNoSession.StdOut + " " + $cliNoSession.StdErr) 240))
        } else {
            Add-Fail "cli.online-missing-session" "online CLI missing --session-file" `
                ("exit=" + $cliNoSession.ExitCode) `
                (Format-Snippet ($cliNoSession.StdOut + " " + $cliNoSession.StdErr) 400)
        }

        $cliUnprotected = Invoke-SyncChild -Exe $loginctlExe -Label "cli-online-unprotected" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 60000) `
            -Arguments @("tasks", "get", "task_absent", "--server", $serverBaseUrl,
                "--session-file", $unprotectedSessionFile)
        if ($cliUnprotected.Exited -and $cliUnprotected.ExitCode -eq 4) {
            Add-Pass "cli.online-invalid-session-file" "online CLI rejects an unprotected session file with exit 4" `
                ("exit=4; " + (Format-Snippet ($cliUnprotected.StdOut + " " + $cliUnprotected.StdErr) 240))
        } else {
            Add-Fail "cli.online-invalid-session-file" "online CLI invalid protected session file" `
                ("exit=" + $cliUnprotected.ExitCode) `
                (Format-Snippet ($cliUnprotected.StdOut + " " + $cliUnprotected.StdErr) 400)
        }

        $cliFake = Invoke-SyncChild -Exe $loginctlExe -Label "cli-online-fake-session" `
            -TimeoutMs (Get-RemainingMilliseconds -Cap 60000) `
            -Arguments @("tasks", "get", "task_absent", "--server", $serverBaseUrl,
                "--session-file", $fakeSessionFile)
        if ($cliFake.Exited -and $cliFake.ExitCode -eq 4) {
            Add-Pass "cli.online-fake-session" "online CLI rejects a protected but invalid session secret with exit 4" `
                ("exit=4; " + (Format-Snippet ($cliFake.StdOut + " " + $cliFake.StdErr) 240))
        } else {
            Add-Fail "cli.online-fake-session" "online CLI fake session secret" `
                ("exit=" + $cliFake.ExitCode) `
                (Format-Snippet ($cliFake.StdOut + " " + $cliFake.StdErr) 400)
        }

        Assert-TimeBudget "graceful stop protocol run"
        $stopProtocol = Stop-ServeInstance -Instance $protocolRun -ShutdownTimeoutSeconds 5
        $portFree = Wait-PortFree -Port $port -TimeoutMs 10000
        if ($stopProtocol.Exited -and $stopProtocol.ExitCode -eq 0 -and $portFree) {
            Add-Pass "shutdown.ctrl-break-protocol" "Ctrl+Break graceful shutdown works with protocol/admin mounted" `
                ("shutdown=" + $stopProtocol.DurationMs + " ms; port released")
        } else {
            Add-Fail "shutdown.ctrl-break-protocol" "graceful shutdown with protocol/admin mounted" `
                ("exited=" + $stopProtocol.Exited + " exit=" + $stopProtocol.ExitCode +
                    " duration=" + $stopProtocol.DurationMs + "ms portFree=" + $portFree) `
                (Format-Snippet (Read-Utf8Text $protocolRun.Child.ErrFile) 600)
        }

        $accessProtocolText = Read-Utf8Text $accessLogProtocol
        if ((Test-Path -LiteralPath $accessLogProtocol) -and $accessProtocolText.Length -gt 0) {
            Add-Pass "access-log.protocol-run" "file access log was written for the protocol/admin run" `
                ("bytes=" + $accessProtocolText.Length)
        } else {
            Add-Fail "access-log.protocol-run" "access log for protocol/admin run" ("bytes=" + $accessProtocolText.Length)
        }
    }

    # ------------------------------------------------------------ maintenance run

    # Safety: never switch to maintenance while a serve instance is still alive.
    foreach ($child in $script:children.ToArray()) {
        if (-not $child.Reaped) { Stop-TrackedChild -Child $child -TimeoutMs 5000 }
    }

    Write-Host ""
    Write-Host "phase: maintenance mode"
    Assert-TimeBudget "maintenance enter"

    $maintenanceEnter = Invoke-SyncChild -Exe $loginctlExe -Label "maintenance-enter" `
        -TimeoutMs (Get-RemainingMilliseconds -Cap 90000) `
        -Arguments @("maintenance-enter", "--database", $databasePath, "--state-dir", $maintenanceStateDir,
            "--key-file", $masterKeyFile, "--operator", $operatorId, "--reason",
            "e2e smoke: verify maintenance 503 responses")
    if ($maintenanceEnter.Exited -and $maintenanceEnter.ExitCode -eq 0) {
        Add-Pass "maintenance.enter" "loginctl maintenance-enter switches the instance to maintenance" `
            (Format-Snippet $maintenanceEnter.StdOut 300)
    } else {
        Add-Fail "maintenance.enter" "loginctl maintenance-enter" ("exit=" + $maintenanceEnter.ExitCode) `
            (Format-Snippet ($maintenanceEnter.StdOut + " " + $maintenanceEnter.StdErr) 500)
    }

    $maintenanceRun = Start-ServeInstance -Label "serve-maintenance" -AccessLogPath $accessLogMaintenance `
        -ExtraArguments $serveFeatureArgs
    if ($maintenanceRun.Ready) {
        Add-Pass "serve.start-maintenance" "serve starts in maintenance mode and answers /healthz" `
            ("pid=" + $maintenanceRun.Child.Pid + " startup=" + $maintenanceRun.StartupMs + " ms")
    } else {
        Add-Fail "serve.start-maintenance" "serve maintenance startup" `
            ("health status=" + $maintenanceRun.HealthStatus) `
            (Format-Snippet (Read-Utf8Text $maintenanceRun.Child.ErrFile) 600)
    }

    if ($maintenanceRun.Ready) {
        $maintenanceHealth = Get-HttpResult -Url $healthUrl
        $maintenanceHealthJson = ConvertFrom-JsonText $maintenanceHealth.Body
        if ($maintenanceHealth.Status -eq 200 -and (Get-JsonValue $maintenanceHealthJson "mode") -eq "maintenance") {
            Add-Pass "maintenance.healthz" "maintenance /healthz returns 200 with mode=maintenance" `
                (Format-Snippet $maintenanceHealth.Body 200)
        } else {
            Add-Fail "maintenance.healthz" "maintenance /healthz" ("status=" + $maintenanceHealth.Status) `
                (Format-Snippet $maintenanceHealth.Body 300)
        }

        $maintenanceLogin = Get-HttpResult -Url ($serverBaseUrl + "/login")
        if ($maintenanceLogin.Status -eq 503) {
            Add-Pass "maintenance.login-503" "business pages return 503 in maintenance mode" "status=503"
        } else {
            Add-Fail "maintenance.login-503" "maintenance /login" ("status=" + $maintenanceLogin.Status)
        }

        $maintenanceDiscovery = Get-HttpResult -Url ($serverBaseUrl + "/.well-known/openid-configuration")
        if ($maintenanceDiscovery.Status -eq 503) {
            Add-Pass "maintenance.protocol-503" "protocol endpoints return 503 in maintenance mode" "status=503"
        } else {
            Add-Fail "maintenance.protocol-503" "maintenance discovery" ("status=" + $maintenanceDiscovery.Status)
        }

        $maintenanceAdmin = Get-HttpResult -Url ($serverBaseUrl + "/admin/v1/meta")
        if ($maintenanceAdmin.Status -eq 503) {
            Add-Pass "maintenance.admin-api-503" "admin JSON API returns 503 in maintenance mode" "status=503"
        } else {
            Add-Fail "maintenance.admin-api-503" "maintenance admin API" ("status=" + $maintenanceAdmin.Status)
        }

        Assert-TimeBudget "graceful stop maintenance"
        $stopMaintenance = Stop-ServeInstance -Instance $maintenanceRun -ShutdownTimeoutSeconds 5
        $portFree = Wait-PortFree -Port $port -TimeoutMs 10000
        if ($stopMaintenance.Exited -and $stopMaintenance.ExitCode -eq 0 -and $portFree) {
            Add-Pass "shutdown.ctrl-break-maintenance" "maintenance instance shuts down gracefully within the bound" `
                ("shutdown=" + $stopMaintenance.DurationMs + " ms; port released")
        } else {
            Add-Fail "shutdown.ctrl-break-maintenance" "graceful shutdown in maintenance mode" `
                ("exited=" + $stopMaintenance.Exited + " exit=" + $stopMaintenance.ExitCode +
                    " duration=" + $stopMaintenance.DurationMs + "ms portFree=" + $portFree)
        }
    }

    Assert-TimeBudget "maintenance exit"
    $maintenanceExit = Invoke-SyncChild -Exe $loginctlExe -Label "maintenance-exit" `
        -TimeoutMs (Get-RemainingMilliseconds -Cap 90000) `
        -Arguments @("maintenance-exit", "--database", $databasePath, "--state-dir", $maintenanceStateDir,
            "--key-file", $masterKeyFile, "--operator", $operatorId, "--reason",
            "e2e smoke: maintenance verification finished")
    if ($maintenanceExit.Exited -and $maintenanceExit.ExitCode -eq 0) {
        Add-Pass "maintenance.exit" "loginctl maintenance-exit restores normal state" `
            (Format-Snippet $maintenanceExit.StdOut 300)
    } else {
        Add-Fail "maintenance.exit" "loginctl maintenance-exit" ("exit=" + $maintenanceExit.ExitCode) `
            (Format-Snippet ($maintenanceExit.StdOut + " " + $maintenanceExit.StdErr) 500)
    }

    $diagReady = Invoke-SyncChild -Exe $loginctlExe -Label "cli-diag-ready" `
        -TimeoutMs (Get-RemainingMilliseconds -Cap 60000) `
        -Arguments @("diag", "ready", "--config", $configPath, "--state-dir", $maintenanceStateDir,
            "--keyring-file", $masterKeyFile, "--json")
    $diagReadyJson = ConvertFrom-JsonText $diagReady.StdOut
    $diagReadyData = Get-JsonValue $diagReadyJson "data"
    $diagReadyStatus = Get-JsonValue $diagReadyData "status"
    if ($diagReady.Exited -and $diagReady.ExitCode -eq 0 -and $diagReadyStatus -eq "ok") {
        Add-Pass "maintenance.ready-after-exit" "loginctl diag ready reports ok after maintenance exit" `
            (Format-Snippet $diagReady.StdOut 300)
    } else {
        Add-Fail "maintenance.ready-after-exit" "diag ready after maintenance exit" `
            ("exit=" + $diagReady.ExitCode + " status=" + $diagReadyStatus) `
            (Format-Snippet ($diagReady.StdOut + " " + $diagReady.StdErr) 500)
    }

    # ------------------------------------------------------------ run F: normal again

    Write-Host ""
    Write-Host "phase: normal serve after maintenance"
    Assert-TimeBudget "serve final"

    $finalRun = Start-ServeInstance -Label "serve-final" -AccessLogPath $accessLogFinal `
        -ExtraArguments $serveFeatureArgs
    if ($finalRun.Ready) {
        Add-Pass "serve.start-after-maintenance" "serve starts normally again after maintenance exit" `
            ("pid=" + $finalRun.Child.Pid + " startup=" + $finalRun.StartupMs + " ms")
    } else {
        Add-Fail "serve.start-after-maintenance" "serve startup after maintenance exit" `
            ("health status=" + $finalRun.HealthStatus) `
            (Format-Snippet (Read-Utf8Text $finalRun.Child.ErrFile) 600)
    }

    if ($finalRun.Ready) {
        $finalDiscovery = Get-HttpResult -Url ($serverBaseUrl + "/.well-known/openid-configuration")
        $finalAdmin = Get-HttpResult -Url ($serverBaseUrl + "/admin/v1/meta")
        if ($finalDiscovery.Status -eq 200 -and $finalAdmin.Status -eq 401) {
            Add-Pass "serve.post-maintenance-endpoints" "protocol 200 and admin 401 confirm normal (non-maintenance) assembly" `
                ("discovery=" + $finalDiscovery.Status + " admin=" + $finalAdmin.Status)
        } else {
            Add-Fail "serve.post-maintenance-endpoints" "post-maintenance endpoints" `
                ("discovery=" + $finalDiscovery.Status + " admin=" + $finalAdmin.Status)
        }

        Assert-TimeBudget "graceful stop final"
        $stopFinal = Stop-ServeInstance -Instance $finalRun -ShutdownTimeoutSeconds 5
        $portFree = Wait-PortFree -Port $port -TimeoutMs 10000
        if ($stopFinal.Exited -and $stopFinal.ExitCode -eq 0 -and $portFree) {
            Add-Pass "shutdown.ctrl-break-final" "final instance shuts down gracefully and releases the port" `
                ("shutdown=" + $stopFinal.DurationMs + " ms; port released")
        } else {
            Add-Fail "shutdown.ctrl-break-final" "final graceful shutdown" `
                ("exited=" + $stopFinal.Exited + " exit=" + $stopFinal.ExitCode +
                    " duration=" + $stopFinal.DurationMs + "ms portFree=" + $portFree)
        }
    }

    # ------------------------------------------------------------ limitations

    Add-NotTested "admin-api.strong-auth-session" `
        "admin JSON API with a real strong-authenticated management session" `
        "Requires a Passkey/MFA strong-auth session on root; not obtainable non-interactively. Anonymous/disabled/maintenance paths are verified."
    Add-NotTested "protocol.authcode-token-device-qr" `
        "OAuth/OIDC authcode, token, device and QR login suites" `
        "Require a registered OAuth client and a real browser session cookie; this build exposes no unattended client registration path."
    Add-NotTested "tls.mtls-and-proxy" `
        "TLS/mTLS and trusted reverse proxy behavior" `
        "Out of scope for a loopback plain HTTP smoke test; TLS is disabled in the generated configuration."
    Add-NotTested "notifications.external-delivery" `
        "real email/webhook delivery" `
        "Product design keeps email delivery locally disabled; the test never sends external notifications."
    Add-NotTested "shutdown.sigterm-ctrl-close" `
        "CTRL_CLOSE/SIGTERM delivery on Windows" `
        "Ctrl+Break is delivered as os.Interrupt (same signal context); a CTRL_CLOSE would terminate the harness console and is not attempted."

    # ------------------------------------------------------------ final hygiene

    Write-Host ""
    Write-Host "phase: hygiene"

    $liveChildren = @($script:children | Where-Object { -not $_.Reaped })
    foreach ($child in $liveChildren) {
        Stop-TrackedChild $child
    }
    $liveChildren = @($script:children | Where-Object { -not $_.Reaped })
    if ($liveChildren.Count -eq 0) {
        Add-Pass "hygiene.no-child-processes" "no spawned process was left running" `
            ("tracked=" + $script:children.Count)
    } else {
        Add-Fail "hygiene.no-child-processes" "spawned process cleanup" `
            (($liveChildren | ForEach-Object { $_.Label + "=" + $_.Pid }) -join ", ")
    }

    if (Wait-PortFree -Port $port -TimeoutMs 10000) {
        Add-Pass "hygiene.port-released" "the loopback test port is released" ("port=" + $port)
    } else {
        Add-Fail "hygiene.port-released" "test port release" ("port=" + $port + " still bound")
    }

    $repoDatabaseChanged = $false
    $repoDatabaseExistsNow = Test-Path -LiteralPath $repoDatabase
    if ($repoDatabaseExisted -ne $repoDatabaseExistsNow) {
        $repoDatabaseChanged = $true
    } elseif ($repoDatabaseExistsNow) {
        $repoDatabaseHashAfter = (Get-FileHash -LiteralPath $repoDatabase -Algorithm SHA256).Hash
        if ($repoDatabaseHashAfter -ne $repoDatabaseHashBefore) { $repoDatabaseChanged = $true }
    }
    if (-not $repoDatabaseChanged) {
        Add-Pass "repo.database-untouched" "repository database/login.db was neither created nor modified" `
            ("existed=" + $repoDatabaseExisted)
    } else {
        Add-Fail "repo.database-untouched" "repository database must not be touched" `
            ("existedBefore=" + $repoDatabaseExisted + " existsNow=" + $repoDatabaseExistsNow)
    }

    # No test secret may appear in any captured output file.
    $leakedFiles = New-Object System.Collections.Generic.List[string]
    $capturedFiles = @(Get-ChildItem -LiteralPath $logsDir -File -ErrorAction SilentlyContinue)
    foreach ($file in $capturedFiles) {
        $content = Read-Utf8Text $file.FullName
        foreach ($secret in $script:secretValues) {
            if (-not [string]::IsNullOrEmpty($secret) -and $content.Contains($secret)) {
                $leakedFiles.Add($file.Name) | Out-Null
            }
        }
    }
    if ($leakedFiles.Count -eq 0) {
        Add-Pass "hygiene.no-secret-in-captured-output" "captured process output contains no password or test session secret" `
            ("scanned=" + $capturedFiles.Count + " files")
    } else {
        Add-Fail "hygiene.no-secret-in-captured-output" "secret leakage in captured output" `
            (($leakedFiles | Select-Object -First 5) -join ", ")
    }
} catch {
    $script:abortReason = $_.Exception.Message
    Add-Fail "harness.aborted" "harness aborted before completing the matrix" "" (Format-Snippet $_.Exception.Message 600)
} finally {
    # Always try to clean up any process that is still alive.
    foreach ($child in $script:children.ToArray()) {
        try {
            if (-not $child.Reaped) { Stop-TrackedChild -Child $child -TimeoutMs 5000 }
        } catch {
            # Best effort cleanup only.
        }
    }
    try {
        $resultPath = Join-Path $script:workRoot "result.json"
        if (Test-Path -LiteralPath $script:workRoot) {
            Write-ResultJson -Path $resultPath -Completed ([string]::IsNullOrEmpty($script:abortReason))
        }
    } catch {
        Write-Host ("warning: failed to write result.json: " + $_.Exception.Message) -ForegroundColor DarkYellow
        Write-Host ("  stack: " + $_.ScriptStackTrace) -ForegroundColor DarkYellow
        try {
            $fallback = '{"tool":"e2e-login-server","result_version":1,"write_error":' +
                (ConvertTo-Json ($_.Exception.Message)) + '}'
            [System.IO.File]::WriteAllText((Join-Path $script:workRoot "result.error.json"), $fallback,
                (New-Object System.Text.UTF8Encoding($false)))
        } catch {
            # Nothing more can be reported here.
        }
    }
    if ($null -ne $script:httpClient) {
        try { $script:httpClient.Dispose() } catch { }
    }
}

$failed = $script:failCount -gt 0
if ($failed -or $KeepArtifacts) {
    $keepRoot = $script:workRoot
} else {
    $keepRoot = $null
}

Write-Host ""
Write-Host ("=" * 72)
Write-Host ("e2e-login-server summary: PASS=" + $script:passCount + " FAIL=" + $script:failCount +
    " NOT_TESTED=" + $script:notTestedCount)
if ($failed) {
    Write-Host "FAILED checks:" -ForegroundColor Red
    foreach ($check in @($script:checks | Where-Object { $_.status -eq "FAIL" })) {
        Write-Host ("  - " + $check.id + ": " + $check.name) -ForegroundColor Red
    }
}
if ($script:notTestedCount -gt 0) {
    Write-Host "NOT_TESTED (documented limitations):"
    foreach ($check in @($script:checks | Where-Object { $_.status -eq "NOT_TESTED" })) {
        Write-Host ("  - " + $check.id + ": " + $check.name)
    }
}
if ($null -ne $keepRoot) {
    Write-Host ("artifacts kept: " + $keepRoot)
    Write-Host ("  structured result: " + (Join-Path $keepRoot "result.json"))
    Write-Host "  (remove this directory manually when no longer needed)"
} else {
    try {
        if (Test-Path -LiteralPath $script:workRoot) {
            Remove-Item -LiteralPath $script:workRoot -Recurse -Force -ErrorAction Stop
            Write-Host "temporary work directory removed (use -KeepArtifacts to keep it)"
        }
    } catch {
        Write-Host ("warning: could not remove temporary work directory " + $script:workRoot +
            ": " + $_.Exception.Message) -ForegroundColor DarkYellow
    }
}
Write-Host ("=" * 72)

if ($failed) { exit 1 }
exit 0
