# r12-300-acceptance.ps1
#
# Step 300 merged acceptance runner (skeleton / orchestration only).
#
# Purpose
#   Serial, evidence-producing run of the old 274 security matrix, old 275
#   integration regression (phase 2 docs/capability checks), local-maintenance
#   boundary comparison, key old-fix regressions, CUI smoke, and one full
#   `go test ./...` pass. The script itself does NOT modify product code; the
#   only optional write to tracked files is `-RegenerateCapabilities` which is
#   off by default and must be approved by the Lead.
#
# Rules
#   - Heavy commands run serially; this script acquires the shared heavy-lock
#     itself unless -NoLock is passed (Lead coordinates the window).
#   - Machine-readable JSON is written to -OutPath. No Git add/commit/push.
#   - The script never deletes repository files. Work artifacts stay under
#     -WorkRoot for evidence collection.
#   - Default mode runs the full suite. -SkipFull / -DryRun are for rehearsal
#     and mark the summary as incomplete (complete=false).
#
# Usage (EvernightLogin root):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/r12-300-acceptance.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/r12-300-acceptance.ps1 -DryRun
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/r12-300-acceptance.ps1 `
#       -WorkRoot P:/go/tmp/r12-300 -OutPath P:/go/tmp/r12-300/summary.json
#
# Exit codes: 0 = all executed suites passed; 1 = at least one failure;
#             2 = invocation/guard failure; 3 = incomplete run (e.g. -SkipFull).

[CmdletBinding()]
param(
    [string]$OutPath = '',
    [string]$WorkRoot = 'P:/go/tmp/r12-300',
    [string]$EvidenceDir = 'docs/acceptance/evidence/step300',
    [int]$FullTestTimeoutSeconds = 3600,
    [int]$SuiteTimeoutSeconds = 900,
    [int]$LockTimeoutSec = 10800,
    [string]$HeavyLockOwner = 'r12-300-acceptance',
    [switch]$NoLock,
    [switch]$DryRun,
    [switch]$SkipFull,
    [switch]$RegenerateCapabilities
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$lockScript = Join-Path $root '.ai/lead/tools/heavy-lock.ps1'
$script:startedAt = Get-Date
$script:results = New-Object System.Collections.ArrayList
$script:lockAcquired = $false
$script:criticalFailed = $false
$script:incomplete = $false

function Get-ShortTail {
    param([object[]]$Lines, [int]$Count = 40)
    if ($null -eq $Lines) { return '' }
    $text = ($Lines | Select-Object -Last $Count | Out-String -Width 500).Trim()
    if ($text.Length -gt 6000) { $text = $text.Substring($text.Length - 6000) }
    return $text
}

function Add-SuiteResult {
    param(
        [string]$Name,
        [string]$Status,
        [string]$Command,
        [int]$ExitCode,
        [double]$DurationSeconds,
        [string]$Tail,
        [string]$LogPath = ''
    )
    [void]$script:results.Add([pscustomobject]@{
        name             = $Name
        status           = $Status
        command          = $Command
        exit_code        = $ExitCode
        duration_seconds = [math]::Round($DurationSeconds, 3)
        log_path         = $LogPath
        tail             = $Tail
    })
}

function Test-CommandExists {
    param([string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    return ($null -ne $command)
}

function Invoke-Suite {
    param(
        [string]$Name,
        [string]$CommandText,
        [scriptblock]$Block,
        [switch]$Critical,
        [switch]$Optional,
        [string]$LogPath = ''
    )
    if ($script:criticalFailed) {
        Add-SuiteResult -Name $Name -Status 'not_run' -Command $CommandText `
            -ExitCode -1 -DurationSeconds 0 -Tail 'skipped after critical failure'
        return
    }
    if ($Optional) {
        Add-SuiteResult -Name $Name -Status 'not_required' -Command $CommandText `
            -ExitCode -1 -DurationSeconds 0 -Tail 'optional suite not enabled'
        return
    }
    if ($DryRun) {
        Write-Host ("[dry-run] {0} :: {1}" -f $Name, $CommandText)
        Add-SuiteResult -Name $Name -Status 'planned' -Command $CommandText `
            -ExitCode 0 -DurationSeconds 0 -Tail 'dry-run' -LogPath $LogPath
        return
    }
    Write-Host ''
    Write-Host ("== {0} ==" -f $Name)
    Write-Host ("   {0}" -f $CommandText)
    if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
        Write-Host ("   full log: {0}" -f $LogPath)
    }
    $global:LASTEXITCODE = 0
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $output = $null
    $failure = $null
    try {
        $output = & $Block 2>&1
    } catch {
        $failure = $_
        $output = @($_ | Out-String)
    }
    $stopwatch.Stop()
    $exitCode = $global:LASTEXITCODE
    if ($null -eq $exitCode) { $exitCode = 0 }
    if ($null -ne $failure) { $exitCode = 1 }
    $status = 'pass'
    if ($exitCode -ne 0) { $status = 'fail' }
    $tail = Get-ShortTail -Lines $output
    Add-SuiteResult -Name $Name -Status $status -Command $CommandText `
        -ExitCode $exitCode -DurationSeconds $stopwatch.Elapsed.TotalSeconds `
        -Tail $tail -LogPath $LogPath
    if ($exitCode -ne 0) {
        Write-Host ("   FAIL exit={0} duration={1:N1}s" -f $exitCode, $stopwatch.Elapsed.TotalSeconds)
        if ($Critical) { $script:criticalFailed = $true }
    } else {
        Write-Host ("   PASS duration={0:N1}s" -f $stopwatch.Elapsed.TotalSeconds)
    }
}

function Invoke-HeavyLock {
    param([ValidateSet('acquire', 'release')][string]$Action)
    if ($DryRun -or $NoLock) { return }
    if (-not (Test-Path $lockScript)) {
        throw "heavy-lock script missing: $lockScript"
    }
    & powershell -NoProfile -ExecutionPolicy Bypass -File $lockScript $Action `
        -Owner $HeavyLockOwner -TimeoutSec $LockTimeoutSec
    if ($LASTEXITCODE -ne 0) {
        throw "heavy-lock $Action failed (exit=$LASTEXITCODE)"
    }
    if ($Action -eq 'acquire') { $script:lockAcquired = $true } else { $script:lockAcquired = $false }
}

# ---------------------------------------------------------------------------
# Suite blocks
# ---------------------------------------------------------------------------

$buildBlock = {
    $env:CGO_ENABLED = '0'
    go build ./...
}
$vetBlock = {
    $env:CGO_ENABLED = '0'
    go vet ./...
}
$gofmtBlock = {
    $files = @(git ls-files '*.go')
    if ($files.Count -eq 0) { throw 'no tracked Go files' }
    $bad = @()
    for ($start = 0; $start -lt $files.Count; $start += 200) {
        $end = [Math]::Min($start + 199, $files.Count - 1)
        $chunk = $files[$start..$end]
        $out = @(& gofmt -l $chunk 2>&1)
        foreach ($item in $out) {
            if (-not [string]::IsNullOrWhiteSpace($item)) { $bad += $item }
        }
    }
    if ($bad.Count -gt 0) {
        Write-Output ('gofmt violations:')
        $bad | Sort-Object | ForEach-Object { Write-Output $_ }
        throw 'gofmt violations found'
    }
    Write-Output 'gofmt: clean'
}
$matrix274Block = {
    $script = Join-Path $root 'scripts/r11-274-regression.ps1'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $script
    if ($LASTEXITCODE -ne 0) {
        throw ("r11-274-regression failed (exit=$LASTEXITCODE)")
    }
}
$phase275Block = {
    $env:CGO_ENABLED = '0'
    $out = Join-Path $WorkRoot 'step275-phase2.json'
    go run ./scripts/step275regression -phase2 -timeout 20m -out $out
}
$referenceBlock = {
    $env:CGO_ENABLED = '0'
    go run ./scripts/reference -check
}
$verifyDocsBlock = {
    $env:CGO_ENABLED = '0'
    go run ./scripts/verify-docs -reference require
}
$capabilitiesCheckBlock = {
    $env:CGO_ENABLED = '0'
    go run ./scripts/capabilities -check
}
$capabilitiesRegenBlock = {
    $env:CGO_ENABLED = '0'
    go run ./scripts/capabilities -strict
}
$remoteBoundaryBlock = {
    $env:CGO_ENABLED = '0'
    go test -p 1 -count=1 -timeout "${SuiteTimeoutSeconds}s" ./app/ `
        -run 'TestDirect|TestManagement|TestRoot|TestLoginRoot|TestAccess|TestSession'
}
$localMaintenanceBlock = {
    $env:CGO_ENABLED = '0'
    go test -p 1 -count=1 -timeout "${SuiteTimeoutSeconds}s" ./internal/setupconsole/ `
        -run 'TestWS3|TestLocalRuntime|TestRegistration|TestMaintenance|TestDetect|TestSaveConfigDraft|TestFieldsScreen'
}
$domainNarrowBlock = {
    $env:CGO_ENABLED = '0'
    go test -p 1 -count=1 -timeout "${SuiteTimeoutSeconds}s" `
        ./internal/authn/ ./internal/mfa/ ./internal/passkey/ ./internal/recovery/ `
        ./internal/session/ ./internal/profile/ ./internal/totp/ ./internal/oauthclient/ `
        ./internal/auditops/ ./internal/reports/ -run 'TestLocalMaintenance'
}
$oldFixBlock = {
    $env:CGO_ENABLED = '0'
    go test -p 1 -count=1 -timeout "${SuiteTimeoutSeconds}s" `
        ./internal/passwordreset/ ./internal/emailchange/ ./migrations/
}
$cuiSmokeBlock = {
    $env:CGO_ENABLED = '0'
    $instanceDir = Join-Path $WorkRoot 'cui-empty-instance'
    if (Test-Path $instanceDir) { Remove-Item -Recurse -Force $instanceDir }
    New-Item -ItemType Directory -Force $instanceDir | Out-Null
    $binary = Join-Path $WorkRoot 'login-setup.exe'
    go build -o $binary ./cmd/login-setup/
    if ($LASTEXITCODE -ne 0) { throw ("login-setup build failed (exit=$LASTEXITCODE)") }
    $before = @(Get-ChildItem -Force $instanceDir | ForEach-Object Name)
    $inputText = "status`nquit`n"
    $output = $inputText | & $binary --config missing.yaml 2>&1
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Output $_ }
    if ($code -ne 0) { throw ("login-setup smoke failed (exit=$code)") }
    $after = @(Get-ChildItem -Force $instanceDir | ForEach-Object Name)
    if ($after.Count -ne $before.Count) {
        throw ("empty instance was modified: before=$($before -join ',') after=$($after -join ',')")
    }
    $text = ($output | Out-String)
    if ($text -notmatch '简化文本模式') {
        throw 'CUI smoke output missing simplified-mode marker'
    }
    Write-Output 'CUI smoke: exit 0, no files created'
}
$mailSearchBlock = {
    $submodule = Join-Path $root 'EvernightMail'
    if (-not (Test-Path (Join-Path $submodule 'go.mod'))) {
        throw 'EvernightMail submodule not initialized'
    }
    $treeLine = (git ls-tree HEAD EvernightMail)
    $treeParts = ($treeLine -split '\s+')
    if ($treeParts.Count -lt 3) {
        throw ("cannot read parent gitlink: $treeLine")
    }
    $parentPointer = $treeParts[2]
    $subHead = ((git -C $submodule rev-parse HEAD) | Out-String).Trim()
    Write-Output ("parent gitlink={0} submodule HEAD={1}" -f $parentPointer, $subHead)
    if ($subHead -ne $parentPointer) {
        throw 'submodule HEAD does not match parent gitlink'
    }
    $subDirty = @(git -C $submodule status --porcelain)
    if ($subDirty.Count -gt 0) {
        Write-Output ("submodule dirty entries: {0}" -f $subDirty.Count)
        $subDirty | Select-Object -First 20 | ForEach-Object { Write-Output $_ }
        throw 'EvernightMail submodule is dirty'
    }
    Push-Location $submodule
    try {
        $env:CGO_ENABLED = '0'
        go test -count=1 -p 1 -timeout "${SuiteTimeoutSeconds}s" `
            ./internal/index/ ./internal/users/ ./internal/adminapi/ ./internal/web/ `
            -run 'TestSearch|TestOldIndex|TestUsersConsoleSearch|TestRunMatchesConsoleSearch|TestRunsConsoleSearchLimitRejected|TestFilterQuery|TestPageQuery' -v
        if ($LASTEXITCODE -ne 0) {
            throw ("EvernightMail search/privacy tests failed (exit=$LASTEXITCODE)")
        }
    } finally {
        Pop-Location
    }
}
$fullTestBlock = {
    $env:CGO_ENABLED = '0'
    $logPath = $script:fullTestLogPath
    if ([string]::IsNullOrWhiteSpace($logPath)) {
        $logPath = Join-Path $WorkRoot 'full-go-test.log'
    }
    & go test ./... -count=1 -p 1 -timeout "${FullTestTimeoutSeconds}s" *> $logPath
    $code = $global:LASTEXITCODE
    if ($code -ne 0) {
        Write-Output 'full-go-test complete output (tail 120 lines; full log preserved):'
        Get-Content -Path $logPath -Tail 120 | ForEach-Object { Write-Output $_ }
    }
    Write-Output ("full log: {0}" -f $logPath)
    $global:LASTEXITCODE = $code
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not (Test-CommandExists 'go')) {
    Write-Error 'go toolchain not found in PATH'
    exit 2
}
if (-not $DryRun -and -not $NoLock) {
    try {
        Invoke-HeavyLock -Action 'acquire'
    } catch {
        Write-Error ("heavy-lock acquire failed: {0}" -f $_)
        exit 2
    }
}
try {
    New-Item -ItemType Directory -Force $WorkRoot | Out-Null
    if ([string]::IsNullOrWhiteSpace($OutPath)) {
        $OutPath = Join-Path $WorkRoot 'r12-300-acceptance.json'
    }
    # 全量测试完整日志：默认写入仓库内 docs/acceptance/evidence/step300（持久证据），
    # 目录不可写时回退到 WorkRoot；JSON 的 full-go-test 套件记录该路径。
    $runStamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $evidenceDir = $EvidenceDir
    if (-not [System.IO.Path]::IsPathRooted($evidenceDir)) {
        $evidenceDir = Join-Path $root $evidenceDir
    }
    try {
        New-Item -ItemType Directory -Force $evidenceDir | Out-Null
    } catch {
        Write-Warning ("evidence dir unavailable, fallback to WorkRoot: {0}" -f $evidenceDir)
        $evidenceDir = $WorkRoot
    }
    $script:fullTestLogPath = Join-Path $evidenceDir "full-go-test-run-$runStamp.log"
    Push-Location $root
    try {
        $head = (git rev-parse HEAD 2>$null)
        $dirty = @(git status --porcelain 2>$null)
        $goVersion = (go version 2>$null)

        # 1) Build / vet / format gates (build is critical).
        Invoke-Suite -Name 'build' -CommandText 'go build ./...' -Block $buildBlock -Critical
        Invoke-Suite -Name 'vet' -CommandText 'go vet ./...' -Block $vetBlock
        Invoke-Suite -Name 'gofmt' -CommandText "gofmt -l tracked Go files" -Block $gofmtBlock

        # 2) Old step 274 security matrix (includes CLI matrix after D-274-1 fix).
        Invoke-Suite -Name 'old274-security-matrix' `
            -CommandText 'scripts/r11-274-regression.ps1' -Block $matrix274Block

        # 3) Old step 275 integration regression + docs/reference/capabilities.
        Invoke-Suite -Name 'old275-phase2-regression' `
            -CommandText 'go run ./scripts/step275regression -phase2 -out <work>/step275-phase2.json' `
            -Block $phase275Block
        Invoke-Suite -Name 'docs-reference-check' `
            -CommandText 'go run ./scripts/reference -check' -Block $referenceBlock
        Invoke-Suite -Name 'verify-docs' `
            -CommandText 'go run ./scripts/verify-docs -reference require' -Block $verifyDocsBlock
        Invoke-Suite -Name 'capabilities-check' `
            -CommandText 'go run ./scripts/capabilities -check' -Block $capabilitiesCheckBlock
        if ($RegenerateCapabilities.IsPresent) {
            Invoke-Suite -Name 'capabilities-regenerate-strict' `
                -CommandText 'go run ./scripts/capabilities -strict (writes tracked docs)' `
                -Block $capabilitiesRegenBlock
        } else {
            Invoke-Suite -Name 'capabilities-regenerate-strict' `
                -CommandText 'go run ./scripts/capabilities -strict (approval required)' `
                -Block { } -Optional
        }

        # 4) Local-maintenance vs remote boundary comparison + domain narrow methods.
        Invoke-Suite -Name 'remote-boundary-app' `
            -CommandText 'go test ./app -run TestDirect|TestManagement|TestRoot|TestLoginRoot|TestAccess|TestSession' `
            -Block $remoteBoundaryBlock
        Invoke-Suite -Name 'local-maintenance-boundary' `
            -CommandText 'go test ./internal/setupconsole -run WS3|LocalRuntime|Registration|Maintenance|Detect|SaveConfigDraft|FieldsScreen' `
            -Block $localMaintenanceBlock
        Invoke-Suite -Name 'domain-narrow-methods' `
            -CommandText 'go test ./internal/{authn,mfa,passkey,recovery,session,profile,totp,oauthclient,auditops,reports} -run TestLocalMaintenance' `
            -Block $domainNarrowBlock

        # 5) Old-fix regressions + EvernightMail submodule search/privacy evidence.
        Invoke-Suite -Name 'old-fix-regressions' `
            -CommandText 'go test ./internal/passwordreset ./internal/emailchange ./migrations' `
            -Block $oldFixBlock
        Invoke-Suite -Name 'mail-submodule-search-privacy' `
            -CommandText 'EvernightMail@gitlink: go test ./internal/{index,users,adminapi,web} -run search/privacy' `
            -Block $mailSearchBlock

        # 6) Real login-setup CUI smoke (non-TTY, empty instance, no files created).
        Invoke-Suite -Name 'cui-smoke' `
            -CommandText 'build login-setup.exe + status/quit in empty instance dir' `
            -Block $cuiSmokeBlock

        # 7) Exactly one full test pass (unless rehearsal mode).
        if ($SkipFull.IsPresent) {
            $script:incomplete = $true
            Invoke-Suite -Name 'full-go-test' `
                -CommandText 'go test ./... -count=1 -p 1 -timeout <full>' `
                -Block { } -Optional
        } else {
            Invoke-Suite -Name 'full-go-test' `
                -CommandText 'go test ./... -count=1 -p 1 -timeout <full>' `
                -Block $fullTestBlock -LogPath $script:fullTestLogPath
        }
    } finally {
        Pop-Location
    }

    $finishedAt = Get-Date
    $passed = @($script:results | Where-Object { $_.status -eq 'pass' }).Count
    $failed = @($script:results | Where-Object { $_.status -eq 'fail' }).Count
    $notRun = @($script:results | Where-Object { $_.status -eq 'not_run' }).Count
    $complete = (-not $DryRun.IsPresent) -and (-not $SkipFull.IsPresent) -and ($failed -eq 0) -and ($notRun -eq 0)
    if ($SkipFull.IsPresent) { $complete = $false }
    $summary = [pscustomobject]@{
        schema          = 'evernight.step300.acceptance/v1'
        generated_at    = (Get-Date -Format o)
        repo_root       = $root
        head            = $head
        dirty_count     = $dirty.Count
        dirty_entries   = @($dirty | Select-Object -First 40)
        go_version      = $goVersion
        platform        = ('{0}/{1}' -f [System.Runtime.InteropServices.RuntimeInformation]::OSDescription, $env:PROCESSOR_ARCHITECTURE)
        work_root       = $WorkRoot
        dry_run         = $DryRun.IsPresent
        skip_full       = $SkipFull.IsPresent
        regenerate_caps = $RegenerateCapabilities.IsPresent
        heavy_lock      = @{owner = $HeavyLockOwner; acquired = $script:lockAcquired; no_lock = $NoLock.IsPresent}
        started_at      = $script:startedAt.ToString('o')
        finished_at     = $finishedAt.ToString('o')
        duration_seconds = [math]::Round(($finishedAt - $script:startedAt).TotalSeconds, 3)
        complete        = $complete
        counts          = @{passed = $passed; failed = $failed; not_run = $notRun; total = $script:results.Count}
        suites          = $script:results
    }
    $json = $summary | ConvertTo-Json -Depth 8
    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($OutPath, $json, $encoding)
    Write-Host ''
    Write-Host ("Step 300 acceptance summary: pass={0} fail={1} not_run={2} complete={3}" -f `
        $passed, $failed, $notRun, $complete)
    Write-Host ("JSON: {0}" -f $OutPath)

    if ($DryRun) { exit 0 }
    if ($failed -gt 0) { exit 1 }
    if ($script:incomplete) { exit 3 }
    exit 0
} finally {
    if ($script:lockAcquired) {
        try {
            & powershell -NoProfile -ExecutionPolicy Bypass -File $lockScript release -Owner $HeavyLockOwner
        } catch {
            Write-Warning ("heavy-lock release failed: {0}" -f $_)
        }
    }
}

