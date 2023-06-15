# Steps 159-163 acceptance matrix draft (parent Login).
# DRAFT ONLY. No destructive actions, no long-running process, no product changes.
# Default mode prints the per-step plan; -CheckPrereqs runs read-only checks;
# -Execute is intentionally refused until steps 157/158 and 138-156 are closed.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\acceptance\step159-163-matrix.ps1
#   powershell ... -Step 159,160
#   powershell ... -CheckPrereqs
#   powershell ... -JsonOut P:\go\tmp\step159-163-plan.json
#   powershell ... -Execute   # refused: exit 3

[CmdletBinding()]
param(
    [string[]]$Step = @("159", "160", "161", "162", "163"),
    [switch]$CheckPrereqs,
    [string]$JsonOut = "",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Execute) {
    Write-Host "DRAFT: execution is not implemented. Steps 159-163 remain blocked by step 157/158 and 138-156."
    exit 3
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$casesPath = Join-Path $PSScriptRoot "step159-163-cases.json"
if (-not (Test-Path -LiteralPath $casesPath -PathType Leaf)) {
    Write-Error ("missing matrix data: " + $casesPath)
    exit 2
}
$data = Get-Content -LiteralPath $casesPath -Raw -Encoding UTF8 | ConvertFrom-Json

Write-Host "Steps 159-163 acceptance matrix draft (PREP_ONLY, no execution)"
Write-Host ("repo: " + $repo)
Write-Host ("steps: " + ($Step -join ","))
Write-Host ""

foreach ($number in $Step) {
    $stepKey = $number.ToString()
    if ($null -eq $data.steps.$stepKey) {
        Write-Host ("[WARN] unknown step: " + $stepKey)
        continue
    }
    $stepData = $data.steps.$stepKey
    Write-Host ("== Step " + $stepKey + ": " + $stepData.title)
    foreach ($stage in $stepData.stages) {
        Write-Host ("  {0,-8} {1,-58} {2}" -f $stage.id, $stage.case, $stage.status)
    }
    Write-Host ("  dependencies: " + ($stepData.dependencies -join "; "))
    Write-Host ("  NOT_TESTED : " + ($stepData.not_tested -join "; "))
    Write-Host ""
}
Write-Host ("global NOT_TESTED risks: " + ($data.not_tested_risks -join "; "))

if ($CheckPrereqs) {
    Write-Host ""
    Write-Host "Read-only prerequisite checks"
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $go) { Write-Host "  [FAIL] go not found"; exit 2 }
    Write-Host ("  [PASS] go: " + (& go version))
    foreach ($relative in @(
        "cmd/login-server/main.go", "cmd/loginctl/main.go", "cmd/login-backup/main.go",
        "tools/loginte2e/main.go", "scripts/e2e-login-server.ps1",
        "scripts/e2e-mail-delivery.ps1", "examples/oidc-login",
        "examples/app-qr-login", "EvernightMail/cmd/evernightmail/main.go"
    )) {
        $path = Join-Path $repo $relative
        if (Test-Path -LiteralPath $path) { Write-Host ("  [PASS] present: " + $relative) }
        else { Write-Host ("  [WARN] missing: " + $relative) }
    }
    foreach ($browser in @(
        "C:\Program Files\Google\Chrome\Application\chrome.exe",
        "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    )) {
        if (Test-Path -LiteralPath $browser) { Write-Host ("  [PASS] browser: " + $browser) }
        else { Write-Host ("  [WARN] browser not found: " + $browser) }
    }
    if (Test-Path -LiteralPath (Join-Path $repo ".git")) {
        $head = (& git -C $repo rev-parse --short HEAD 2>$null)
        $dirty = @(& git -C $repo status --porcelain -uall 2>$null).Count
        Write-Host ("  [INFO] HEAD=" + $head + " dirty_entries=" + $dirty + " (read-only)")
    }
    Write-Host "  [INFO] execution blocked until step 157/158 and 138-156 are closed; see .ai/lead/reports/step159-163-prep.md"
}

if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
    $plan = [pscustomobject]@{
        draft = $true
        generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        repo = $repo
        requested_steps = $Step
        status = "PREP_ONLY_NOT_RUN"
        blocked_by = @("step157", "step158", "step138", "step139", "step140-156")
        data = $data
    }
    $parent = Split-Path -Parent $JsonOut
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $plan | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $JsonOut -Encoding utf8
    Write-Host ("Plan JSON written: " + $JsonOut)
}

exit 0
