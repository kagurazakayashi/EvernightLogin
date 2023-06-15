# Step 158 acceptance matrix draft (parent Login: Windows + SQLite + real process)
# DRAFT ONLY. This skeleton performs NO destructive action and does not start any
# process unless -Execute is passed (not implemented yet). It can print the plan
# and run read-only prerequisite checks.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\acceptance\step158-matrix.ps1
#   powershell ... -CheckPrereqs
#   powershell ... -JsonOut P:\go\tmp\step158-plan.json
#   powershell ... -Execute   # reserved; currently refuses (exit 3)
#
# Exit codes: 0 plan/check completed; 2 invalid args; 3 execution explicitly refused.

[CmdletBinding()]
param(
    [string]$WorkRoot = "",
    [switch]$CheckPrereqs,
    [string]$JsonOut = "",
    [switch]$Execute
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($Execute) {
    Write-Host "DRAFT: -Execute is intentionally not implemented. Step 158 is blocked on step 157 and 138-156 assembly; run only after Lead freeze."
    exit 3
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if ([string]::IsNullOrWhiteSpace($WorkRoot)) {
    $WorkRoot = Join-Path ([System.IO.Path]::GetTempPath()) "login-step158-draft"
}

$cases = @(
    [pscustomobject]@{
        Id = "S0"; Name = "Baseline and candidate binary build"
        Command = "go version; git -C <repo> rev-parse HEAD; git -C <repo> status --porcelain -uall; go build -p 3 -trimpath -o <work>/bin/login-server.exe ./cmd/login-server; go build ... ./cmd/loginctl; go build ... ./tools/loginte2e"
        Expected = "Build exit 0; HEAD/status recorded; version strings recorded; no repository database touched"
        Evidence = "<work>/evidence/s0-build.json, console log"
        Dependency = "none"; Status = "READY_REUSE"
    },
    [pscustomobject]@{
        Id = "S1"; Name = "Empty temp dir, config, protected secrets, init root"
        Command = "copy examples/config-load/login.example.yaml <work>/login.yaml; set random loopback port + temp sqlite path; write protected password file; login-server init --config <work>/login.yaml --master-key-file <work>/secrets/master.key --password-file <work>/secrets/init-password.txt --operator step158"
        Expected = "Exit 0 and setup_verified; root_state=setup_verified; strong_auth_required=true; repeat init rejected"
        Evidence = "<work>/evidence/s1-init.json; init stdout/stderr (password never printed)"
        Dependency = "138 init/serve regression; no 140 dependency for local root creation"; Status = "READY_REUSE"
    },
    [pscustomobject]@{
        Id = "S2"; Name = "Real serve process and HTTP surface"
        Command = "login-server serve --config <work>/login.yaml --master-key-file <work>/secrets/master.key --enable-protocol --enable-admin-api --access-log <work>/access.log; wait for http://127.0.0.1:<port>/healthz"
        Expected = "Health ok; openapi/login page reachable; access log written; graceful stop releases port"
        Evidence = "<work>/evidence/s2-serve.json; process logs; netstat/port release"
        Dependency = "138 serve assembly; HTTP pages/protocol routes"; Status = "READY_REUSE (process smoke via scripts/e2e-login-server.ps1)"
    },
    [pscustomobject]@{
        Id = "S3"; Name = "Strong-factor binding (root/strong auth)"
        Command = "go test -count=1 -run 'TestMFASecurityKeySecondFactorWithRealPasskeyCeremony|TestServeRejectsNonRequiredPasskeyUV' -v ./internal/passkey ./internal/serverapp"
        Expected = "Root strong-auth state and passkey/MFA ceremony assertions pass; no plaintext secrets in logs"
        Evidence = "<work>/evidence/s3-strongfactor.log"
        Dependency = "browser/CTAP hardware may be NOT_TESTED; step 159/140"; Status = "PARTIAL (real browser/authenticator NOT_TESTED)"
    },
    [pscustomobject]@{
        Id = "S4"; Name = "Register + admin-created user + review"
        Command = "GOMAXPROCS=4 CGO_ENABLED=0 go test -count=1 -p 2 -run 'TestStep91RegistrationInviteAndReview' -v ."
        Expected = "Pending registration, review approval, invite flow; cross-app role grant rejected; audit written"
        Evidence = "<work>/evidence/s4-registration.log"
        Dependency = "140/146/147 HTTP registration/user management for HTTP-level variant"; Status = "READY_REUSE (Go-level); HTTP variant BLOCKED"
    },
    [pscustomobject]@{
        Id = "S5"; Name = "Profile rename/email change invariants"
        Command = "go test -count=1 -run 'TestStep91ProfileAndEmailChange|TestStep91AccountLifecycleAndSessionInvalidation' -v ."
        Expected = "User ID unchanged on rename; field whitelist; email verification path; audit records"
        Evidence = "<work>/evidence/s5-profile.log"
        Dependency = "140 email verification HTTP; 147 profile API"; Status = "READY_REUSE (Go-level); HTTP variant BLOCKED"
    },
    [pscustomobject]@{
        Id = "S6"; Name = "Groups/roles/permissions and two-application isolation"
        Command = "go test -count=1 -run 'TestStep91PermissionMatrixAcrossApps|TestStep91SelfEscalationAndCrossAppDenied' -v .; loginctl group list/role list/app list/permission list --operator step158 --config <work>/login.yaml"
        Expected = "Direct/indirect grants bounded; app A/B isolation; self-escalation and cross-app denial; root protected; audit"
        Evidence = "<work>/evidence/s6-authz.log; loginctl read-only JSON"
        Dependency = "144/146/147/148/149 for HTTP/admin API; local CLI read-only available"; Status = "READY_REUSE (Go-level/CLI read); HTTP variant BLOCKED"
    },
    [pscustomobject]@{
        Id = "S7"; Name = "Disable/enable, session invalidation and revocation"
        Command = "go test -count=1 -run 'TestStep91AccountLifecycleAndSessionInvalidation' -v .; loginctl user get/disable <id> --operator step158 --expected-version N --confirm DISABLE --config <work>/login.yaml; loginctl session list/revoke --session-file <protected> --keyring-file <protected>"
        Expected = "Disable bumps security_version; old sessions rejected; enable does not lower version; revoke semantics; audit"
        Evidence = "<work>/evidence/s7-session.log"
        Dependency = "151 forced logout/151 admin sessions for cross-app admin variant"; Status = "READY_REUSE (Go/CLI); admin-forced logout HTTP NOT_TESTED"
    },
    [pscustomobject]@{
        Id = "S8"; Name = "Refusal paths (HTTP/CLI/protocol)"
        Command = "curl admin API without session -> 401/403; loginctl online no-session/fake-session -> stable non-zero; loginte2e token negative PKCE/replay; 404 for disabled API/protocol"
        Expected = "Stable error codes, no secret leakage, no fake success"
        Evidence = "<work>/evidence/s8-refusal.json"
        Dependency = "146-156 admin API; 147/148/155/156 management routes"; Status = "PARTIAL (existing e2e negative paths READY; user-management negative BLOCKED)"
    },
    [pscustomobject]@{
        Id = "S9"; Name = "Audit evidence and cleanup"
        Command = "go test assertions in TestStep91*; loginctl audit events list --session-file <protected> --config <work>/login.yaml (requires enabled admin API/strong auth); stop serve; delete temp dir; assert no process/port/db side effect"
        Expected = "Audit entries for create/rename/role change/disable/refusal; sanitized output; zero remnants"
        Evidence = "<work>/evidence/s9-audit.json; cleanup check"
        Dependency = "144/146/147/148/155/156 audit API; otherwise only Go-level audit assertions"; Status = "PARTIAL (Go-level READY; API-level BLOCKED)"
    }
)

Write-Host "Step 158 acceptance matrix draft (NO destructive action)"
Write-Host ("repo   : " + $repo)
Write-Host ("work   : " + $WorkRoot)
Write-Host ("cases  : " + $cases.Count)
Write-Host ""
$format = "{0,-3} {1,-46} {2,-12} {3}"
Write-Host ("{0,-3} {1,-46} {2,-12} {3}" -f "id", "case", "status", "dependency")
foreach ($case in $cases) {
    Write-Host ("{0,-3} {1,-46} {2,-12} {3}" -f $case.Id, $case.Name, $case.Status, $case.Dependency)
}

if ($CheckPrereqs) {
    Write-Host ""
    Write-Host "Read-only prerequisite checks"
    $go = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $go) { Write-Host "  [FAIL] go not found"; exit 2 }
    Write-Host ("  [PASS] go: " + (& go version))
    foreach ($relative in @("cmd/login-server/main.go", "cmd/loginctl/main.go", "tools/loginte2e/main.go", "scripts/e2e-login-server.ps1", "examples/config-load/login.example.yaml")) {
        $path = Join-Path $repo $relative
        if (Test-Path -LiteralPath $path -PathType Leaf) { Write-Host ("  [PASS] present: " + $relative) }
        else { Write-Host ("  [FAIL] missing: " + $relative) }
    }
    if (Test-Path -LiteralPath (Join-Path $repo ".git")) {
        $head = (& git -C $repo rev-parse --short HEAD 2>$null)
        $dirty = @(& git -C $repo status --porcelain -uall 2>$null).Count
        Write-Host ("  [INFO] HEAD=" + $head + " dirty_entries=" + $dirty + " (read-only, no git write)")
    }
    Write-Host "  [INFO] full step 158 execution is blocked until step 157 and 138-156 are closed; see .ai/lead/reports/step157-158-prep.md"
}

if (-not [string]::IsNullOrWhiteSpace($JsonOut)) {
    $plan = [pscustomobject]@{
        draft = $true
        generated_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        repo = $repo
        work_root = $WorkRoot
        blocked_by = @("step157", "step138", "step139", "step140-156")
        cases = $cases
    }
    $parent = Split-Path -Parent $JsonOut
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }
    $plan | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $JsonOut -Encoding utf8
    Write-Host ("Plan JSON written: " + $JsonOut)
}

exit 0
