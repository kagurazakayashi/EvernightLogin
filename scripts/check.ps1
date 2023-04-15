# login local checks for Windows PowerShell 5.1 and PowerShell 7.
# Runs format, dependency, build, vet, and targeted test checks only.
# It never commits, pushes, starts a service, or writes go.mod/go.sum.
[CmdletBinding()]
param(
    [ValidateRange(0, 1024)]
    [int]$Parallel = 0,
    # Also check the EvernightMail submodule as a separate Go module. Mail is a
    # development/test-only sibling module; the parent module never imports it.
    # Without -Mail the parent checks remain self-contained and -Mail is skipped.
    [switch]$Mail,
    # Require the parent gitlink + clean Mail worktree (reproducible revision).
    # Default -Mail only warns about an unpinned/dirty Mail checkout.
    [switch]$RequirePinned,
    # Run the parent internal/mailtest package (available after migration 136).
    # It is opt-in because 135/136 may be in progress or the fixture may need a
    # separately built Mail binary; -Mail alone still checks preflight/build/gofmt.
    [switch]$MailTests,
    # Explicitly skip the fixture even when -MailTests was requested.
    [switch]$SkipMailTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $cores = [Environment]::ProcessorCount
    $limit = [Math]::Max(1, [Math]::Floor($cores / 2))
    if ($Parallel -eq 0) {
        $Parallel = $limit
    } elseif ($Parallel -gt $limit) {
        throw "Concurrency cap is $limit (half of $cores logical processors); refusing $Parallel."
    }

    # Pin the local toolchain and pure-Go build so checks do not download
    # another toolchain or mutate the module graph.
    $env:GOTOOLCHAIN = 'local'
    $env:CGO_ENABLED = '0'
    $env:GOMAXPROCS = "$Parallel"

    Write-Host "workdir: $root"
    Write-Host "logical processors: $cores; concurrency cap: $Parallel"

    $failed = $false
    function Invoke-Check {
        param([string]$Name, [scriptblock]$Action)
        Write-Host "==> $Name"
        & $Action
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[FAIL] $Name" -ForegroundColor Red
            $script:failed = $true
        } else {
            Write-Host "[PASS] $Name" -ForegroundColor Green
        }
    }

    # Parent module only: never lint the nested EvernightMail module from the
    # repository root (it has its own module/gofmt gate; see -Mail below).
    # EvernightMail submodule check (separate module, never imported by parent).
    $mailDir = Join-Path $root 'EvernightMail'
    if ($Mail) {
        Write-Host '==> Mail prerequisite preflight'
        $preflight = Join-Path $PSScriptRoot 'mail-preflight.ps1'
        if (-not (Test-Path -LiteralPath $preflight -PathType Leaf)) {
            Write-Host "[FAIL] missing $preflight" -ForegroundColor Red
            $failed = $true
        } else {
            if ($PSVersionTable.PSEdition -eq 'Core') {
                $hostExe = Join-Path $PSHOME 'pwsh.exe'
            } else {
                $hostExe = Join-Path $PSHOME 'powershell.exe'
            }
            if (-not (Test-Path -LiteralPath $hostExe -PathType Leaf)) { $hostExe = 'powershell.exe' }
            $preflightArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $preflight,
                '-Build', '-RequireMail', '-Parallel', "$Parallel")
            if ($RequirePinned) { $preflightArgs += '-RequirePinned' }
            & $hostExe @preflightArgs
            if ($LASTEXITCODE -ne 0) {
                Write-Host '[FAIL] Mail prerequisite preflight' -ForegroundColor Red
                $failed = $true
            } else {
                Write-Host '[PASS] Mail prerequisite preflight' -ForegroundColor Green
                if (Test-Path -LiteralPath $mailDir -PathType Container) {
                    Write-Host '==> Mail gofmt (separate module)'
                    $mailGoFiles = @(Get-ChildItem -Path $mailDir -Recurse -Filter '*.go' -File |
                        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
                        ForEach-Object { $_.FullName })
                    if ($mailGoFiles.Count -eq 0) {
                        Write-Host '[PASS] Mail gofmt (no Go files)' -ForegroundColor Green
                    } else {
                        $mailUnformatted = @()
                        $mailGofmtFailed = $false
                        for ($offset = 0; $offset -lt $mailGoFiles.Count; $offset += 100) {
                            $end = [Math]::Min($offset + 99, $mailGoFiles.Count - 1)
                            $chunk = @($mailGoFiles[$offset..$end])
                            $chunkResult = @(& gofmt -l $chunk)
                            if ($LASTEXITCODE -ne 0) { $mailGofmtFailed = $true; break }
                            $mailUnformatted += $chunkResult
                        }
                        if ($mailGofmtFailed -or $mailUnformatted.Count -gt 0) {
                            Write-Host '[FAIL] Mail gofmt' -ForegroundColor Red
                            $mailUnformatted | ForEach-Object { Write-Host "  $_" }
                            $failed = $true
                        } else {
                            Write-Host '[PASS] Mail gofmt' -ForegroundColor Green
                        }
                    }
                    # Parent-side Mail test fixture (step 136 migration target).
                    if ($MailTests -and -not $SkipMailTests) {
                        $mailtestDir = Join-Path $root 'internal/mailtest'
                        if (Test-Path -LiteralPath $mailtestDir -PathType Container) {
                            Write-Host '==> Mail fixture tests (parent internal/mailtest)'
                            $oldRequired = $env:EVERNIGHTMAIL_REQUIRED
                            $env:EVERNIGHTMAIL_REQUIRED = '1'
                            try {
                                & go test -mod=readonly -count=1 -p 1 -parallel $Parallel -timeout 180s ./internal/mailtest/...
                                if ($LASTEXITCODE -ne 0) {
                                    Write-Host '[FAIL] Mail fixture tests' -ForegroundColor Red
                                    $failed = $true
                                } else {
                                    Write-Host '[PASS] Mail fixture tests' -ForegroundColor Green
                                }
                            } finally {
                                $env:EVERNIGHTMAIL_REQUIRED = $oldRequired
                            }
                        } else {
                            Write-Host '[SKIP] internal/mailtest not present yet (step 136); parent Mail fixture tests skipped.'
                        }
                    } elseif (-not $SkipMailTests) {
                        Write-Host '[SKIP] parent Mail fixture tests not requested (use -MailTests after step 136).'
                    }
                }
            }
        }
    } else {
        Write-Host '==> Mail checks skipped (use -Mail to include EvernightMail submodule checks)'
    }

    $goFiles = @(Get-ChildItem -Path $root -Recurse -Filter '*.go' -File |
        Where-Object {
            $_.FullName -notmatch '[\\/]\.git[\\/]' -and
            $_.FullName -notmatch '[\\/]EvernightMail[\\/]'
        } |
        ForEach-Object { $_.FullName })
    Write-Host '==> gofmt (check only)'
    if ($goFiles.Count -eq 0) {
        Write-Host '[PASS] gofmt (no Go files)' -ForegroundColor Green
    } else {
        # Pass files in bounded chunks: a single gofmt.exe command line can
        # exceed the Windows limit once the repository has many Go files.
        $unformatted = @()
        $gofmtFailed = $false
        for ($offset = 0; $offset -lt $goFiles.Count; $offset += 100) {
            $end = [Math]::Min($offset + 99, $goFiles.Count - 1)
            $chunk = @($goFiles[$offset..$end])
            $chunkResult = @(& gofmt -l $chunk)
            if ($LASTEXITCODE -ne 0) { $gofmtFailed = $true; break }
            $unformatted += $chunkResult
        }
        if ($gofmtFailed) {
            Write-Host '[FAIL] gofmt failed to run' -ForegroundColor Red
            $failed = $true
        } elseif ($unformatted.Count -gt 0) {
            Write-Host '[FAIL] these files need gofmt:' -ForegroundColor Red
            $unformatted | ForEach-Object { Write-Host "  $_" }
            $failed = $true
        } else {
            Write-Host '[PASS] gofmt' -ForegroundColor Green
        }
    }

    Invoke-Check 'go mod verify' { & go mod verify }
    Invoke-Check 'go mod tidy -diff' { & go mod tidy -diff }
    Invoke-Check 'go build' { & go build -trimpath -mod=readonly -p $Parallel ./... }
    Invoke-Check 'go vet' { & go vet -mod=readonly -p $Parallel ./... }
    Invoke-Check 'go test' {
        # Test packages run one at a time so this script never starts several
        # test binaries at once; build parallelism is still capped above.
        & go test -mod=readonly -count=1 -p 1 -parallel $Parallel -timeout 120s ./...
    }

    if ($failed) {
        Write-Host 'CHECK FAILED' -ForegroundColor Red
        exit 1
    }
    Write-Host 'CHECK PASSED' -ForegroundColor Green
    exit 0
}
finally {
    Pop-Location
}
