# login local checks for Windows PowerShell 5.1 and PowerShell 7.
# Runs format, dependency, build, vet, and targeted test checks only.
# It never commits, pushes, starts a service, or writes go.mod/go.sum.
[CmdletBinding()]
param(
    [ValidateRange(0, 1024)]
    [int]$Parallel = 0
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

    $goFiles = @(Get-ChildItem -Path $root -Recurse -Filter '*.go' -File |
        Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
        ForEach-Object { $_.FullName })
    Write-Host '==> gofmt (check only)'
    if ($goFiles.Count -eq 0) {
        Write-Host '[PASS] gofmt (no Go files)' -ForegroundColor Green
    } else {
        $unformatted = @(& gofmt -l $goFiles)
        if ($LASTEXITCODE -ne 0) {
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
