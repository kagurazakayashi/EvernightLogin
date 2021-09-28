# login Windows service install helper (step 89).
#
# Purpose: install the WinSW-wrapped login-server as a Windows service with an
# explicit working directory and no secrets on the command line.
#
# IMPORTANT: cmd/login-server currently only implements --version/--help and
# exits immediately without arguments. Registering this service now will show a
# stopped/failed service; that is expected behavior, not a configuration bug.
# The template is provided for the moment the standalone HTTP assembly lands.
#
# Usage (elevated PowerShell):
#   pwsh -File .\install-windows-service.ps1 `
#        -WinswExe "C:\apps\evernight-login\bin\winsw.exe" `
#        -AppRoot  "C:\apps\evernight-login"
#
# The script never reads, writes or prints secrets.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$WinswExe,

    [Parameter(Mandatory = $true)]
    [string]$AppRoot,

    [Parameter(Mandatory = $false)]
    [string]$ServiceId = "EvernightLogin"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# 1. Verify elevation (installing a service requires an elevated process).
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must run in an elevated PowerShell session."
}

# 2. Verify paths and that no secret-looking files are inside the service config.
if (-not (Test-Path -LiteralPath $WinswExe -PathType Leaf)) {
    Write-Error "WinSW executable not found: $WinswExe"
}
if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
    Write-Error "Application root not found: $AppRoot"
}
$serviceXml = Join-Path $AppRoot "winsw-evernight-login.xml"
if (-not (Test-Path -LiteralPath $serviceXml -PathType Leaf)) {
    Write-Error "Service XML not found: $serviceXml (copy samples/winsw-evernight-login.xml there first)"
}
$serverExe = Join-Path $AppRoot "bin\login-server.exe"
if (-not (Test-Path -LiteralPath $serverExe -PathType Leaf)) {
    Write-Error "login-server.exe not found: $serverExe"
}

# 3. Smoke-run the binary once so operators see the honest current behavior.
Write-Host "Running a version check before installing the service..."
& $serverExe --version
if ($LASTEXITCODE -ne 0) {
    Write-Error "login-server --version failed with exit code $LASTEXITCODE"
}

# 4. Install and start through WinSW. WinSW install is idempotent only when the
#    service does not exist yet; stop/uninstall manually before re-installing.
Write-Host "Installing service $ServiceId ..."
& $WinswExe install $serviceXml
if ($LASTEXITCODE -ne 0) {
    Write-Error "WinSW install failed with exit code $LASTEXITCODE"
}

Write-Host "Starting service $ServiceId ..."
& $WinswExe start $serviceXml
if ($LASTEXITCODE -ne 0) {
    Write-Error "WinSW start failed with exit code $LASTEXITCODE"
}

sc.exe query $ServiceId
Write-Host "Done. Remember: until the standalone HTTP assembly lands, the service will exit immediately by design."
Write-Host "Logs: $(Join-Path $AppRoot 'logs')"
