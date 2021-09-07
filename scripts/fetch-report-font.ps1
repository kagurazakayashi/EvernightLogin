# Step 78: fetch the vetted Noto Sans SC static Regular TTF for report PDF output.
# Usage (PowerShell 7 or Windows PowerShell 5.1):
#   pwsh -File scripts/fetch-report-font.ps1 -Destination C:\path\to\fonts
#   pwsh -File scripts/fetch-report-font.ps1 -Destination C:\path\to\fonts -Proxy http://127.0.0.1:23333
# The font is NOT committed to Git. Point reports.Options.FontPath at the downloaded
# NotoSansSC-Regular.ttf and keep docs/licenses/NotoSansSC-OFL.txt in the distribution.
# The script verifies the exact size and SHA-256 before reporting success; a mismatch
# is a hard failure and the partial file is removed.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Destination = (Join-Path $env:LOCALAPPDATA 'EvernightLogin\fonts'),

    [Parameter(Mandatory = $false)]
    [string]$Proxy = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$FontUrl = 'https://fonts.gstatic.com/s/notosanssc/v41/k3kCo84MPvpLmixcA63oeAL7Iqp5IZJF9bmaG9_FnYw.ttf'
$LicenseUrl = 'https://raw.githubusercontent.com/google/fonts/main/ofl/notosanssc/OFL.txt'
$ExpectedFontBytes = 10540644
$ExpectedFontSha256 = '450625c8d46ab3df97b7904ded955ec2746d17ec76740cb1e91d1ba63a0f89af'
$ExpectedLicenseBytes = 4388
$ExpectedLicenseSha256 = '1c05c68c34f9708415aada51f17e1b0092d2cea709bf4a94cd38114f9e73d7d9'

function Get-Sha256Hex {
    param([Parameter(Mandatory = $true)][string]$Path)
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Invoke-Download {
    param(
        [Parameter(Mandatory = $true)][string]$Url,
        [Parameter(Mandatory = $true)][string]$OutFile
    )
    $arguments = @{
        Uri             = $Url
        OutFile         = $OutFile
        UseBasicParsing = $true
    }
    if ($Proxy -ne '') {
        $arguments['Proxy'] = $Proxy
    }
    Write-Host "Downloading $Url"
    Invoke-WebRequest @arguments
}

if (-not (Test-Path -LiteralPath $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
}

$fontPath = Join-Path $Destination 'NotoSansSC-Regular.ttf'
$licensePath = Join-Path $Destination 'OFL.txt'

Invoke-Download -Url $FontUrl -OutFile $fontPath
$fontInfo = Get-Item -LiteralPath $fontPath
if ($fontInfo.Length -ne $ExpectedFontBytes) {
    Remove-Item -LiteralPath $fontPath -Force
    throw "Font size mismatch: got $($fontInfo.Length), expected $ExpectedFontBytes"
}
$fontHash = Get-Sha256Hex -Path $fontPath
if ($fontHash -ne $ExpectedFontSha256) {
    Remove-Item -LiteralPath $fontPath -Force
    throw "Font SHA-256 mismatch: got $fontHash, expected $ExpectedFontSha256"
}
Write-Host "Verified font: $fontPath ($ExpectedFontBytes bytes, SHA-256 $ExpectedFontSha256)"

Invoke-Download -Url $LicenseUrl -OutFile $licensePath
$licenseInfo = Get-Item -LiteralPath $licensePath
$licenseHash = Get-Sha256Hex -Path $licensePath
if ($licenseInfo.Length -ne $ExpectedLicenseBytes -or $licenseHash -ne $ExpectedLicenseSha256) {
    Remove-Item -LiteralPath $licensePath -Force
    throw "OFL.txt mismatch: got $($licenseInfo.Length) bytes / $licenseHash"
}
Write-Host "Verified license: $licensePath ($ExpectedLicenseBytes bytes, SHA-256 $ExpectedLicenseSha256)"
Write-Host ''
Write-Host 'Set reports.Options.FontPath to the font path above.'
Write-Host 'Keep docs/licenses/NotoSansSC-OFL.txt (and the downloaded OFL.txt) with the distribution.'
