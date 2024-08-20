# protocol-selftest.ps1 - 步骤 243 自包含协议与安全集成测试工具（CI/本地入口）。
#
# 本包装只负责定位仓库根、设置固定工具链环境并透传参数给 Go 工具；所有场景、
# 超时、JSON/退出码语义均在 scripts/protocol-selftest/main.go 中，避免两套逻辑。
#
# 用法：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\protocol-selftest.ps1
#   powershell -File scripts\protocol-selftest.ps1 -out P:\go\tmp\protocol-selftest.json -verbose
#   powershell -File scripts\protocol-selftest.ps1 -list
#
# 退出码与 Go 工具一致：0 通过/1 失败/2 参数/3 环境不可用/4 结果写出失败/130 超时。
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$env:GOTOOLCHAIN = 'local'
$env:GOWORK = 'off'
$env:GOFLAGS = '-mod=readonly'
$env:CGO_ENABLED = '0'
$env:GOMAXPROCS = '2'
$env:GOPROXY = 'off'
Push-Location $repositoryRoot
try {
    & go run ./scripts/protocol-selftest @Arguments
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
