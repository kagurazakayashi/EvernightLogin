# build.ps1 - 步骤179 根目录一键构建入口（Windows PowerShell 5.1/7）。
#
# 用法示例：
#   .\build.ps1                                       # 四产品 × 六目标，输出 dist/build
#   .\build.ps1 -Version 1.0.0                        # 指定版本（注入 ldflags + 目录命名）
#   .\build.ps1 -Products login -Targets windows/amd64,linux/amd64
#   .\build.ps1 -OutputDir P:\go\tmp\build-output -Jobs 2
#   .\build.ps1 -OutputDir P:\go\tmp\build-output -ForceClean   # 清理已存在的非构建目录
#   .\build.ps1 -SkipVerify                           # 仅排障；正式验收禁用
#
# 输出目录安全：已存在的非空目录只有在包含 `.build-all-root` 构建标记时才会被自动
# 清理；否则必须显式传 -ForceClean，避免误删用户目录。
#
# 全部逻辑在 scripts/build-all.ps1（便于单测/维护）；本文件只做参数透传与退出码传播。
# 退出码：0 成功；10 预检失败；20 工具构建失败；21 Login 构建失败；22 Mail 构建失败；
#         30 manifest/聚合字段不符；31 产物缺失/类型/尺寸/SHA 不符；40 内部错误。
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
$core = Join-Path $PSScriptRoot 'scripts\build-all.ps1'
if (-not (Test-Path -LiteralPath $core)) {
    Write-Host "build.ps1: missing scripts/build-all.ps1"
    exit 10
}
$powerShell = (Get-Process -Id $PID).Path
if ([string]::IsNullOrWhiteSpace($powerShell)) { $powerShell = 'powershell' }
& $powerShell -NoProfile -ExecutionPolicy Bypass -File $core @Arguments
exit $LASTEXITCODE
