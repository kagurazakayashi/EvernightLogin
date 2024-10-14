# run.ps1 - 根目录运行入口（Windows PowerShell 5.1/7）。
#
# 用法示例：
#   .\run.ps1                                          # 有 login.yaml 启动服务，否则进入 login-setup
#   .\run.ps1 -Program login-server                    # 启动独立服务
#   .\run.ps1 -Program login-setup                     # 本地初始化/维护控制台
#   .\run.ps1 -Program login-server -- --help          # -- 之后的参数原样传给程序
#   .\run.ps1 -List                                    # 查看当前平台可用产物
#
# 本文件只做参数透传与退出码传播；全部逻辑在 scripts/run-app.ps1。这里刻意不使用
# param 块，而由 $args 原样收集参数：这样 run.cmd 通过 powershell -File 调用时，
# 程序自身的 -flag 不会被脚本参数绑定吞掉或报错。
# 退出码：0 程序正常退出；2 参数/产物错误；3 login-server 缺少配置；其余为程序自身退出码。
$ErrorActionPreference = 'Stop'
$core = Join-Path $PSScriptRoot 'scripts\run-app.ps1'
if (-not (Test-Path -LiteralPath $core)) {
    Write-Host 'run.ps1: missing scripts/run-app.ps1'
    exit 2
}
& $core @args
exit $LASTEXITCODE
