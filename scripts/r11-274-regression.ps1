# 步骤 274 分阶段安全回归：自包含 Windows 短测试运行器
#
# 用法（EvernightLogin 根目录）：
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/r11-274-regression.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts/r11-274-regression.ps1 -SkipStatic
#
# 说明：
#   - 只运行本步新增的 internal/e2e 公开门面矩阵（不含仓库其他测试）；
#   - 重型命令在共享工作树中应串行；运行前应先按团队规则获取 heavy-lock；
#   - 其他平台只做静态编译检查（CGO_ENABLED=0 go vet），不运行真实平台测试；
#   - 258/259/260 未合入前，直接管理 HTTP/CLI 入口与邮件 token/A→B→A 旧链接
#     以测试 Skip 形式显式记录（见 internal/e2e/pending_matrix_test.go）；
#   - 测试使用临时 SQLite/临时主密钥，结束后自动清理；不访问网络、不写真实数据。

param(
    [switch]$SkipStatic,
    [int]$TimeoutSeconds = 600
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $env:CGO_ENABLED = '0'
    Write-Host '== 步骤274 公开门面安全矩阵（Windows，短测试） =='
    go test -p 1 -count=1 -timeout "${TimeoutSeconds}s" ./internal/e2e/ -run 'TestMatrix' -v
    $matrixExit = $LASTEXITCODE
    if ($matrixExit -ne 0) {
        Write-Host "矩阵测试失败（exit=$matrixExit）"
        exit $matrixExit
    }

    if (-not $SkipStatic) {
        Write-Host '== 其他平台静态编译检查（仅编译，不运行） =='
        foreach ($target in @(
            @{ GOOS = 'linux'; GOARCH = 'amd64' },
            @{ GOOS = 'linux'; GOARCH = 'arm64' },
            @{ GOOS = 'darwin'; GOARCH = 'arm64' },
            @{ GOOS = 'windows'; GOARCH = 'arm64' }
        )) {
            $env:GOOS = $target.GOOS
            $env:GOARCH = $target.GOARCH
            Write-Host ("-- go vet ./internal/e2e/ (GOOS={0} GOARCH={1})" -f $target.GOOS, $target.GOARCH)
            go vet ./internal/e2e/
            if ($LASTEXITCODE -ne 0) {
                Write-Host ("静态检查失败: GOOS={0} GOARCH={1}" -f $target.GOOS, $target.GOARCH)
                exit $LASTEXITCODE
            }
        }
    }
    Write-Host '== 步骤274 当前阶段回归完成（258/259/260 后需补 HTTP/CLI/邮件链路矩阵） =='
}
finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Pop-Location
}
