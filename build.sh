#!/usr/bin/env sh
# build.sh - 步骤179 其他平台入口（POSIX 维护入口）。
#
# 说明：与 build.ps1 相同的参数与退出码语义；本入口委托给 PowerShell 版本，
# 以避免两套构建逻辑分叉。当前项目约束下**只在 Windows 实测**；本文件仅做
# 静态审阅，未在 Linux/macOS 实机运行（需 pwsh 或 powershell 可用）。
#
# 示例：
#   ./build.sh                               # 四产品 × 六目标
#   ./build.sh -Version 1.0.0 -Products all
#   ./build.sh -OutputDir "$PWD/dist/build"
#
# 退出码同 scripts/build-all.ps1：0/10/20/21/22/30/31/40。

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CORE="$SCRIPT_DIR/scripts/build-all.ps1"

if [ ! -f "$CORE" ]; then
  echo "build.sh: missing scripts/build-all.ps1" >&2
  exit 10
fi

if command -v pwsh >/dev/null 2>&1; then
  PS="pwsh"
elif command -v powershell >/dev/null 2>&1; then
  PS="powershell"
else
  echo "build.sh: PowerShell (pwsh/powershell) not found; this POSIX entry delegates to" >&2
  echo "          scripts/build-all.ps1 so the build logic stays single-sourced." >&2
  echo "          Install PowerShell 7 or run build.ps1 on Windows." >&2
  exit 10
fi

# 固定工具链与产品依赖选择；其余参数原样透传。
export GOTOOLCHAIN=local
export GOWORK=off
export GOFLAGS=-mod=readonly
export CGO_ENABLED=0
export GOMAXPROCS=2

"$PS" -NoProfile -ExecutionPolicy Bypass -File "$CORE" "$@"
exit $?
