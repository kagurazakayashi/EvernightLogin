#!/usr/bin/env sh
# run.sh - 根目录运行入口（POSIX）。
#
# 两种路径：
#   1) 默认优先委托现成 PowerShell（pwsh/powershell）执行 run.ps1，与 Windows
#      入口使用同一份逻辑，参数/退出码一致；
#   2) 仅有一份 POSIX shell 时（或显式 --no-powershell），使用本文件的原生路径：
#      按当前平台在 dist/build 中定位产物并 exec，不重新构建、不修改源码。
#
# 参数（原生路径同样接受 PowerShell 风格 -Name 形式）：
#   --program <name>   auto（默认）| login-server | login-setup | loginctl |
#                      login-backup | evernightmail
#   --config <path>    配置路径；缺省使用当前目录 login.yaml（存在时）
#   --exe <path>       直接指定可执行文件
#   --output-dir <dir> 产物根目录（默认 dist/build）
#   --goos/--goarch    覆盖目标平台（默认当前主机）
#   --list             列出当前平台可用产物
#   --no-powershell    强制原生 POSIX 路径
#   --                 其后参数原样传给程序
#
# 退出码：0 程序正常退出；2 参数/产物错误；3 login-server 缺少配置；
#         其余为被启动程序自身的退出码。产物缺失时先运行 sh build.sh。

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

PROGRAM="auto"
CONFIG=""
EXE=""
OUTPUT_DIR=""
GOOS=""
GOARCH=""
LIST=0
NO_POWERSHELL=0

usage() {
    cat <<'EOF'
用法：sh run.sh [选项] [-- 程序参数...]

选项：
  --program <name>   auto（默认）| login-server | login-setup | loginctl |
                     login-backup | evernightmail
  --config <path>    配置路径；缺省使用当前目录 login.yaml（存在时）
  --exe <path>       直接指定可执行文件
  --output-dir <dir> 产物根目录（默认 dist/build）
  --goos/--goarch    覆盖目标平台（默认当前主机）
  --list             列出当前平台可用产物
  --no-powershell    强制原生 POSIX 路径
  --                 其后参数原样传给程序

示例：
  sh run.sh                                       # 有 login.yaml 启动服务，否则进入 login-setup
  sh run.sh --program login-server                # 启动独立服务
  sh run.sh --program login-server -- --help      # -- 之后的参数原样传给程序
  sh run.sh --list                                # 查看当前平台产物

产物缺失时先运行 sh build.sh。
EOF
}

# 在委托前识别 --no-powershell；-- 之后的内容属于程序参数，不参与判断。
seen_separator=0
for arg in "$@"; do
    if [ "$seen_separator" -eq 1 ]; then break; fi
    case "$arg" in
        --) seen_separator=1 ;;
        --no-powershell) NO_POWERSHELL=1 ;;
    esac
done

if [ "$NO_POWERSHELL" -eq 0 ] && [ -f "$SCRIPT_DIR/run.ps1" ]; then
    if command -v pwsh >/dev/null 2>&1; then
        exec pwsh -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/run.ps1" "$@"
    fi
    if command -v powershell >/dev/null 2>&1; then
        exec powershell -NoProfile -ExecutionPolicy Bypass -File "$SCRIPT_DIR/run.ps1" "$@"
    fi
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --program|-Program) PROGRAM=${2:?missing value for $1}; shift 2 ;;
        --config|-Config) CONFIG=${2:?missing value for $1}; shift 2 ;;
        --exe|-Exe) EXE=${2:?missing value for $1}; shift 2 ;;
        --output-dir|-OutputDir) OUTPUT_DIR=${2:?missing value for $1}; shift 2 ;;
        --goos|-GoOS) GOOS=${2:?missing value for $1}; shift 2 ;;
        --goarch|-GoArch) GOARCH=${2:?missing value for $1}; shift 2 ;;
        --list|-List) LIST=1; shift ;;
        --no-powershell) NO_POWERSHELL=1; shift ;;
        -h|-\?) break ;;
        --help|-Help|-help) usage; exit 0 ;;
        --version|-version|-v) break ;;
        --) shift; break ;;
        -*) echo "run.sh: unknown option: $1 (use -- to pass program arguments)" >&2; exit 2 ;;
        *) break ;;
    esac
done

# 解析当前主机平台：优先 go env，缺少 Go 时退回 uname。
if [ -z "$GOOS" ]; then
    GOOS=$(go env GOOS 2>/dev/null || true)
    if [ -z "$GOOS" ]; then
        case "$(uname -s 2>/dev/null || echo unknown)" in
            MINGW*|MSYS*|CYGWIN*|Windows_NT) GOOS=windows ;;
            Darwin) GOOS=darwin ;;
            *) GOOS=linux ;;
        esac
    fi
fi
if [ -z "$GOARCH" ]; then
    GOARCH=$(go env GOARCH 2>/dev/null || true)
    if [ -z "$GOARCH" ]; then
        case "$(uname -m 2>/dev/null || echo unknown)" in
            x86_64|amd64) GOARCH=amd64 ;;
            aarch64|arm64) GOARCH=arm64 ;;
            i386|i686|x86) GOARCH=386 ;;
            *) GOARCH=amd64 ;;
        esac
    fi
fi

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$SCRIPT_DIR/dist/build"
fi

suffix=""
[ "$GOOS" = "windows" ] && suffix=".exe"

# find_artifact <name> <area>：输出匹配当前平台的最新可执行文件路径（可能为空）。
find_artifact() {
    _name=$1
    _area=$2
    _best=""
    for _dir in "$OUTPUT_DIR/$_area"/*; do
        [ -d "$_dir" ] || continue
        _base=${_dir##*/}
        case "$_base" in
            "${_name}_v"*"_${GOOS}_${GOARCH}") ;;
            *) continue ;;
        esac
        _file="$_dir/$_name$suffix"
        [ -f "$_file" ] || continue
        if [ -z "$_best" ] || [ "$_file" -nt "$_best" ]; then
            _best="$_file"
        fi
    done
    printf '%s' "$_best"
}

if [ "$LIST" -eq 1 ]; then
    printf '%s\n\n' "[run] platform=$GOOS/$GOARCH output=$OUTPUT_DIR"
    printf '%-15s %12s  %s\n' "程序" "大小" "路径"
    for name in login-server login-setup loginctl login-backup evernightmail; do
        area=login
        [ "$name" = "evernightmail" ] && area=mail
        item=$(find_artifact "$name" "$area")
        if [ -z "$item" ]; then
            printf '%-15s %12s  %s\n' "$name" "缺失" "-"
        else
            size=$(wc -c < "$item" | tr -d ' ')
            printf '%-15s %12s  %s\n' "$name" "$size B" "$item"
        fi
    done
    printf '\n%s\n' "产物缺失时先运行 sh build.sh。"
    exit 0
fi

# 配置：显式 --config 优先；否则仅当当前目录存在 login.yaml 时作为默认值。
EXPLICIT_CONFIG=0
[ -n "$CONFIG" ] && EXPLICIT_CONFIG=1
if [ -z "$CONFIG" ] && [ -f login.yaml ]; then
    CONFIG="login.yaml"
fi

PROGRAM=$(printf '%s' "$PROGRAM" | tr 'A-Z' 'a-z')
if [ "$PROGRAM" = "auto" ] && [ -n "$EXE" ]; then
    exe_name=${EXE##*/}
    exe_name=${exe_name%.exe}
    exe_name=${exe_name%.EXE}
    exe_name=$(printf '%s' "$exe_name" | tr 'A-Z' 'a-z')
    case "$exe_name" in
        login-server|login-setup|loginctl|login-backup|evernightmail)
            PROGRAM=$exe_name
            echo "[run] 由 --exe 推断程序：$PROGRAM"
            ;;
        *)
            echo "[run] 无法从 --exe 推断程序：$EXE；请同时指定 --program" >&2
            exit 2
            ;;
    esac
fi
if [ "$PROGRAM" = "auto" ]; then
    if [ "$EXPLICIT_CONFIG" -eq 1 ] || [ -n "$CONFIG" ]; then
        PROGRAM=login-server
        echo "[run] auto -> login-server（已指定 -Config 或存在 login.yaml）"
    else
        PROGRAM=login-setup
        echo "[run] auto -> login-setup（未发现 login.yaml；可用 -Program login-server 显式启动服务）"
    fi
fi

case "$PROGRAM" in
    login-server|login-setup|loginctl|login-backup|evernightmail) ;;
    *)
        echo "[run] 未知程序：$PROGRAM" >&2
        echo "[run] 可用程序：login-server, login-setup, loginctl, login-backup, evernightmail" >&2
        exit 2
        ;;
esac

area=login
[ "$PROGRAM" = "evernightmail" ] && area=mail

if [ -n "$EXE" ]; then
    if [ ! -f "$EXE" ]; then
        echo "[run] 指定的可执行文件不存在：$EXE" >&2
        exit 2
    fi
    artifact=$EXE
else
    artifact=$(find_artifact "$PROGRAM" "$area")
fi

if [ -z "$artifact" ]; then
    echo "[run] 未找到 $PROGRAM 的 $GOOS/$GOARCH 产物。" >&2
    echo "[run] 期望位置：$OUTPUT_DIR/$area/${PROGRAM}_v*_${GOOS}_${GOARCH}/" >&2
    echo "[run] 请先运行 sh build.sh。" >&2
    exit 2
fi

# 检测程序参数中是否已经包含配置与帮助/版本开关。
has_config=0
wants_help=0
for arg in "$@"; do
    case "$arg" in
        --config|--config=*|-config|-config=*) has_config=1 ;;
        -h|--help|-help|--version|-version|-v) wants_help=1 ;;
    esac
done

# 补齐配置参数：login-server 的 --config 必须在 serve/init 之后；
# login-setup 的 -config 是全局参数，必须在子命令之前。
case "$PROGRAM" in
    login-server)
        if [ "$has_config" -eq 0 ]; then
            if [ -z "$CONFIG" ]; then
                if [ "$wants_help" -eq 0 ]; then
                    echo "[run] login-server 需要配置文件，但当前目录没有 login.yaml。" >&2
                    echo "[run] 首次使用可先运行：sh run.sh --program login-setup" >&2
                    echo "[run] 已有配置可指定：sh run.sh --config /path/to/login.yaml" >&2
                    exit 3
                fi
            elif [ $# -eq 0 ]; then
                set -- serve --config "$CONFIG"
            else
                case "$1" in
                    serve|init)
                        subcommand=$1
                        shift
                        set -- "$subcommand" --config "$CONFIG" "$@"
                        ;;
                esac
            fi
        fi
        ;;
    login-setup)
        if [ "$wants_help" -eq 0 ] && [ "$has_config" -eq 0 ] && [ -n "$CONFIG" ]; then
            set -- -config "$CONFIG" "$@"
        fi
        ;;
esac

echo "[run] program=$PROGRAM platform=$GOOS/$GOARCH"
echo "[run] artifact=$artifact"

exec "$artifact" "$@"
