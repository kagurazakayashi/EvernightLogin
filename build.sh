#!/usr/bin/env sh
# build.sh - 一键四产品 × 六目标构建入口（POSIX）。
#
# 两种路径：
#   1) 默认自动选用现成 PowerShell（pwsh/powershell）并通过 scripts/build-all.ps1
#      执行与 build.ps1 完全相同的逻辑（单源逻辑，参数/退出码一致）；
#   2) 仅有一份 Go 工具链与 POSIX shell 时（或显式 --no-powershell），使用本文件
#      的原生 POSIX 构建路径：从固定源码构建 go-build-all、构建 Login 三程序与
#      Mail、按 manifest/清单记录版本/commit/平台/命令入口/SHA-256，并做基础校验。
#
# 原生路径参数（也接受 PowerShell 风格 -Name 形式）：
#   --version <v>       版本（默认 0.1.0-dev）
#   --products <p>      all|login|mail（默认 all）
#   --targets <list>    逗号分隔 GOOS/GOARCH，默认 windows/amd64,windows/arm64,
#                       linux/amd64,linux/arm64,darwin/amd64,darwin/arm64
#   --output-dir <dir>  输出目录（默认 dist/build；已存在目录只有含 .build-all-root
#                       构建标记才会被清理，否则拒绝，避免误删用户目录）
#   --jobs <n>          工具并发上限（0=工具默认；总预算会被工具夹紧）
#   --allow-dirty       允许子模块工作树脏（仅排障；正式构建应 clean）
#   --skip-verify       跳过基础产物校验（仅排障）
#   --no-powershell     强制原生 POSIX 路径，不调用 PowerShell
#
# 退出码：0 成功；10 预检/参数/输出目录失败；20 工具构建失败；21 Login 构建失败；
#         22 Mail 构建失败；31 产物缺失/空文件/清单校验失败；40 内部错误；130 取消。
#
# 本入口不执行 Git 写操作；不读取数据库；不清理 dist/release 或用户 bin 目录。

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CORE="$SCRIPT_DIR/scripts/build-all.ps1"
REPO_ROOT="$SCRIPT_DIR"

VERSION="0.1.0-dev"
PRODUCTS="all"
TARGETS="windows/amd64,windows/arm64,linux/amd64,linux/arm64,darwin/amd64,darwin/arm64"
OUTPUT_DIR=""
JOBS="0"
ALLOW_DIRTY=0
SKIP_VERIFY=0
NO_POWERSHELL=0
TOOL_SHA="8764de6504db1ecd1ecc5c3d4dd6618b51699cf1"
MAIL_SHA="aa7ccf57f6c0a8bb000a7dff6f101983ed6219fa"
MIN_GO="1.27.0"

usage() {
    sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
}

# ---- 优先委托 PowerShell（单源逻辑）----
if [ "$NO_POWERSHELL" -eq 0 ]; then
    for arg in "$@"; do
        if [ "$arg" = "--no-powershell" ]; then NO_POWERSHELL=1; fi
    done
fi

if [ "$NO_POWERSHELL" -eq 0 ]; then
    if [ -f "$CORE" ]; then
        if command -v pwsh >/dev/null 2>&1; then
            export GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOMAXPROCS=2
            export LOGIN_BUILD_ENTRY='build.sh (pwsh delegated)'
            exec pwsh -NoProfile -ExecutionPolicy Bypass -File "$CORE" "$@"
        elif command -v powershell >/dev/null 2>&1; then
            export GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOMAXPROCS=2
            export LOGIN_BUILD_ENTRY='build.sh (powershell delegated)'
            exec powershell -NoProfile -ExecutionPolicy Bypass -File "$CORE" "$@"
        fi
    fi
fi

# ---- 原生 POSIX 路径：只依赖 go + POSIX sh ----
while [ $# -gt 0 ]; do
    case "$1" in
        --version|-Version) VERSION=${2:?missing value for $1}; shift 2 ;;
        --products|-Products) PRODUCTS=${2:?missing value for $1}; shift 2 ;;
        --targets|-Targets) TARGETS=${2:?missing value for $1}; shift 2 ;;
        --output-dir|-OutputDir|-o) OUTPUT_DIR=${2:?missing value for $1}; shift 2 ;;
        --jobs|-Jobs|-j) JOBS=${2:?missing value for $1}; shift 2 ;;
        --allow-dirty|-AllowDirty) ALLOW_DIRTY=1; shift ;;
        --skip-verify|-SkipVerify) SKIP_VERIFY=1; shift ;;
        --no-powershell) NO_POWERSHELL=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "build.sh: unknown argument: $1 (try --help)" >&2; exit 10 ;;
    esac
done

fail() { echo "build.sh: $*" >&2; exit 10; }
command -v go >/dev/null 2>&1 || fail "go not found in PATH"
[ -d "$REPO_ROOT/go-build-all" ] || fail "missing go-build-all submodule"
[ -d "$REPO_ROOT/EvernightMail" ] || fail "missing EvernightMail submodule"
[ -f "$REPO_ROOT/go.mod" ] || fail "missing root go.mod"

export GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=0 GOMAXPROCS=2

GO_VERSION_TEXT=$(go version)
case "$GO_VERSION_TEXT" in
    *"go version go"*) ;;
    *) fail "cannot parse go version: $GO_VERSION_TEXT" ;;
esac
GO_VERSION=$(printf '%s' "$GO_VERSION_TEXT" | sed -n 's/.*go version go\([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
[ -n "$GO_VERSION" ] || fail "cannot parse go version: $GO_VERSION_TEXT"
GOMAJOR=$(printf '%s' "$GO_VERSION" | cut -d. -f1)
GOMINOR=$(printf '%s' "$GO_VERSION" | cut -d. -f2)
MINMAJOR=$(printf '%s' "$MIN_GO" | cut -d. -f1)
MINMINOR=$(printf '%s' "$MIN_GO" | cut -d. -f2)
if [ "$GOMAJOR" -lt "$MINMAJOR" ] || { [ "$GOMAJOR" -eq "$MINMAJOR" ] && [ "$GOMINOR" -lt "$MINMINOR" ]; }; then
    fail "go $GO_VERSION is older than required $MIN_GO"
fi
GOWORK_VALUE=$(go env GOWORK | tr -d '[:space:]')
[ -z "$GOWORK_VALUE" ] || [ "$GOWORK_VALUE" = "off" ] || fail "GOWORK must be off/empty (got '$GOWORK_VALUE')"
[ -z "$(find "$REPO_ROOT" -maxdepth 1 -name 'go.work*' -print -quit)" ] || fail "go.work must not exist"

git_or_unknown() { # git_or_unknown <dir> <args...>
    dir=$1; shift
    if command -v git >/dev/null 2>&1; then
        git -C "$dir" "$@" 2>/dev/null || printf 'unknown\n'
    else
        printf 'unknown\n'
    fi
}
PARENT_HEAD=$(git_or_unknown "$REPO_ROOT" rev-parse HEAD)
MAIL_HEAD=$(git_or_unknown "$REPO_ROOT/EvernightMail" rev-parse HEAD)
TOOL_HEAD=$(git_or_unknown "$REPO_ROOT/go-build-all" rev-parse HEAD)
PARENT_DIRTY=no
MAIL_DIRTY=no
TOOL_DIRTY=no
if command -v git >/dev/null 2>&1; then
    [ -z "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ] || PARENT_DIRTY=yes
    [ -z "$(git -C "$REPO_ROOT/EvernightMail" status --porcelain 2>/dev/null)" ] || MAIL_DIRTY=yes
    [ -z "$(git -C "$REPO_ROOT/go-build-all" status --porcelain 2>/dev/null)" ] || TOOL_DIRTY=yes
fi
[ "$TOOL_HEAD" = "$TOOL_SHA" ] || fail "go-build-all HEAD $TOOL_HEAD != pinned $TOOL_SHA"
[ "$MAIL_HEAD" = "$MAIL_SHA" ] || fail "EvernightMail HEAD $MAIL_HEAD != pinned $MAIL_SHA"
if [ "$ALLOW_DIRTY" -eq 0 ]; then
    [ "$MAIL_DIRTY" = no ] || fail "EvernightMail worktree dirty (pass --allow-dirty for diagnosis only)"
    [ "$TOOL_DIRTY" = no ] || fail "go-build-all worktree dirty (pass --allow-dirty for diagnosis only)"
fi
if [ "$PARENT_DIRTY" = yes ]; then
    echo "[warn ] parent worktree dirty; build summary records dirty=yes" >&2
fi

case " $(printf '%s' "$PRODUCTS" | tr ',' ' ') " in
    *" all "*) BUILD_LOGIN=1; BUILD_MAIL=1 ;;
    *) BUILD_LOGIN=0; BUILD_MAIL=0
       case ",$PRODUCTS," in
           *",login,"*) BUILD_LOGIN=1 ;;
           *",mail,"*) BUILD_MAIL=1 ;;
           *) fail "unknown --products '$PRODUCTS' (all|login|mail)" ;;
       esac ;;
esac
[ "$BUILD_LOGIN" -eq 1 ] || [ "$BUILD_MAIL" -eq 1 ] || fail "no product selected"

TARGET_COUNT=0
for target in $(printf '%s' "$TARGETS" | tr ',' ' '); do
    case "$target" in
        windows/amd64|windows/arm64|linux/amd64|linux/arm64|darwin/amd64|darwin/arm64) ;;
        *) fail "invalid target '$target'" ;;
    esac
    TARGET_COUNT=$((TARGET_COUNT + 1))
done
[ "$TARGET_COUNT" -gt 0 ] || fail "no targets selected"

if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="$REPO_ROOT/dist/build"
fi
case "$OUTPUT_DIR" in
    /*|[A-Za-z]:[\\/]*) ;;
    *) OUTPUT_DIR="$REPO_ROOT/$OUTPUT_DIR" ;;
esac
[ "$OUTPUT_DIR" = "$REPO_ROOT" ] && fail "output dir must not be repository root"
if [ -e "$OUTPUT_DIR" ]; then
    if [ -d "$OUTPUT_DIR" ] && [ -z "$(ls -A "$OUTPUT_DIR" 2>/dev/null)" ]; then
        :
    elif [ -d "$OUTPUT_DIR" ] && [ -f "$OUTPUT_DIR/.build-all-root" ]; then
        echo "[build] cleaning previous build output (marker found): $OUTPUT_DIR"
        rm -rf "$OUTPUT_DIR"
    else
        fail "output dir exists and is not a build-all directory: $OUTPUT_DIR (choose another dir)"
    fi
fi
mkdir -p "$OUTPUT_DIR/_tools"
printf '{"tool":"go-build-all build entry","version":"%s","created_at":"%s"}\n' \
    "$VERSION" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUTPUT_DIR/.build-all-root"
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

# compute_sha256 计算文件 SHA-256；缺少哈希工具时 fail-closed（退出 31），
# 不允许写出空哈希的“可追溯”清单。
compute_sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 "$1" | awk '{print $NF}'
    elif command -v certutil >/dev/null 2>&1; then
        certutil -hashfile "$1" SHA256 | sed -n '2p' | tr -d ' \r'
    else
        echo "build.sh: no SHA-256 tool (sha256sum/shasum/openssl) found" >&2
        exit 31
    fi
}

EXE_SUFFIX=""
case "$(go env GOOS)" in windows) EXE_SUFFIX=".exe" ;; esac
TOOL_EXE="$OUTPUT_DIR/_tools/go-build-all$EXE_SUFFIX"

CANCELLED=0
CURRENT_STAGE=preflight
START_TS=$(date +%s)
finish_cancelled() {
    CANCELLED=1
    DUR=$(( $(date +%s) - START_TS ))
    SUMMARY="$OUTPUT_DIR/build-summary.json"
    cat > "$SUMMARY" <<EOF
{"format":1,"generated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","started_at":"$(date -u -d "@$START_TS" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)","duration_ms":$((DUR * 1000)),"version":"$(json_escape "$VERSION")","status":"cancelled","cancelled":true,"stage":"$(json_escape "$CURRENT_STAGE")","exit_code":130,"entry":{"wrapper":"build.sh","script":"scripts/build-all.sh","arguments":{"version":"$(json_escape "$VERSION")","products":"$(json_escape "$PRODUCTS")","targets":"$(json_escape "$TARGETS")","output_dir":"$(json_escape "$OUTPUT_DIR")"}},"go":{"version":"$GO_VERSION"},"modules":{"EvernightLogin":"$PARENT_HEAD","EvernightMail":"$MAIL_HEAD"},"platforms":"$(json_escape "$TARGETS")"}
EOF
    echo "build.sh: cancelled at $CURRENT_STAGE; partial summary: $SUMMARY" >&2
    exit 130
}
trap 'finish_cancelled' INT TERM

CURRENT_STAGE=tool-build
echo "[build] repo=$REPO_ROOT go=$GO_VERSION products=$PRODUCTS targets=$TARGETS"
echo "[build] building go-build-all from pinned source $TOOL_SHA -> _tools/"
( cd "$REPO_ROOT/go-build-all" && go build -trimpath -o "$TOOL_EXE" . ) || { echo "build.sh: go-build-all build failed" >&2; exit 20; }
[ -s "$TOOL_EXE" ] || fail "go-build-all binary missing/empty"
TOOL_SHA256=$(compute_sha256 "$TOOL_EXE")

LOGIN_LDFLAGS="-s -w -X github.com/kagurazakayashi/EvernightLogin.version=$VERSION -X github.com/kagurazakayashi/EvernightLogin.commit=$PARENT_HEAD -X github.com/kagurazakayashi/EvernightLogin.buildTime=$BUILD_TIME"
MAIL_LDFLAGS="-s -w -X github.com/kagurazakayashi/EvernightMail/internal/version.Version=$VERSION -X github.com/kagurazakayashi/EvernightMail/internal/version.Commit=$MAIL_HEAD -X github.com/kagurazakayashi/EvernightMail/internal/version.BuildDate=$BUILD_TIME"

CURRENT_STAGE=login-build
if [ "$BUILD_LOGIN" -eq 1 ]; then
    echo "[build] invoking go-build-all for login (cmd/login-server,cmd/loginctl,cmd/login-backup)"
    "$TOOL_EXE" -r "$REPO_ROOT" -e 'cmd/login-server,cmd/loginctl,cmd/login-backup' \
        -p "$TARGETS" -o "$OUTPUT_DIR/login" -P cli -v "$VERSION" -A off -l off \
        -j "$JOBS" -T 1200 -trimpath -buildvcs=false -L "$LOGIN_LDFLAGS" || { echo "build.sh: Login build failed" >&2; exit 21; }
fi
CURRENT_STAGE=mail-build
if [ "$BUILD_MAIL" -eq 1 ]; then
    echo "[build] invoking go-build-all for mail (cmd/evernightmail)"
    "$TOOL_EXE" -r "$REPO_ROOT/EvernightMail" -e 'cmd/evernightmail' \
        -p "$TARGETS" -o "$OUTPUT_DIR/mail" -P cli -v "$VERSION" -A off -l off \
        -j "$JOBS" -T 1200 -trimpath -buildvcs=false -L "$MAIL_LDFLAGS" || { echo "build.sh: Mail build failed" >&2; exit 22; }
fi

CURRENT_STAGE=verify
EXPECTED=0
ARTIFACT_FILE="$OUTPUT_DIR/artifacts.tsv"
: > "$ARTIFACT_FILE"
SHA_FILE="$OUTPUT_DIR/SHA256SUMS.txt"
: > "$SHA_FILE"
add_product() { # add_product <product> <command> <root>
    product=$1; command=$2; root=$3
    [ -d "$root" ] || return 0
    for target in $(printf '%s' "$TARGETS" | tr ',' ' '); do
        goos=${target%%/*}
        goarch=${target#*/}
        suffix=""
        [ "$goos" = windows ] && suffix=".exe"
        binary=$(basename "$command")
        candidate=$(find "$root" -type f -name "$binary$suffix" 2>/dev/null | while IFS= read -r f; do
            case "$f" in *"$goos"*"$goarch"*) printf '%s\n' "$f";; esac
        done | head -n 1)
        if [ -z "$candidate" ] || [ ! -s "$candidate" ]; then
            echo "build.sh: missing artifact product=$product target=$goos/$goarch" >&2
            exit 31
        fi
        size=$(wc -c < "$candidate" | tr -d ' ')
        sha=$(compute_sha256 "$candidate")
        rel=$(printf '%s' "$candidate" | sed "s#^$OUTPUT_DIR/##")
        case "$goos" in
            windows) ftype=PE ;;
            linux) ftype=ELF ;;
            darwin) ftype=Mach-O ;;
            *) ftype=unknown ;;
        esac
        if [ "$product" = "evernightmail" ]; then artifact_commit=$MAIL_HEAD; else artifact_commit=$PARENT_HEAD; fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$product" "$command" "$goos" "$goarch" "$ftype" "$goarch" "$artifact_commit" "$size" "$sha" "$rel" >> "$ARTIFACT_FILE"
        ( cd "$OUTPUT_DIR" && printf '%s  %s\n' "$sha" "$rel" >> "$SHA_FILE" )
        EXPECTED=$((EXPECTED + 1))
    done
}
[ "$BUILD_LOGIN" -eq 1 ] && { add_product login-server cmd/login-server "$OUTPUT_DIR/login"; add_product loginctl cmd/loginctl "$OUTPUT_DIR/login"; add_product login-backup cmd/login-backup "$OUTPUT_DIR/login"; }
[ "$BUILD_MAIL" -eq 1 ] && add_product evernightmail cmd/evernightmail "$OUTPUT_DIR/mail"

if [ "$SKIP_VERIFY" -eq 0 ]; then
    echo "[build] artifacts verified=$EXPECTED"
fi

CURRENT_STAGE=summary
SUMMARY="$OUTPUT_DIR/build-summary.json"
{
    printf '{"format":1,"generated_at":"%s","started_at":"%s","duration_ms":%s,' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u -d "@$START_TS" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)" "$(( ( $(date +%s) - START_TS ) * 1000 ))"
    printf '"version":"%s","build_time":"%s","status":"completed","cancelled":false,"stage":"completed","exit_code":0,' "$(json_escape "$VERSION")" "$(json_escape "$BUILD_TIME")"
    printf '"entry":{"wrapper":"build.sh","script":"scripts/build-all.sh","arguments":{"version":"%s","products":"%s","targets":"%s","jobs":%s,"output_dir":"%s","allow_dirty":%s,"skip_verify":%s}},' \
        "$(json_escape "$VERSION")" "$(json_escape "$PRODUCTS")" "$(json_escape "$TARGETS")" "$JOBS" "$(json_escape "$OUTPUT_DIR")" "$([ "$ALLOW_DIRTY" -eq 1 ] && echo true || echo false)" "$([ "$SKIP_VERIFY" -eq 1 ] && echo true || echo false)"
    printf '"host":{"os":"%s","shell":"posix-sh"},"go":{"version":"%s","cgo_enabled":"0","gotoolchain":"local","gowork":"off"},' "$(json_escape "$(uname -s 2>/dev/null || echo unknown)")" "$(json_escape "$GO_VERSION")"
    printf '"modules":[{"name":"EvernightLogin","commit":"%s","dirty":%s},{"name":"EvernightMail","commit":"%s","dirty":%s}],' \
        "$PARENT_HEAD" "$([ "$PARENT_DIRTY" = yes ] && echo true || echo false)" "$MAIL_HEAD" "$([ "$MAIL_DIRTY" = yes ] && echo true || echo false)"
    printf '"tool":{"commit":"%s","path":"_tools/go-build-all%s","sha256":"%s"},"submodule_gitlinks":{"mail":"%s","tool":"%s"},"platforms":"%s","artifact_count":%s,"artifacts":[' "$TOOL_SHA" "$EXE_SUFFIX" "$TOOL_SHA256" "$MAIL_SHA" "$TOOL_SHA" "$(json_escape "$TARGETS")" "$EXPECTED"
    first=1
    while IFS="$(printf '\t')" read -r product command goos goarch ftype arch commit size sha rel; do
        [ -n "$product" ] || continue
        if [ "$first" -eq 0 ]; then printf ','; fi
        first=0
        printf '{"product":"%s","command":"%s","goos":"%s","goarch":"%s","type":"%s","arch":"%s","version":"%s","commit":"%s","size":%s,"sha256":"%s","path":"%s","status":"built"}' \
            "$(json_escape "$product")" "$(json_escape "$command")" "$(json_escape "$goos")" "$(json_escape "$goarch")" "$(json_escape "$ftype")" "$(json_escape "$arch")" "$(json_escape "$VERSION")" "$commit" "$size" "$sha" "$(json_escape "$rel")"
    done < "$ARTIFACT_FILE"
    printf ']}'
} > "$SUMMARY"

{
    printf 'EvernightLogin/EvernightMail one-click build checklist (posix-sh fallback)\n'
    printf 'version=%s go=%s tool=%s mail=%s\n' "$VERSION" "$GO_VERSION" "$TOOL_SHA" "$MAIL_SHA"
    while IFS="$(printf '\t')" read -r product command goos goarch ftype arch commit size sha rel; do
        [ -n "$product" ] || continue
        printf 'OK  %s  %s  %s/%s  type=%s  arch=%s  commit=%s  size=%s  sha256=%s  %s\n' "$product" "$command" "$goos" "$goarch" "$ftype" "$arch" "$commit" "$size" "$sha" "$rel"
    done < "$ARTIFACT_FILE"
    printf 'TOTAL verified=%s exit=0\n' "$EXPECTED"
} > "$OUTPUT_DIR/checklist.txt"

echo "[build] build-summary: $SUMMARY"
echo "[build] checklist:    $OUTPUT_DIR/checklist.txt"
echo "[build] Done. verified=$EXPECTED exit=0"
exit 0
