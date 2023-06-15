# ----- login 容器样例（步骤 89）-----
# 多阶段构建：静态 Go 二进制 + 最小运行镜像。
# 注意：镜像 ENTRYPOINT 需按部署配置补 `serve --config <挂载配置>` 参数才会常驻
# 监听；首次初始化 `init` 应作为一次性运维任务单独执行（不在容器启动脚本内创建 root）。
# 当前独立服务为宿主装配 MVP：健康检查/OpenAPI 与 14 个页面选项（默认 12、条件 2）
# 可用；OAuth/OIDC 协议端点与管理 JSON API 已装配但默认关闭（需配置开关），设备码/扫码/
# 令牌状态查询部分实现且未完成验收（142–145），不能当作开箱即用的完整对外身份服务。
#
# 构建（在仓库根目录）：
#   docker build -f docs/deployment/samples/Dockerfile -t evernight-login:dev .
# 说明：本轮未实际执行镜像构建与运行（环境不保证有 Docker），标记为未实测。

# ---------- 构建阶段 ----------
FROM golang:1.27 AS build

WORKDIR /src

# 先复制依赖清单，利用缓存；不使用 vendor，不新增依赖。
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=devel
ARG COMMIT=unknown
ARG BUILD_TIME=unknown

ENV CGO_ENABLED=0

RUN go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X github.com/kagurazakayashi/EvernightLogin.version=${VERSION} \
        -X github.com/kagurazakayashi/EvernightLogin.commit=${COMMIT} \
        -X github.com/kagurazakayashi/EvernightLogin.buildTime=${BUILD_TIME}" \
      -o /out/login-server ./cmd/login-server && \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X github.com/kagurazakayashi/EvernightLogin.version=${VERSION} \
        -X github.com/kagurazakayashi/EvernightLogin.commit=${COMMIT} \
        -X github.com/kagurazakayashi/EvernightLogin.buildTime=${BUILD_TIME}" \
      -o /out/loginctl ./cmd/loginctl && \
    go build -trimpath -buildvcs=false \
      -ldflags "-s -w \
        -X github.com/kagurazakayashi/EvernightLogin.version=${VERSION} \
        -X github.com/kagurazakayashi/EvernightLogin.commit=${COMMIT} \
        -X github.com/kagurazakayashi/EvernightLogin.buildTime=${BUILD_TIME}" \
      -o /out/login-backup ./cmd/login-backup

# ---------- 运行阶段 ----------
# 使用 scratch：无 shell、无包管理器，减小攻击面。需要出站 TLS 时复制 CA 证书。
FROM scratch

# 如需 SMTP/Webhook 等出站 TLS，CA 证书是必要运行依赖。
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app

COPY --from=build /out/login-server /app/bin/login-server
COPY --from=build /out/loginctl /app/bin/loginctl
COPY --from=build /out/login-backup /app/bin/login-backup

# 数据/配置/秘密/备份/日志目录：由挂载提供，镜像本身不包含数据与秘密。
# 非 root 数字用户（65532:65532 = nobody:nogroup 在 distroless 中的约定值）。
USER 65532:65532

# 当前版本不会监听端口；装配完成后才对外暴露。
EXPOSE 8080

ENTRYPOINT ["/app/bin/login-server"]
