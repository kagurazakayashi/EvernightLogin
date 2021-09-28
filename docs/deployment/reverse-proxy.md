# 反向代理与子路径部署

本文说明 login 在反向代理后、以及部署在固定路径前缀（子路径）下的配置边界。样例见
`samples/nginx-login.conf`、`samples/Caddyfile`。

## 1. 两种 TLS 拓扑（二选一，不能同时启用）

### A. 本地 TLS（login 自己终结 HTTPS）

- 配置 `server.tls_cert_files` + `server.tls_key_files`（一一对应），或 `server.tls_pfx_file`
  + 秘密来源 `secrets.tls_pfx_password`。
- 私钥必须是普通文件且权限受限（非 Windows：仅所有者可读写）。
- 启用本地 TLS 后 `server.public_base_url` 必须是 `https://`。
- `server.tls_ca_file` 只能在 PEM 模式下追加中间证书；PFX 模式禁止。
- `server.tls_terminating_proxy` 必须为 false（与本地 TLS 互斥）。

### B. TLS 终止代理（明文监听只在受信任代理后端）

必须同时满足，否则构造监听组件时拒绝启动：

- `server.tls_terminating_proxy: true`（显式声明，不是自动推断）；
- `server.trusted_proxies` 非空，且只包含该代理的 IP/CIDR；
- `server.public_base_url` 为 `https://...`；
- 建议仍然把 `server.listen_addr` 设为回环地址，仅由本机代理访问。

## 2. 转发头与真实客户端地址

- 只有**直连对端**命中 `server.trusted_proxies` 时才会解析 `X-Forwarded-For`/`Forwarded`。
- 解析从右向左跳过可信代理，取第一个不可信地址；转发链超过 16 跳或超过 2 KiB、
  任一条目非法时回退为直连地址。
- 未配置可信代理时**完全忽略**转发头；`X-Real-IP`、`X-Client-IP` 等非标准头一律不信任。
- 必须让代理传递 `X-Forwarded-Proto` 与正确 Host；login 不会从这些头推导用于签发身份的
  地址（公开地址/OIDC Issuer/WebAuthn RP ID 都是独立显式配置）。
- 访问日志中的客户端 IP 与限流都使用同一可信解析结果；伪造 XFF 不会改变它。

## 3. 路径前缀与子路径

- `server.path_prefix` 是固定前缀（空或 `/segment(/segment)*`，不能以 `/` 结尾）。配置后
  所有路由都挂在 `${prefix}/...`；前缀不匹配的请求一律 404，不做清理重写。
- `server.public_base_url` 带路径时，其路径**必须与** `server.path_prefix` 一致；
  独立服务启动时还会与实际 Handler 前缀核对。
- 反向代理**不要剥离前缀**（不要用会去掉 `/login` 的 rewrite），否则后端收到的路径不在
  固定前缀下，会被 404。应在同一前缀下转发。
- `server.allowed_hosts` 用于显式允许的 Host；配置了 `public_base_url` 时其主机也要被接受。
  使用未配置的 Host 会被拒绝（421），不要用通配域名绕过。

## 4. 样例：Nginx（TLS 终止 + 子路径 `/login/`）

完整样例见 `samples/nginx-login.conf`。关键点：

```nginx
location /login/ {
    # 不剥离前缀：proxy_pass 不带 URI 部分会保留原始路径
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
    proxy_send_timeout 60s;
}
```

对应配置片段：

```yaml
server:
  listen_addr: "127.0.0.1:8080"
  public_base_url: "https://login.example.com/login"
  path_prefix: "/login"
  trusted_proxies:
    - "127.0.0.1/32"
    - "10.0.0.0/8"
  tls_terminating_proxy: true
```

## 5. 样例：Caddy（自动证书、根路径）

```caddyfile
login.example.com {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Forwarded-For {remote_host}
    }
}
```

对应 `public_base_url: "https://login.example.com"`、`path_prefix: ""`、
`trusted_proxies` 填 Caddy 所在主机 IP（同机部署时为 `127.0.0.1/32`）。

## 6. IIS / ARR 提示

- 安装 ARR + URL Rewrite，启用代理，把 `/login` 转发到 `http://127.0.0.1:8080`，**保留
  原始路径**，不要启用会剥离前缀的 rewrite。
- 在 ARR 服务器变量中允许 `HTTP_X_FORWARDED_FOR`/`HTTP_X_FORWARDED_PROTO` 转发；
  `trusted_proxies` 只填 IIS 主机 IP。
- IIS 需要 TLS 证书绑定；不要在 IIS 与后端之间再放明文公网监听。

## 7. 上线校验清单

- [ ] 直连伪造 `X-Forwarded-For` 时，访问日志与限流仍按真实直连地址处理。
- [ ] 前缀后的登录页、静态资源、表单 POST、CSRF、回调地址都工作；`/login`（无尾斜杠）
      行为符合预期。
- [ ] 错误 Host 返回拒绝（421）；公开地址与证书域名一致。
- [ ] 后端只监听回环或受信网段，端口不对公网开放。
- [ ] 代理不缓存鉴权页面与 Token 响应（`Cache-Control: no-store` 由后端设置，
      代理不得改写为可缓存）。
- [ ] HSTS 只在确认全站 HTTPS 后启用；不要在混合 HTTP 环境启用 HSTS。

## 8. 已知限制

- 反向代理配置样例**未做真实代理联调**（本项目约定不部署运行真实代理）；样例用于表达
  配置契约，上线前必须在目标环境自行验证。
- 不支持 PROXY protocol；负载均衡健康检查与后端健康端点需按实际装配核对。
