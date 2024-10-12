# 配置字段机器参考（58 个字段）

> **语义权威不在本页**：字段含义、默认值、校验规则、覆盖优先级与迁移说明见 [../guide/configuration.md](../guide/configuration.md)（由 `verify-docs` 逐字段核对）。本页只提供机器元数据（字段/环境变量/生效分类/秘密标记），由 `config.Fields()` 生成。

配置来源优先级：**内置默认 < YAML < 环境变量 < 显式代码覆盖**；未知字段、重复键、类型错误、越界或危险组合会拒绝启动。

## 1. 生效分类

- **重启生效**：修改后必须重启进程；热重载不会改变当前有效值。
- **重载生效**：宿主触发重新加载后生效；仍需服务端校验与失败回退（失败保留最后有效状态）。
- **秘密字段**：诊断/日志只显示“已配置/未配置”等脱敏状态；秘密只通过 `{env: NAME}` 或 `{file: 路径}` 引用，不写明文 YAML。
- 环境变量命名为 `LOGIN_` + 点分路径大写并用下划线连接（如 `LOGIN_DATABASE_PATH`）。

## 2. 字段表（58 个）

| 字段 | 环境变量 | 生效分类 | 秘密 |
|---|---|---|---|
| `server.listen_addr` | `LOGIN_SERVER_LISTEN_ADDR` | 重启生效 | 否 |
| `server.extra_listen_addrs` | `LOGIN_SERVER_EXTRA_LISTEN_ADDRS` | 重启生效 | 否 |
| `server.public_base_url` | `LOGIN_SERVER_PUBLIC_BASE_URL` | 重启生效 | 否 |
| `server.path_prefix` | `LOGIN_SERVER_PATH_PREFIX` | 重启生效 | 否 |
| `server.allowed_hosts` | `LOGIN_SERVER_ALLOWED_HOSTS` | 重启生效 | 否 |
| `server.trusted_proxies` | `LOGIN_SERVER_TRUSTED_PROXIES` | 重启生效 | 否 |
| `server.tls_terminating_proxy` | `LOGIN_SERVER_TLS_TERMINATING_PROXY` | 重启生效 | 否 |
| `server.tls_cert_files` | `LOGIN_SERVER_TLS_CERT_FILES` | 重启生效 | 否 |
| `server.tls_key_files` | `LOGIN_SERVER_TLS_KEY_FILES` | 重启生效 | 否 |
| `server.tls_ca_file` | `LOGIN_SERVER_TLS_CA_FILE` | 重启生效 | 否 |
| `server.tls_pfx_file` | `LOGIN_SERVER_TLS_PFX_FILE` | 重启生效 | 否 |
| `server.tls_expiry_warning_days` | `LOGIN_SERVER_TLS_EXPIRY_WARNING_DAYS` | 重启生效 | 否 |
| `server.tls_client_auth` | `LOGIN_SERVER_TLS_CLIENT_AUTH` | 重启生效 | 否 |
| `server.tls_client_ca_files` | `LOGIN_SERVER_TLS_CLIENT_CA_FILES` | 重启生效 | 否 |
| `server.tls_client_identities` | `LOGIN_SERVER_TLS_CLIENT_IDENTITIES` | 重启生效 | 否 |
| `server.shutdown_timeout_seconds` | `LOGIN_SERVER_SHUTDOWN_TIMEOUT_SECONDS` | 重载生效 | 否 |
| `logging.level` | `LOGIN_LOGGING_LEVEL` | 重载生效 | 否 |
| `logging.format` | `LOGIN_LOGGING_FORMAT` | 重载生效 | 否 |
| `database.driver` | `LOGIN_DATABASE_DRIVER` | 重启生效 | 否 |
| `database.path` | `LOGIN_DATABASE_PATH` | 重启生效 | 否 |
| `database.wal` | `LOGIN_DATABASE_WAL` | 重启生效 | 否 |
| `database.busy_timeout_ms` | `LOGIN_DATABASE_BUSY_TIMEOUT_MS` | 重启生效 | 否 |
| `database.host` | `LOGIN_DATABASE_HOST` | 重启生效 | 否 |
| `database.port` | `LOGIN_DATABASE_PORT` | 重启生效 | 否 |
| `database.username` | `LOGIN_DATABASE_USERNAME` | 重启生效 | 否 |
| `database.password` | `LOGIN_DATABASE_PASSWORD` | 重启生效 | 是 |
| `database.name` | `LOGIN_DATABASE_NAME` | 重启生效 | 否 |
| `database.tls_mode` | `LOGIN_DATABASE_TLS_MODE` | 重启生效 | 否 |
| `registration.enabled` | `LOGIN_REGISTRATION_ENABLED` | 重启生效 | 否 |
| `registration.require_review` | `LOGIN_REGISTRATION_REQUIRE_REVIEW` | 重启生效 | 否 |
| `registration.require_email_verification` | `LOGIN_REGISTRATION_REQUIRE_EMAIL_VERIFICATION` | 重启生效 | 否 |
| `registration.default_role_ids` | `LOGIN_REGISTRATION_DEFAULT_ROLE_IDS` | 重启生效 | 否 |
| `passkey.enabled` | `LOGIN_PASSKEY_ENABLED` | 重启生效 | 否 |
| `passkey.rp_id` | `LOGIN_PASSKEY_RP_ID` | 重启生效 | 否 |
| `passkey.rp_display_name` | `LOGIN_PASSKEY_RP_DISPLAY_NAME` | 重启生效 | 否 |
| `passkey.allowed_origins` | `LOGIN_PASSKEY_ALLOWED_ORIGINS` | 重启生效 | 否 |
| `passkey.user_verification` | `LOGIN_PASSKEY_USER_VERIFICATION` | 重启生效 | 否 |
| `app_qr_login.enabled` | `LOGIN_APP_QR_LOGIN_ENABLED` | 重启生效 | 否 |
| `app_qr_login.allowed_client_ids` | `LOGIN_APP_QR_LOGIN_ALLOWED_CLIENT_IDS` | 重启生效 | 否 |
| `app_qr_login.request_ttl_seconds` | `LOGIN_APP_QR_LOGIN_REQUEST_TTL_SECONDS` | 重启生效 | 否 |
| `app_qr_login.claim_interval_seconds` | `LOGIN_APP_QR_LOGIN_CLAIM_INTERVAL_SECONDS` | 重启生效 | 否 |
| `protocol.device_code_enabled` | `LOGIN_PROTOCOL_DEVICE_CODE_ENABLED` | 重启生效 | 否 |
| `secrets.master_key` | `LOGIN_SECRETS_MASTER_KEY` | 重启生效 | 是 |
| `secrets.tls_pfx_password` | `LOGIN_SECRETS_TLS_PFX_PASSWORD` | 重启生效 | 是 |
| `mail.enabled` | `LOGIN_MAIL_ENABLED` | 重启生效 | 否 |
| `mail.smtp.addr` | `LOGIN_MAIL_SMTP_ADDR` | 重启生效 | 否 |
| `mail.smtp.host` | `LOGIN_MAIL_SMTP_HOST` | 重启生效 | 否 |
| `mail.smtp.tls_mode` | `LOGIN_MAIL_SMTP_TLS_MODE` | 重启生效 | 否 |
| `mail.smtp.trusted_roots` | `LOGIN_MAIL_SMTP_TRUSTED_ROOTS` | 重启生效 | 否 |
| `mail.smtp.username` | `LOGIN_MAIL_SMTP_USERNAME` | 重启生效 | 否 |
| `mail.smtp.password` | `LOGIN_MAIL_SMTP_PASSWORD` | 重启生效 | 是 |
| `mail.smtp.timeout_seconds` | `LOGIN_MAIL_SMTP_TIMEOUT_SECONDS` | 重启生效 | 否 |
| `mail.smtp.allow_plaintext_local` | `LOGIN_MAIL_SMTP_ALLOW_PLAINTEXT_LOCAL` | 重启生效 | 否 |
| `mail.from.address` | `LOGIN_MAIL_FROM_ADDRESS` | 重启生效 | 否 |
| `mail.from.name` | `LOGIN_MAIL_FROM_NAME` | 重启生效 | 否 |
| `mail.app_name` | `LOGIN_MAIL_APP_NAME` | 重启生效 | 否 |
| `mail.delivery.max_attempts` | `LOGIN_MAIL_DELIVERY_MAX_ATTEMPTS` | 重启生效 | 否 |
| `mail.delivery.timeout_seconds` | `LOGIN_MAIL_DELIVERY_TIMEOUT_SECONDS` | 重启生效 | 否 |

## 3. 最小可编译示例

```go
// ExampleConfigLookup 展示如何查询配置字段元数据（字段/环境变量/生效分类/秘密标记）。
// 字段语义、默认值与校验规则以 docs/guide/configuration.md 为唯一权威。
func ExampleConfigLookup() {
	field, ok := config.LookupField("database.path")
	if !ok {
		return
	}
	_ = field.Field
	_ = field.Env
	_ = field.Class
	_ = field.Secret
}
```

## 4. 相关入口

- 完整语义与默认值：[../guide/configuration.md](../guide/configuration.md)
- 配置校验 CLI：[../guide/root-cli.md](../guide/root-cli.md)（`loginctl config validate`）
- 配置管理与版本冲突（管理员）：[../guide/configuration.md](../guide/configuration.md) 与设置权限说明。
