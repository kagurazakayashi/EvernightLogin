# 应用受限客服 API 示例

独立 Go module，只使用标准库，不导入 EvernightLogin 的 `internal/` 包。

1. 由业务应用以真实 OAuth 授权码 + PKCE 流程让客服用户登录；`client_id` 必须是该
   应用，`aud` 必须包含 `urn:evernight:app-support`（或实例配置的
   `--app-support-audience`）。
2. 取得用户委托 Access Token 后设置 `APPSUPPORT_ACCESS_TOKEN`（或 `-access-token`）。
3. 运行示例：

```powershell
$env:APPSUPPORT_ACCESS_TOKEN = "<access token>"
go run . -command list
go run . -command create -target-user-id usr_... -reason "用户在应用中提交人工核验"
go run . -command get -case-id sup_...
```

示例仅调用应用客服 API，不显示密码、MFA、恢复代码、恢复链接或验证码；`approve` 不在
示例中提供，因为全局恢复审批/执行必须由系统 `recovery.approve` 完成。
