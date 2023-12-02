# 应用委派管理与客服示例

真正的外部 Module（只导入 `github.com/kagurazakayashi/EvernightLogin` 与
`github.com/kagurazakayashi/EvernightLogin/app`，不导入 `internal/`、不直连数据库），
演示宿主如何用公开 API 管理**两个共享账户但相互隔离的应用**，并接入客服/人工恢复的
安全边界。

## 运行

在本目录（独立 module，`replace ../../`）执行：

```powershell
go build ./...
go run . -self-test -json   # 有界自检（单行 JSON，供 shorttest 核对）
go run . -demo              # 人类可读演示摘要
```

也可以从仓库根运行统一短测试入口：

```powershell
powershell -File scripts\shorttest.ps1 -Scenario app-delegation-support-selftest -TimeoutSeconds 120
```

自检只使用临时 SQLite + 临时主密钥；不监听端口、不访问网络；结束删除临时目录与
构建产物。

## 演示内容

| 场景 | 说明 |
| --- | --- |
| 两个合成应用 | 应用 A/B 共享账户，成员分别加入；应用 B 用户不能获得应用 A 权限 |
| 应用范围 RBAC | 应用 A 登记自定义权限、角色并授权成员；`RBAC().Authorization().Check` 验证 A 允许、B 在 A 拒绝 |
| 委派资格 | `RBAC().Delegations().Grant/Revoke` 签发/撤回应用 A 范围可转授资格；跨应用请求被拒绝 |
| OAuth 客户端 | `OAuthClients().RegisterClient` 登记 confidential 客户端；一次性秘密只在登记响应出现 |
| 业务投影 | 以稳定 `UserID` 关联；`CreatedAt`（账户创建）与 `LinkedAt`（业务首次关联）分离；同步只更新 `UpdatedAt` |
| 客服 | LocalAdmin 没有真实客服会话，`Support().CreateCase` 必须 `ACCESS_DENIED`（三权分离 fail-closed）；示例不伪造客服/审批人身份 |
| 人工恢复 | `ManualRecovery().Policy` 只读报告制度（默认关闭）；示例不自动跳过审批/等待期，不提供绕过路径 |
| 不能越界 | 应用管理员不能全局禁用账户、不能分配 root/系统角色；跨应用/错误版本资料更新被拒绝 |

## 初学者阅读顺序

1. `main.go` 的 `runChecks`：按「打开运行时 → 初始化 root → 合成用户 → 两个应用 →
   成员/权限/角色 → 委派 → OAuth 客户端 → 业务投影 → 客服/人工恢复边界」阅读；
2. 每个 PASS/FAIL 检查都带中文说明；失败时 JSON 的 `checks[].detail` 给出真实错误；
3. 正式客服流程需要真实客服/审批人**独立管理会话**（强认证 + 再次认证），LocalAdmin
   不能替代；本示例刻意不实现伪造审批，避免把演示写成生产旁路。

## 未覆盖/边界（如实）

- 真实 HTTP 页面/前端成员管理界面：本示例聚焦公开 Go 门面；页面接入见
  `examples/custom-pages-profile-sync` 与 `examples/ui-pages`。
- 客服工单完整状态机/人工恢复申请-审批-执行三权分离成功链：需要真实客服用户会话、
  独立审批人与等待期；示例只验证 LocalAdmin 被拒绝与制度只读，成功链由领域测试覆盖。
- 真实邮件/短信交付、非 SQLite、多实例、非 Windows/-race：未测。
- 委派资格的委派上限/数据范围细节由 `internal/delegation` 领域校验；本示例展示
  应用范围与失败路径，不重复实现 Guard。
