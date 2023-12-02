# 应用委派管理与客服示例（步骤 242）

对应可运行外部 Module：[`../../examples/app-delegation-support/`](../../examples/app-delegation-support/README.md)。

## 演示什么

本示例演示宿主如何只用公开包（`login` + `app`）完成：

1. **两个应用共享账户但隔离**：应用 A/B 分别创建、启用、加入成员；应用 B 用户在
   应用 A 内没有权限；
2. **应用范围权限/角色**：应用 A 登记自定义权限与角色并授予成员；
   `RBAC().Authorization().Check` 返回 A 允许、B 在 A 拒绝；
3. **委派资格受范围约束**：`RBAC().Delegations()` 在应用 A 范围签发/撤回可转授
   资格；跨应用请求被领域 Guard 拒绝；
4. **OAuth 客户端凭证**：应用 A 登记 confidential 客户端，一次性秘密只在登记响应
   出现；
5. **业务投影**：按稳定 `UserID` 关联，`CreatedAt`（账户创建）与 `LinkedAt`
   （业务首次关联）分离，同步只改变 `UpdatedAt`；
6. **客服与人工恢复边界**：LocalAdmin 没有真实客服会话时 `Support().CreateCase`
   必须 `ACCESS_DENIED`（三权分离 fail-closed）；`ManualRecovery().Policy` 只读
   报告制度（默认关闭），示例不自动跳过审批/等待期、不伪造客服或审批人身份；
7. **不能越界**：应用管理员不能全局禁用账户、分配 root/系统角色或修改其他应用
   成员；跨应用/错误版本资料更新被拒绝。

## 运行与自检

```powershell
cd examples\app-delegation-support
go build ./...
go run . -self-test -json
go run . -demo
```

从仓库根跑统一短测试入口：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\shorttest.ps1 `
  -Scenario app-delegation-support-selftest -TimeoutSeconds 120
```

自检只写临时 SQLite/主密钥目录，不监听端口、不访问网络；结束删除临时目录与构建
产物。场景驱动 `scripts/shorttest/scenario/app_delegation_support_selftest/`
只使用标准库，核验示例 JSON、检查项与清理结果。

## 未覆盖/前置条件（如实）

- 完整客服工单/人工恢复**成功链**需要真实客服/审批人独立管理会话（强认证 + 再次
  认证 + 等待期），本示例不伪造；成功链由 `internal/support`、`internal/manualrecovery`
  领域测试覆盖。示例验证的是“LocalAdmin 不能替代客服会话”的拒绝边界与制度只读。
- 未覆盖真实邮件/短信交付、页面/前端成员管理界面、非 SQLite、多实例、非 Windows/
  `-race`。页面接入见 `examples/custom-pages-profile-sync` 与 `examples/ui-pages`。
- 委派上限/数据范围细节由 `internal/delegation` 领域 Guard 校验；示例只展示范围
  约束与拒绝路径，不重复实现 Guard。
