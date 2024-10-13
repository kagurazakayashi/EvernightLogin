package e2e

// 步骤 274 终稿：本文件只保留**当前阶段客观不可完成**的最新未测项（显式 Skip+条件）。
// 已被真实入口矩阵覆盖的项已从 Skip 清单移除，证据见对应 matrix_*_test.go：
//   - 258/259 HTTP 管理 API 与 CLI 真实二进制：matrix_http_test.go / matrix_cli_test.go；
//   - 251 ResourceID 非授权资源：matrix_governance_test.go（TestMatrixResourceIDScope）；
//   - 262/263 游标绑定：matrix_governance_test.go（TestMatrixAuditCursorBinding，
//     管理 API 投递记录游标绑定/offset 拒绝由 HTTP 矩阵覆盖权限与稳定错误）；
//   - 268 OpenAPI 契约与秘密扫描：matrix_governance_test.go（TestMatrixOpenAPIContractNoSecrets）；
//   - 265/266 通知真实投递终态：matrix_mail_recovery_test.go
//     （TestMatrixNotificationDeliveryTerminalState，本机 SMTP 捕获 + succeeded 终态）；
//   - 253 强认证完成窗口：matrix_http_test.go 末段强认证窗口过期断言；
//   - 250 部分（重置后 pending 找回同事务取消）：matrix_password_reset_test.go。

import "testing"

// TestPendingMailSearchPrivacy 264 Mail 搜索索引隐私属于 EvernightMail 独立子模块：
// 264 已在其模块内验证；父模块 e2e 不导入子模块实现，不重复第二套测试。
// 步骤 300 的证据入口：scripts/r12-300-acceptance.ps1 的
// mail-submodule-search-privacy 套件在父 gitlink 固定的 Mail 提交上运行其搜索/隐私
// 定向测试，并把命令/输出尾部/退出码写入 300 机器可读汇总（子模块证据引用）。
func TestPendingMailSearchPrivacy(t *testing.T) {
	t.Skip("EvernightMail 独立子模块：父 e2e 不重复实现；300 由 r12-300-acceptance.ps1 的 mail-submodule-search-privacy 套件记录子模块证据")
}
