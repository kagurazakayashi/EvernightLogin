// 本文件实现 `loginctl diag` 诊断命令：健康/就绪/数据库/证书/邮件。
//
// 脱敏与真实性约定：
//   - 输出只含状态、稳定错误码与脱敏说明，不含数据库凭据、主密钥、私钥或证书
//     私钥材料；证书只展示主体、SAN、有效期与是否即将到期。
//   - 无法判定的检查返回 unverified 并计入失败，不把“未检查”当作通过。
//   - 邮件诊断在 CLI 内没有宿主注入的 mailer/SMTP 配置，明确返回不可用错误码；
//     不发送任何真实邮件，也不伪造发送成功。
package managecli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	login "github.com/kagurazakayashi/EvernightLogin"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// diagCommandUsage 是 diag 组帮助。
const diagCommandUsage = `用法：
  loginctl diag health [--config <file>] [--state-dir <dir>] [--keyring-file <f>] [--json]
  loginctl diag ready  [--config <file>] [--state-dir <dir>] [--keyring-file <f>] [--json]
  loginctl diag database [--config <file>] [--json]
  loginctl diag certificate [--config <file>] [--json]
  loginctl diag mail [--config <file>] [--json]
  loginctl diag all [--config <file>] [--state-dir <dir>] [--keyring-file <f>] [--json]

状态值：ok / degraded / unavailable / not_configured / unverified。
只有 ok 与 not_configured 视为该检查通过；degraded/unavailable/unverified 使命令
以退出码 1 结束。ready 额外要求维护状态可验证且为 normal（未提供 --state-dir 与
--keyring-file 时为 unverified，不假定正常）。`

// diagCheck 是一项诊断结果。
type diagCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	// Code 是稳定错误码（ok 时为空）。
	Code   string `json:"code,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// diagOutput 是诊断命令的输出。
type diagOutput struct {
	// Status 是聚合结论：ok / degraded / unavailable。
	Status string      `json:"status"`
	Checks []diagCheck `json:"checks"`
}

// checkFailed 报告单项检查是否应计入失败。
func checkFailed(check diagCheck) bool {
	return check.Status != "ok" && check.Status != "not_configured"
}

// aggregateStatus 把多项检查聚合为结论。
func aggregateStatus(checks []diagCheck) string {
	status := "ok"
	for _, check := range checks {
		if check.Status == "unavailable" {
			return "unavailable"
		}
		if checkFailed(check) {
			status = "degraded"
		}
	}
	return status
}

// runDiag 分派 diag 子命令。
func (r *runner) runDiag(args []string) int {
	r.usageText = diagCommandUsage
	if len(args) == 0 {
		return r.helpText("diag", diagCommandUsage)
	}
	subcommand, rest := args[0], args[1:]
	r.command = "diag " + subcommand
	switch subcommand {
	case "health", "ready", "database", "certificate", "mail", "all":
		return r.runDiagCheck(subcommand, rest)
	case "help", "-h", "--help":
		return r.helpText("diag", diagCommandUsage)
	default:
		return r.usage("未知的 diag 子命令 %q（可用：health/ready/database/certificate/mail/all）",
			subcommand)
	}
}

// runDiagCheck 执行一项或全部诊断。
func (r *runner) runDiagCheck(subcommand string, args []string) int {
	values, positional, err := parseFlags(args, []flagDef{
		{name: "config", value: true}, {name: "json"},
		{name: "state-dir", value: true}, {name: "keyring-file", value: true},
	})
	if err != nil {
		return r.flagErrorWith(diagCommandUsage, err)
	}
	if len(positional) != 0 {
		return r.usage("diag %s 不接受位置参数", subcommand)
	}
	r.json = boolFlag(values, "json")
	config, exit := r.loadEffectiveConfig(values)
	if exit != ExitOK {
		return exit
	}
	var checks []diagCheck
	switch subcommand {
	case "health":
		checks = append(checks, r.diagConfig(config))
		checks = append(checks, r.diagDatabase(config)...)
		checks = append(checks, r.diagMigration(config)...)
		checks = append(checks, r.diagMaintenance(config, values))
	case "ready":
		checks = append(checks, r.diagConfig(config))
		checks = append(checks, r.diagDatabase(config)...)
		checks = append(checks, r.diagMigration(config)...)
		checks = append(checks, r.diagMaintenanceReady(config, values))
	case "database":
		checks = append(checks, r.diagDatabase(config)...)
		checks = append(checks, r.diagMigration(config)...)
	case "certificate":
		checks = append(checks, r.diagCertificate(config))
	case "mail":
		checks = append(checks, r.diagMail())
	case "all":
		checks = append(checks, r.diagConfig(config))
		checks = append(checks, r.diagDatabase(config)...)
		checks = append(checks, r.diagMigration(config)...)
		checks = append(checks, r.diagMaintenanceReady(config, values))
		checks = append(checks, r.diagCertificate(config))
		checks = append(checks, r.diagMail())
	}
	output := diagOutput{Status: aggregateStatus(checks), Checks: checks}
	failed := false
	for _, check := range checks {
		if checkFailed(check) {
			failed = true
		}
	}
	exitCode := ExitOK
	if failed {
		exitCode = ExitError
	}
	if r.json {
		r.writeEnvelope(jsonEnvelope{OK: exitCode == ExitOK, Command: r.command,
			Data: output})
		return exitCode
	}
	for _, check := range checks {
		line := fmt.Sprintf("[%s] %s", check.Status, check.Name)
		if check.Code != "" {
			line += " " + check.Code
		}
		if check.Detail != "" {
			line += "：" + check.Detail
		}
		fmt.Fprintln(r.stdout, line)
	}
	fmt.Fprintf(r.stdout, "结论：%s\n", output.Status)
	return exitCode
}

// diagConfig 检查配置是否有效（loadEffectiveConfig 已在调用前完成，这里只投影）。
func (r *runner) diagConfig(_ login.Config) diagCheck {
	return diagCheck{Name: "config", Status: "ok", Detail: "配置加载与校验通过"}
}

// diagDatabase 检查数据库是否存在、可打开、可查询与完整性。
func (r *runner) diagDatabase(config login.Config) []diagCheck {
	checks := []diagCheck{}
	store, code := r.tryDatabaseReadOnly(config)
	if code != "" {
		checks = append(checks, diagCheck{Name: "database", Status: "unavailable",
			Code: code, Detail: "数据库文件不存在、不可读或无法打开"})
		if code == "DATABASE_NOT_INITIALIZED" {
			checks = append(checks, diagCheck{Name: "migration", Status: "unverified",
				Code: code, Detail: "数据库尚未初始化，无法读取迁移状态"})
		}
		return checks
	}
	defer func() { _ = store.Close() }()
	if err := store.Ping(r.ctx); err != nil {
		checks = append(checks, diagCheck{Name: "database", Status: "unavailable",
			Code: "DB_UNAVAILABLE", Detail: "数据库 ping 失败"})
		return checks
	}
	checks = append(checks, diagCheck{Name: "database", Status: "ok",
		Detail: "SQLite 连接可用"})
	ok, _, err := quickCheck(r.ctx, store)
	if err != nil {
		checks = append(checks, diagCheck{Name: "database.integrity", Status: "unavailable",
			Code: "DB_UNAVAILABLE", Detail: "完整性检查无法执行"})
		return checks
	}
	if !ok {
		checks = append(checks, diagCheck{Name: "database.integrity", Status: "unavailable",
			Code: "DB_INTEGRITY_FAILED", Detail: "quick_check 未通过"})
		return checks
	}
	checks = append(checks, diagCheck{Name: "database.integrity", Status: "ok",
		Detail: "quick_check 通过"})
	return checks
}

// diagMigration 检查迁移是否全部应用、校验和一致且无失败记录。
func (r *runner) diagMigration(config login.Config) []diagCheck {
	store, code := r.tryDatabaseReadOnly(config)
	if code != "" {
		return []diagCheck{{Name: "migration", Status: "unverified",
			Code: code, Detail: "无法读取迁移状态"}}
	}
	defer func() { _ = store.Close() }()
	report, err := inspectMigrations(r.ctx, store)
	if err != nil {
		return []diagCheck{{Name: "migration", Status: "unavailable",
			Code: "DB_UNAVAILABLE", Detail: "读取迁移记录失败"}}
	}
	var problems []string
	if len(report.Pending) > 0 {
		problems = append(problems, "存在未应用迁移")
	}
	if len(report.UnknownApplied) > 0 {
		problems = append(problems, "存在未知已应用版本（数据库可能来自更新版本）")
	}
	if len(report.ChecksumMismatch) > 0 {
		problems = append(problems, "已应用迁移校验和与内嵌文件不一致")
	}
	if len(report.Failed) > 0 {
		problems = append(problems, "存在未处理的迁移失败记录")
	}
	Name := "migration"
	if len(problems) > 0 {
		return []diagCheck{{Name: Name, Status: "unavailable", Code: "DB_UNAVAILABLE",
			Detail: strings.Join(problems, "；")}}
	}
	return []diagCheck{{Name: Name, Status: "ok",
		Detail: fmt.Sprintf("已应用 %d 个迁移，当前版本 %s", report.AppliedCount,
			report.AppliedVersion)}}
}

// diagMaintenance 检查维护状态（health 用，维护中不算不可用但需报告）。
func (r *runner) diagMaintenance(config login.Config,
	values map[string]string) diagCheck {
	if err := r.ctx.Err(); err != nil {
		return diagCheck{Name: "maintenance", Status: "unverified",
			Code: "CANCELLED", Detail: "已中断"}
	}
	controller, check := r.maintenanceController(config, values)
	if check != nil {
		return *check
	}
	state := controller.State()
	if controller.Missing() {
		return diagCheck{Name: "maintenance", Status: "unverified",
			Code:   "MAINTENANCE_STATE_MISSING",
			Detail: "维护状态文件缺失或未初始化；不能假定服务正常"}
	}
	if state.Mode == maintenance.ModeMaintenance {
		return diagCheck{Name: "maintenance", Status: "degraded",
			Code:   "RESTORE_MAINTENANCE_REQUIRED",
			Detail: "实例处于维护状态，拒绝新写入"}
	}
	if state.Pending != nil {
		return diagCheck{Name: "maintenance", Status: "degraded",
			Code:   "RESTORE_PENDING",
			Detail: "存在未完成的恢复尝试"}
	}
	return diagCheck{Name: "maintenance", Status: "ok", Detail: "维护状态为 normal"}
}

// diagMaintenanceReady 是 ready 用的维护检查：未验证即视为不通过。
func (r *runner) diagMaintenanceReady(config login.Config,
	values map[string]string) diagCheck {
	check := r.diagMaintenance(config, values)
	if check.Status == "unverified" {
		return check
	}
	return check
}

// maintenanceController 构造只读维护状态控制器；不传状态目录/密钥时返回 unverified。
func (r *runner) maintenanceController(config login.Config,
	values map[string]string) (*maintenance.Controller, *diagCheck) {
	stateDir := stringFlag(values, "state-dir")
	keyringFile := stringFlag(values, "keyring-file")
	if stateDir == "" || keyringFile == "" {
		check := diagCheck{Name: "maintenance", Status: "unverified",
			Code:   "MAINTENANCE_STATE_UNVERIFIED",
			Detail: "未提供 --state-dir 与 --keyring-file，无法验证维护状态"}
		return nil, &check
	}
	absoluteStateDir, err := filepath.Abs(stateDir)
	if err != nil {
		check := diagCheck{Name: "maintenance", Status: "unverified",
			Code: "MAINTENANCE_STATE_UNVERIFIED", Detail: "状态目录路径无效"}
		return nil, &check
	}
	if info, err := os.Stat(absoluteStateDir); err != nil || !info.IsDir() {
		check := diagCheck{Name: "maintenance", Status: "unverified",
			Code: "MAINTENANCE_STATE_MISSING", Detail: "状态目录不存在"}
		return nil, &check
	}
	databasePath, exit := r.dataPath(config)
	if exit != ExitOK {
		check := diagCheck{Name: "maintenance", Status: "unverified",
			Code: "CONFIG_INVALID", Detail: "无法确定数据库路径"}
		return nil, &check
	}
	provider, err := secrets.NewFileProvider(strings.TrimSpace(keyringFile))
	if err != nil {
		check := diagCheck{Name: "maintenance", Status: "unverified",
			Code: "KEYRING_UNAVAILABLE", Detail: "主密钥环文件路径无效"}
		return nil, &check
	}
	controller, err := maintenance.New(maintenance.Options{StateDir: absoluteStateDir,
		DatabasePath: databasePath, Keyring: provider, Now: r.options.Now})
	if err != nil {
		check := diagCheck{Name: "maintenance", Status: "unavailable",
			Code:   "MAINTENANCE_STATE_INVALID",
			Detail: "维护状态无法通过完整性校验（密钥不匹配或文件损坏）"}
		return nil, &check
	}
	return controller, nil
}

// diagCertificate 检查本地 TLS 证书链与私钥匹配、有效期与到期告警。
func (r *runner) diagCertificate(config login.Config) diagCheck {
	if config.Server.TLSPFXFile != "" {
		return diagCheck{Name: "certificate", Status: "unavailable",
			Code:   "CERT_PFX_UNSUPPORTED",
			Detail: "CLI 证书诊断暂不解析 PFX/P12；请改用 PEM 或人工核验"}
	}
	certFiles := config.Server.TLSCertFiles
	keyFiles := config.Server.TLSKeyFiles
	if len(certFiles) == 0 && len(keyFiles) == 0 {
		return diagCheck{Name: "certificate", Status: "not_configured",
			Detail: "未配置本地 TLS 证书（可能由受信任反向代理终止 TLS）"}
	}
	if len(certFiles) != len(keyFiles) {
		return diagCheck{Name: "certificate", Status: "unavailable",
			Code: "CERT_CONFIG_INVALID", Detail: "证书文件与私钥文件数量不一致"}
	}
	now := r.options.Now()
	warningDays := config.Server.TLSExpiryWarningDays
	if warningDays == 0 {
		warningDays = 30
	}
	var summary []string
	for index := range certFiles {
		certificate, err := loadLeafCertificate(certFiles[index])
		if err != nil {
			return diagCheck{Name: "certificate", Status: "unavailable",
				Code: "CERT_INVALID", Detail: fmt.Sprintf("第 %d 个证书无法解析", index+1)}
		}
		if err := checkCertificateTime(certificate, now); err != nil {
			return diagCheck{Name: "certificate", Status: "unavailable",
				Code: "CERT_EXPIRED", Detail: err.Error()}
		}
		if err := matchPrivateKey(keyFiles[index], certificate); err != nil {
			return diagCheck{Name: "certificate", Status: "unavailable",
				Code: "CERT_KEY_MISMATCH", Detail: err.Error()}
		}
		days := int(certificate.NotAfter.Sub(now).Hours() / 24)
		state := "有效"
		if days < warningDays {
			state = "即将到期"
		}
		summary = append(summary, fmt.Sprintf("%s：主体 %q，到期 %s（剩余 %d 天，%s）",
			filepath.Base(certFiles[index]), certificate.Subject.CommonName,
			certificate.NotAfter.UTC().Format(time.RFC3339), days, state))
	}
	return diagCheck{Name: "certificate", Status: "ok",
		Detail: strings.Join(summary, "；")}
}

// loadLeafCertificate 读取 PEM 证书链的第一张证书（叶证书）。
func loadLeafCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}
	return nil, errors.New("未找到 CERTIFICATE PEM 块")
}

// checkCertificateTime 只校验有效期；不校验用途/主机名（那需要实际连接协商）。
func checkCertificateTime(certificate *x509.Certificate, now time.Time) error {
	if now.Before(certificate.NotBefore) {
		return fmt.Errorf("证书尚未生效（生效时间 %s）",
			certificate.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(certificate.NotAfter) {
		return fmt.Errorf("证书已过期（到期时间 %s）",
			certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

// matchPrivateKey 校验私钥文件与证书公钥匹配；错误信息不含私钥内容。
func matchPrivateKey(path string, certificate *x509.Certificate) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return errors.New("私钥文件无法读取")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("私钥文件不是 PEM 格式")
	}
	var public any
	switch block.Type {
	case "PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return errors.New("私钥文件无法解析")
		}
		public = publicKeyOf(parsed)
	case "RSA PRIVATE KEY":
		parsed, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
		if parseErr != nil {
			return errors.New("私钥文件无法解析")
		}
		public = &parsed.PublicKey
	case "EC PRIVATE KEY":
		parsed, parseErr := x509.ParseECPrivateKey(block.Bytes)
		if parseErr != nil {
			return errors.New("私钥文件无法解析")
		}
		public = &parsed.PublicKey
	default:
		return errors.New("不支持的私钥 PEM 类型")
	}
	if public == nil {
		return errors.New("私钥文件不含可用于比对的公钥")
	}
	certificatePublic := certificate.PublicKey
	if !publicKeysEqual(public, certificatePublic) {
		return errors.New("私钥与证书公钥不匹配")
	}
	return nil
}

// publicKeyOf 返回私钥对象的公钥部分。
func publicKeyOf(private any) any {
	switch key := private.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public()
	default:
		return nil
	}
}

// publicKeysEqual 用 PKIX DER 编码比较公钥；编码失败视为不匹配（fail-closed）。
func publicKeysEqual(left, right any) bool {
	leftDER, err := x509.MarshalPKIXPublicKey(left)
	if err != nil {
		return false
	}
	rightDER, err := x509.MarshalPKIXPublicKey(right)
	if err != nil {
		return false
	}
	return string(leftDER) == string(rightDER)
}

// diagMail 报告邮件诊断不可用：CLI 没有宿主注入的 mailer/SMTP 配置，不能伪造成功。
func (r *runner) diagMail() diagCheck {
	return diagCheck{Name: "mail", Status: "unavailable",
		Code: "MAIL_DIAGNOSTICS_UNAVAILABLE",
		Detail: "CLI 未装配发件通道：邮件/通知配置由宿主注入，本命令不会发送真实邮件；" +
			"请在宿主装配后用受控本地捕获器验证"}
}
