package login

import (
	"strings"
	"testing"
)

// TestRegistrationConfigDefaults 验证自主注册默认关闭、邮箱非必需、无默认角色。
func TestRegistrationConfigDefaults(t *testing.T) {
	cfg := Default()
	if cfg.Registration.Enabled || cfg.Registration.RequireReview ||
		cfg.Registration.RequireEmailVerification {
		t.Errorf("注册策略默认值应保守关闭：%+v", cfg.Registration)
	}
	if len(cfg.Registration.DefaultRoleIDs) != 0 {
		t.Errorf("默认不应配置默认角色：%v", cfg.Registration.DefaultRoleIDs)
	}
	diagnostic := cfg.Diagnostic()
	for _, field := range []string{"registration.enabled", "registration.require_review",
		"registration.require_email_verification", "registration.default_role_ids"} {
		if !strings.Contains(diagnostic, field+" = ") {
			t.Errorf("脱敏诊断缺少注册字段 %s", field)
		}
	}
}

// TestRegistrationConfigYAMLAndEnv 验证 YAML 与固定环境变量都能加载注册策略。
func TestRegistrationConfigYAMLAndEnv(t *testing.T) {
	cfg := mustLoad(t, LoadOptions{YAML: yamlBytes(`registration:
  enabled: true
  require_review: true
  require_email_verification: true
  default_role_ids:
    - role_default_member
    - role_default_viewer
`)})
	if !cfg.Registration.Enabled || !cfg.Registration.RequireReview ||
		!cfg.Registration.RequireEmailVerification {
		t.Errorf("YAML 注册策略未生效：%+v", cfg.Registration)
	}
	wantRoles := []string{"role_default_member", "role_default_viewer"}
	if len(cfg.Registration.DefaultRoleIDs) != len(wantRoles) {
		t.Fatalf("默认角色 = %v", cfg.Registration.DefaultRoleIDs)
	}
	for index, role := range wantRoles {
		if cfg.Registration.DefaultRoleIDs[index] != role {
			t.Errorf("默认角色[%d] = %q，期望 %q", index, cfg.Registration.DefaultRoleIDs[index], role)
		}
	}

	envCfg := mustLoad(t, LoadOptions{LookupEnv: envLookup(map[string]string{
		envRegistrationEnabled: "true",
		envRegistrationReview:  "true",
		envRegistrationEmail:   "true",
		envRegistrationRoles:   "role_a, role_b",
	})})
	if !envCfg.Registration.Enabled || !envCfg.Registration.RequireReview ||
		!envCfg.Registration.RequireEmailVerification {
		t.Errorf("环境变量注册策略未生效：%+v", envCfg.Registration)
	}
	if len(envCfg.Registration.DefaultRoleIDs) != 2 ||
		envCfg.Registration.DefaultRoleIDs[0] != "role_a" ||
		envCfg.Registration.DefaultRoleIDs[1] != "role_b" {
		t.Errorf("环境变量默认角色 = %v", envCfg.Registration.DefaultRoleIDs)
	}
}

// TestRegistrationConfigOverridesAndValidation 验证显式覆盖与非法默认角色策略。
func TestRegistrationConfigOverridesAndValidation(t *testing.T) {
	cfg := mustLoad(t, LoadOptions{Overrides: &Overrides{Registration: RegistrationOverrides{
		Enabled:                  Ptr(true),
		RequireReview:            Ptr(false),
		RequireEmailVerification: Ptr(false),
		DefaultRoleIDs:           &[]string{"role_system_user"},
	}}})
	if !cfg.Registration.Enabled || len(cfg.Registration.DefaultRoleIDs) != 1 {
		t.Errorf("显式注册覆盖未生效：%+v", cfg.Registration)
	}
	// 未知 YAML 字段（例如客户端伪造的注册字段）必须被结构检查拒绝。
	errs := loadErrors(t, LoadOptions{YAML: yamlBytes("registration:\n  is_root: true\n")})
	if len(errs) == 0 {
		t.Fatal("注册段未知字段应被拒绝")
	}
	invalid := [][]string{
		{"bad role id!"},
		{"same_role", "same_role"},
		{""},
	}
	for _, roles := range invalid {
		errs := loadErrors(t, LoadOptions{YAML: yamlBytes(
			"registration:\n  default_role_ids:\n" + yamlRoleList(roles))})
		if findConfigError(errs, ConfigErrorValue, "registration.default_role_ids") == nil {
			t.Errorf("非法默认角色 %v 应报错：%v", roles, errs)
		}
	}
	tooMany := make([]string, MaxRegistrationDefaultRoles+1)
	for index := range tooMany {
		tooMany[index] = "role_" + strings.Repeat("a", index+1)
	}
	errs = loadErrors(t, LoadOptions{YAML: yamlBytes(
		"registration:\n  default_role_ids:\n" + yamlRoleList(tooMany))})
	if findConfigError(errs, ConfigErrorValue, "registration.default_role_ids") == nil {
		t.Errorf("默认角色过多应报错：%v", errs)
	}
}

// yamlRoleList 生成 YAML 列表文本。
func yamlRoleList(roles []string) string {
	var builder strings.Builder
	for _, role := range roles {
		builder.WriteString("    - ")
		builder.WriteString(role)
		builder.WriteString("\n")
	}
	return builder.String()
}
