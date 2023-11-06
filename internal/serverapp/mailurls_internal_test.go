package serverapp

import (
	"strings"
	"testing"

	login "github.com/kagurazakayashi/EvernightLogin"
)

// mailURLExpect 是一组合法组合的期望值。
type mailURLExpect struct {
	name    string
	baseURL string
	prefix  string
	verify  string
	change  string
	reset   string
	support string
}

// TestBuildMailURLs 覆盖 buildMailURLs 的合法组合与防御性拒绝：
//   - mail 关闭返回零值；
//   - 启用时要求绝对 http(s) 公开地址，并拒绝 userinfo/query/fragment/非法 prefix；
//   - 邮件页面基址由“解析后的 URL 路径 + 规范化 path_prefix”统一拼接，不重复前缀。
//
// 注意：部分组合（如 base 无路径 + 非空 prefix、base 路径 ≠ prefix）会被
// Config.Validate 明确拒绝，不属于可利用缺陷；这里单独验证构建函数的幂等去重
// 行为只作为健壮性兜底（见 TestMailURLConfigCombinations）。
func TestBuildMailURLs(t *testing.T) {
	disabled := login.Default()
	if urls, err := buildMailURLs(disabled); err != nil || urls.VerifyEmail != "" {
		t.Fatalf("mail disabled 应返回零值: %+v %v", urls, err)
	}

	invalid := login.Default()
	invalid.Mail.Enabled = true
	if _, err := buildMailURLs(invalid); err == nil {
		t.Fatal("mail enabled 缺少 public_base_url 应失败")
	}
	invalid.Server.PublicBaseURL = "login.example.test"
	if _, err := buildMailURLs(invalid); err == nil {
		t.Fatal("相对/缺少 scheme 的公开地址应失败")
	}
	for _, base := range []string{
		"https://user:pass@login.example.test",
		"https://login.example.test?x=1",
		"https://login.example.test/#fragment",
	} {
		cfg := login.Default()
		cfg.Mail.Enabled = true
		cfg.Server.PublicBaseURL = base
		if _, err := buildMailURLs(cfg); err == nil {
			t.Fatalf("公开地址 %q 应被拒绝（不能生成含糊链接）", base)
		}
	}
	badPrefix := login.Default()
	badPrefix.Mail.Enabled = true
	badPrefix.Server.PublicBaseURL = "https://login.example.test/base"
	badPrefix.Server.PathPrefix = "/base/"
	if _, err := buildMailURLs(badPrefix); err == nil {
		t.Fatal("非法 path_prefix 应被 buildMailURLs 拒绝")
	}

	cases := []mailURLExpect{
		{
			name: "根路径部署", baseURL: "https://login.example.test", prefix: "",
			verify:  "https://login.example.test/email/verify",
			change:  "https://login.example.test/email/change/verify",
			reset:   "https://login.example.test/login/reset-password",
			support: "https://login.example.test/support",
		},
		{
			name: "根路径但公开地址带路径", baseURL: "https://login.example.test/app", prefix: "",
			verify:  "https://login.example.test/app/email/verify",
			change:  "https://login.example.test/app/email/change/verify",
			reset:   "https://login.example.test/app/login/reset-password",
			support: "https://login.example.test/app/support",
		},
		{
			name:    "公开地址路径等于 path_prefix（不重复前缀）",
			baseURL: "https://login.example.test/base", prefix: "/base",
			verify:  "https://login.example.test/base/email/verify",
			change:  "https://login.example.test/base/email/change/verify",
			reset:   "https://login.example.test/base/login/reset-password",
			support: "https://login.example.test/base/support",
		},
		{
			// 防御性：/parent/base 以完整路径段包含 /base，不得再追加一次。
			name:    "带父路径的公开地址（防重复前缀）",
			baseURL: "https://login.example.test/parent/base", prefix: "/base",
			verify:  "https://login.example.test/parent/base/email/verify",
			change:  "https://login.example.test/parent/base/email/change/verify",
			reset:   "https://login.example.test/parent/base/login/reset-password",
			support: "https://login.example.test/parent/base/support",
		},
		{
			// 防御性：base 无路径但函数被直接调用时按 prefix 拼接（配置校验会先拒绝）。
			name:    "公开地址无路径（防御性补 prefix）",
			baseURL: "https://login.example.test", prefix: "/base",
			verify:  "https://login.example.test/base/email/verify",
			change:  "https://login.example.test/base/email/change/verify",
			reset:   "https://login.example.test/base/login/reset-password",
			support: "https://login.example.test/base/support",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := login.Default()
			cfg.Mail.Enabled = true
			cfg.Server.PublicBaseURL = testCase.baseURL
			cfg.Server.PathPrefix = testCase.prefix
			urls, err := buildMailURLs(cfg)
			if err != nil {
				t.Fatalf("合法组合失败: %v", err)
			}
			if urls.VerifyEmail != testCase.verify || urls.ChangeEmail != testCase.change ||
				urls.PasswordReset != testCase.reset || urls.Support != testCase.support {
				t.Fatalf("生成地址 = %+v，期望 verify=%q change=%q reset=%q support=%q",
					urls, testCase.verify, testCase.change, testCase.reset, testCase.support)
			}
			// 所有邮件链接必须由同一公开基址派生，且不以重复的 "/base/base" 出现。
			for _, generated := range []string{urls.VerifyEmail, urls.ChangeEmail,
				urls.PasswordReset, urls.Support} {
				if !strings.HasPrefix(generated, "https://login.example.test/") {
					t.Fatalf("链接不在公开基址下: %q", generated)
				}
				if testCase.prefix != "" &&
					strings.Contains(generated, testCase.prefix+testCase.prefix+"/") {
					t.Fatalf("链接出现重复前缀: %q", generated)
				}
			}
		})
	}
}

// validMailConfigForURLTest 返回带合法邮件传输字段的配置，使 Config.Validate 的
// 失败只来自 public_base_url × path_prefix 组合本身。
func validMailConfigForURLTest() login.Config {
	cfg := login.Default()
	cfg.Mail.Enabled = true
	cfg.Mail.SMTP.Addr = "127.0.0.1:2525"
	// 用 starttls 使配置校验不依赖明文回环组合；该合法组合当前存在既有校验缺陷，
	// 已由 211 发现并移交步骤 212（config 迁移）修复，见 step211-dev.md。
	cfg.Mail.SMTP.TLSMode = "starttls"
	cfg.Mail.SMTP.TimeoutSeconds = 10
	cfg.Mail.From.Address = "no-reply@example.test"
	cfg.Mail.Delivery.MaxAttempts = 2
	cfg.Mail.Delivery.TimeoutSeconds = 60
	return cfg
}

// TestMailURLConfigCombinations 覆盖“邮件公开地址 × path_prefix”的配置级合法/非法
// 组合：合法组合通过 Config.Validate 且可生成一致邮件链接；非法组合在启动校验被
// 拒绝，不能被当作可利用缺陷（例如公开地址路径与真实路由前缀不一致）。
func TestMailURLConfigCombinations(t *testing.T) {
	valid := []struct {
		name    string
		baseURL string
		prefix  string
	}{
		{"根路径", "https://login.example.test", ""},
		{"根路径带公开子路径", "https://login.example.test/app", ""},
		{"公开路径等于固定前缀", "https://login.example.test/base", "/base"},
		{"公开路径等于多段固定前缀", "https://login.example.test/a/b", "/a/b"},
	}
	for _, testCase := range valid {
		t.Run("valid/"+testCase.name, func(t *testing.T) {
			cfg := validMailConfigForURLTest()
			cfg.Server.PublicBaseURL = testCase.baseURL
			cfg.Server.PathPrefix = testCase.prefix
			if err := cfg.Validate(); err != nil {
				t.Fatalf("配置校验应通过: %v", err)
			}
			urls, err := buildMailURLs(cfg)
			if err != nil {
				t.Fatalf("生成邮件链接失败: %v", err)
			}
			expectedPrefix := strings.TrimSuffix(testCase.baseURL, "/")
			if !strings.HasPrefix(urls.PasswordReset, expectedPrefix+"/") {
				t.Fatalf("重置链接 %q 未以公开基址 %q 开头", urls.PasswordReset, expectedPrefix)
			}
		})
	}

	invalid := []struct {
		name    string
		baseURL string
		prefix  string
		wantErr string
	}{
		{"公开地址路径与固定前缀不一致", "https://login.example.test/other", "/base",
			"公开地址的路径必须与 server.path_prefix 一致"},
		{"公开地址无路径但配置固定前缀", "https://login.example.test", "/base",
			"公开地址的路径必须与 server.path_prefix 一致"},
		{"公开地址带查询串", "https://login.example.test/base?x=1", "/base",
			"公开地址不能包含查询字符串"},
		{"公开地址带片段", "https://login.example.test/base#frag", "/base",
			"公开地址不能包含片段"},
		{"公开地址带用户信息", "https://user:pass@login.example.test/base", "/base",
			"公开地址不能包含用户信息"},
	}
	for _, testCase := range invalid {
		t.Run("invalid/"+testCase.name, func(t *testing.T) {
			cfg := validMailConfigForURLTest()
			cfg.Server.PublicBaseURL = testCase.baseURL
			cfg.Server.PathPrefix = testCase.prefix
			err := cfg.Validate()
			if err == nil {
				t.Fatal("非法组合必须在配置校验阶段被拒绝")
			}
			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("配置校验错误 = %q，期望包含 %q", err.Error(), testCase.wantErr)
			}
		})
	}
}

// TestValidateMailRegistration 覆盖：要求邮箱验证但无邮件启动失败；有邮件但
// 公开地址非法也失败；关闭组合通过。
func TestValidateMailRegistration(t *testing.T) {
	cfg := login.Default()
	cfg.Registration.RequireEmailVerification = true
	if err := validateMailRegistration(cfg); err == nil || !strings.Contains(err.Error(), "mail.enabled") {
		t.Fatalf("无邮件却要求邮箱验证应失败: %v", err)
	}
	cfg.Mail.Enabled = true
	if err := validateMailRegistration(cfg); err == nil {
		t.Fatal("启用邮件但缺少公开地址应失败")
	}
	cfg.Server.PublicBaseURL = "https://login.example.test"
	if err := validateMailRegistration(cfg); err != nil {
		t.Fatalf("合法组合应通过: %v", err)
	}
	cfg.Mail.Enabled = false
	cfg.Registration.RequireEmailVerification = false
	if err := validateMailRegistration(cfg); err != nil {
		t.Fatalf("默认关闭组合应通过: %v", err)
	}
}
