package loginte2e

import (
	"strings"
	"testing"
)

// TestParseSecretContent 覆盖受保护秘密文件的三种格式与非法输入。
func TestParseSecretContent(t *testing.T) {
	const secretValue = "sess_0123456789abcdef0123456789abcdef"
	cases := []struct {
		name       string
		content    string
		cookieName string
		want       string
		wantErr    bool
	}{
		{name: "raw secret", content: secretValue + "\n", want: secretValue},
		{name: "raw secret with bom", content: "\ufeff" + secretValue, want: secretValue},
		{name: "cookie header", content: "Cookie: other=x; " + DefaultSessionCookieName +
			"=" + secretValue + "\n", cookieName: DefaultSessionCookieName, want: secretValue},
		{name: "single cookie no name", content: "foo=" + secretValue + "\n", want: secretValue},
		{
			name:       "netscape cookies",
			content:    "# Netscape HTTP Cookie File\n.example.test\tTRUE\t/\tTRUE\t0\t" + DefaultSessionCookieName + "\t" + secretValue + "\n",
			cookieName: DefaultSessionCookieName, want: secretValue,
		},
		{
			name: "multiple cookies require name", cookieName: DefaultSessionCookieName,
			content: "a=1; " + DefaultSessionCookieName + "=" + secretValue,
			want:    secretValue,
		},
		{name: "multiple cookies ambiguous", content: "a=1; b=2", wantErr: true},
		{name: "empty", content: "  \n", wantErr: true},
		{name: "multi-line raw rejected", content: "abc\ndef", wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseSecretContent(testCase.content, testCase.cookieName)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("期望解析失败，实际得到 %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("解析失败: %v", err)
			}
			if got != testCase.want {
				t.Fatalf("解析结果 = %q，期望 %q", got, testCase.want)
			}
		})
	}
}

// TestValidateSecretValue 验证纯秘密值形态校验。
func TestValidateSecretValue(t *testing.T) {
	if err := validateSecretValue("abcDEF0123-._~"); err != nil {
		t.Fatalf("合法秘密值被拒绝: %v", err)
	}
	for _, invalid := range []string{"", "has space", "line\nbreak", strings.Repeat("a", 5000)} {
		if err := validateSecretValue(invalid); err == nil {
			t.Fatalf("非法秘密值未被拒绝: %q", invalid)
		}
	}
}
