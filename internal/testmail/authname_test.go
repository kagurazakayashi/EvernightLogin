package testmail_test

import (
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// TestAuthUsernamesAmbiguityRejected 验证配置阶段拒绝“大小写/Unicode 归一化后
// 相同”的模拟账户用户名：认证按精确字节比较，而收件箱可见性按大小写不敏感比较，
// 允许这种用户名会破坏账户隔离（两个账户共享同一收件箱且无法区分归属）。
func TestAuthUsernamesAmbiguityRejected(t *testing.T) {
	cases := []struct {
		name  string
		users map[string]string
	}{
		{"大小写不同", map[string]string{"tester": "a", "Tester": "b"}},
		{"全角与半角", map[string]string{"tester": "a", "ｔｅｓｔｅｒ": "b"}},
		{"Unicode 兼容字符", map[string]string{"Kelvin": "a", "Kelvin": "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := testmail.New(testmail.Options{Auth: &testmail.AuthOptions{Users: tc.users}}); err == nil {
				t.Fatalf("归一化后重复的用户名 %v 应被拒绝", tc.users)
			} else if !strings.Contains(err.Error(), "归一化") {
				t.Errorf("错误信息应说明归一化歧义: %v", err)
			}
		})
	}

	// 互不相同的用户名（含只有大小写/前缀差异但归一化后唯一）仍可正常启动。
	srv := startServer(t, testmail.Options{
		Auth: &testmail.AuthOptions{Users: map[string]string{
			"tester":  "pass-1",
			"tester2": "pass-2",
			"民":       "pass-3",
		}},
		IMAP: &testmail.IMAPOptions{},
	})
	if srv.IMAPAddr() == nil {
		t.Fatal("合法账户配置下 IMAP 监听器应正常启动")
	}
}
