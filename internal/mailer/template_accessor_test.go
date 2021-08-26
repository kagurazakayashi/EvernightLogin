package mailer_test

// 步骤 72：TemplateSet 源文本只读访问器测试（管理页面只读展示与合成预览）。

import (
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/mailer"
)

func TestTemplateSetTemplatesReadOnlyCopy(t *testing.T) {
	set, err := mailer.DefaultTemplateSet()
	if err != nil {
		t.Fatalf("默认模板: %v", err)
	}
	templates := set.Templates()
	for _, kind := range []mailer.Kind{mailer.KindVerification, mailer.KindPasswordReset,
		mailer.KindSecurityNotice} {
		template, ok := templates[kind]
		if !ok || template.Subject == "" || template.Body == "" {
			t.Fatalf("缺少 %s 模板源文本", kind)
		}
	}
	// 调用方修改返回值不能影响已编译集合。
	templates[mailer.KindVerification] = mailer.Template{Subject: "篡改", Body: "篡改"}
	if again := set.Templates(); again[mailer.KindVerification].Subject == "篡改" {
		t.Fatal("模板源文本应为只读副本")
	}
	content, err := set.Render(mailer.RenderRequest{Kind: mailer.KindSecurityNotice,
		Notice: &mailer.SecurityNoticeData{DisplayName: "测试", Event: "事件",
			OccurredAt: "2026-01-01", AppName: "EvernightLogin",
			SupportURL: "https://example.invalid/support"}})
	if err != nil || content.Subject == "" || content.TextBody == "" {
		t.Fatalf("渲染 = %+v err=%v", content, err)
	}
	var nilSet *mailer.TemplateSet
	if nilSet.Templates() != nil {
		t.Fatal("nil 模板集合应返回 nil 副本")
	}
}
