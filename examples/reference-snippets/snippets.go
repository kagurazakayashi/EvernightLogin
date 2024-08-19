// Package referenceexamples 提供 docs/reference/ 内嵌的最小可编译示例。
//
// 示例只导入公开叶子包（errs/config），不启动服务、不写文件、不连接数据库，
// 因此可在任意产品重构阶段独立编译。文档生成器逐字内嵌这些函数，
// `go build ./examples/reference-snippets` 做真实编译校验；修改示例后必须运行
// `go run ./scripts/reference -write` 重新生成文档。
package referenceexamples

import (
	"github.com/kagurazakayashi/EvernightLogin/config"
	"github.com/kagurazakayashi/EvernightLogin/errs"
)

// ExampleLookupError 展示如何从公开错误码注册表查询错误码的公开含义与重试建议。
// 根包同时提供 login.LookupErrorCode / login.LookupErrorCodeGuidance 别名。
func ExampleLookupError() {
	definition, ok := errs.LookupErrorCode(errs.CodeRateLimited)
	if !ok {
		return
	}
	guidance, _ := errs.LookupErrorCodeGuidance(errs.CodeRateLimited)
	_ = definition.HTTPStatus
	_ = definition.DefaultMessage
	_ = guidance.Cause
	_ = guidance.Advice
	_ = guidance.Retry
}

// ExampleConfigLookup 展示如何查询配置字段元数据（字段/环境变量/生效分类/秘密标记）。
// 字段语义、默认值与校验规则以 docs/guide/configuration.md 为唯一权威。
func ExampleConfigLookup() {
	field, ok := config.LookupField("database.path")
	if !ok {
		return
	}
	_ = field.Field
	_ = field.Env
	_ = field.Class
	_ = field.Secret
}
