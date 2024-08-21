package ui

import "embed"

// webEmbedded 内嵌内置页面模板、静态资源与 zh-CN 文案目录。宿主可通过
// WebUIOptions 的 HostTemplates/AssetOverlays/Translations 覆盖或替换，
// 不依赖 Node/npm 或其他前端构建链。
//
//go:embed web/templates web/assets web/i18n
var webEmbedded embed.FS
