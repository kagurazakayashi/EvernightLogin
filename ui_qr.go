package login

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// renderQRSVG 在服务端把文本渲染为内联 SVG 二维码（本地生成，无第三方在线资源）。
// 使用 rsc.io/qr（Rob Pike/Go Authors，BSD-3-Clause，无传递依赖）；返回的 SVG 带
// role="img" 与 <title> 可访问名，颜色固定为黑白以满足高对比与打印。
func renderQRSVG(payload string) ([]byte, error) {
	if strings.TrimSpace(payload) == "" {
		return nil, fmt.Errorf("二维码载荷为空")
	}
	code, err := qr.Encode(payload, qr.M)
	if err != nil {
		return nil, fmt.Errorf("二维码编码失败: %w", err)
	}
	const quiet = 4
	size := code.Size + quiet*2
	var builder strings.Builder
	builder.WriteString(`<svg xmlns="http://www.w3.org/2000/svg" class="ln-qr" role="img" aria-label="扫码登录二维码" width="220" height="220" viewBox="0 0 `)
	builder.WriteString(fmt.Sprintf("%d %d", size, size))
	builder.WriteString(`" shape-rendering="crispEdges"><title>扫码登录二维码</title>`)
	builder.WriteString(`<rect width="100%" height="100%" fill="#FFFFFF"/>`)
	// 用单 path 绘制所有黑色模块，减少 DOM 节点与 SVG 体积。
	builder.WriteString(`<path fill="#000000" d="`)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Black(x, y) {
				builder.WriteString(fmt.Sprintf("M%d %dh1v1h-1z", x+quiet, y+quiet))
			}
		}
	}
	builder.WriteString(`"/></svg>`)
	return []byte(builder.String()), nil
}
