package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PDF 字体约束与应用内嵌说明（步骤 78）。
//
// 报告 PDF 需要嵌入真实的中文字体；但 10.5 MB 的字体文件不进入 Git 仓库，而是由
// 宿主通过受信配置提供受控本地路径（Options.FontPath），发行包随附 OFL.txt。字体
// 文件在构造服务时读取一次并校验摘要，渲染时只从内存取字节，渲染器不会再访问任意
// 本地文件、网络或子进程（gopdf 为纯 Go 库，无网络/子进程/临时文件副作用）。
const (
	// DefaultPDFFontFamily 是嵌入 PDF 的字体族名；子集化后派生字体名不含 OFL
	// 保留字体名 Source，符合 SIL OFL 1.1 的再分发要求。
	DefaultPDFFontFamily = "NotoSansSC"
	// RequiredPDFFontSHA256 是预审通过的 Noto Sans SC 静态 Regular TTF（v41，
	// Google Fonts 官方 CDN 静态文件）的 SHA-256。未显式配置 FontSHA256 时默认
	// 强制该值，避免误把 OTF（CFF 轮廓）或可变字体（默认 Thin 实例）嵌入报告。
	RequiredPDFFontSHA256 = "450625c8d46ab3df97b7904ded955ec2746d17ec76740cb1e91d1ba63a0f89af"
	// RequiredPDFFontBytes 是同一字体的字节数；生产加载只用区间边界与摘要校验，
	// 该精确值供测试、文档和获取脚本核对（不用于生产快速排除）。
	RequiredPDFFontBytes = 10540644
	// minPDFFontBytes/maxPDFFontBytes 是允许配置的字体文件大小边界，防止把超大
	// 或空文件当作字体读取（10.5 MB 的 Noto Sans SC 落在区间内）。
	minPDFFontBytes = 1 << 20
	maxPDFFontBytes = 48 << 20
	// ttfSFNTVersion 是 gopdf 唯一接受的 sfnt 版本（TrueType glyf 轮廓）。
	ttfSFNTVersion = 0x00010000
)

// pdfFont 是已加载并通过校验的受信 PDF 字体。
type pdfFont struct {
	family string
	data   []byte
	sha256 string
}

// loadPDFFont 读取并校验受信字体文件。path 必须来自宿主配置（绝对路径、常规文件、
// 非符号链接）；默认只接受预审摘要（不匹配/文件类型不符/大小越界都拒绝构造）；
// 非预审摘要还必须由宿主显式设置 AllowUnreviewedPDFFont，防止未审查字体进入
// gopdf 解析器。返回的字节只在内存中使用，渲染阶段不再访问文件系统。
func loadPDFFont(path, expectedSHA256 string, allowUnreviewed bool) (*pdfFont, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: PDF 字体路径必须是绝对路径", ErrOptionsInvalid)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: PDF 字体文件不存在", ErrOptionsInvalid)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: PDF 字体必须是常规文件（不允许符号链接）", ErrOptionsInvalid)
	}
	if info.Size() < minPDFFontBytes || info.Size() > maxPDFFontBytes {
		return nil, fmt.Errorf("%w: PDF 字体文件大小超出允许范围", ErrOptionsInvalid)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: PDF 字体无法读取", ErrOptionsInvalid)
	}
	expected := strings.ToLower(strings.TrimSpace(expectedSHA256))
	if expected == "" {
		expected = RequiredPDFFontSHA256
	}
	if len(expected) != hex.EncodedLen(sha256.Size) {
		return nil, fmt.Errorf("%w: PDF 字体摘要格式无效", ErrOptionsInvalid)
	}
	// 非预审摘要默认拒绝：该字段来自宿主可信配置，但为避免误接线把外部可写配置
	// 或运行期变量接进来，只有显式 AllowUnreviewedPDFFont 才放行。
	if expected != RequiredPDFFontSHA256 && !allowUnreviewed {
		return nil, fmt.Errorf("%w: PDF 字体非预审摘要需要显式受信开关", ErrOptionsInvalid)
	}
	digest := sha256.Sum256(data)
	actual := hex.EncodeToString(digest[:])
	if actual != expected {
		return nil, fmt.Errorf("%w: PDF 字体摘要不符（不接受未经预审的字体文件）", ErrOptionsInvalid)
	}
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: PDF 字体文件过短", ErrOptionsInvalid)
	}
	sfnt := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	if sfnt != ttfSFNTVersion {
		// 0x4f54544f=OTTO（CFF 轮廓）、0x74746366=ttcf（字体集合）都会被 gopdf
		// 解析器拒绝，这里提前给出明确错误，避免把不兼容字体交给渲染器。
		return nil, fmt.Errorf("%w: PDF 字体必须是 TrueType（glyf）静态字体", ErrOptionsInvalid)
	}
	if int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("%w: PDF 字体在读取期间发生变化", ErrOptionsInvalid)
	}
	return &pdfFont{family: DefaultPDFFontFamily, data: data, sha256: actual}, nil
}
