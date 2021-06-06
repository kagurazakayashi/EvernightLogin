// Package avatar 实现用户头像的受控本地上传、存储引用与网络头像处理。
//
// 范围与安全边界：
//   - 只服务“用户头像”这一种资源，不做通用文件管理系统、不提供任意路径下载、
//     不接受客户端文件名或扩展名作为存储路径的一部分。
//   - 上传内容必须先按真实字节解析为受支持的静态图片（PNG/JPEG/GIF），
//     校验尺寸与字节上限，然后重新编码并只保存重编码结果；原始字节、
//     EXIF/文本块与可执行脚本内容不会落盘。SVG 等可执行/主动内容默认拒绝。
//   - 存储键与文件名全部由服务端生成，落在宿主指定的受控目录内；读取时校验
//     键格式、路径未逃逸目录且内容摘要匹配，展示层只拿到媒体类型与安全响应头，
//     不暴露本机路径。
//   - 网络头像采用“受控抓取”路径：仅允许 https（默认端口），拒绝 URL 凭证，
//     每次解析/重定向都校验目标地址，禁止环回、私有、链路本地、CGNAT 等非公网
//     地址，限制重定向次数、总时限与响应字节数，关闭自动解压，抓取到的字节仍走
//     与上传完全相同的重编码流程。
//   - 头像引用的更新、旧文件清理与审计在同一事务边界内处理，事务失败会补偿删除
//     刚写入的新文件；旧文件删除失败不伪造成功，留给 CollectGarbage 清理。
//
// 本包不暴露 HTTP 路由、不签发会话、不直接装配进 cmd/login-server；宿主通过
// SetResponseHeaders 把展示所需的 Content-Type/ETag/禁止嗅探等响应头写入响应，
// 实际路由与鉴权仍由宿主完成。本包不使用真实外网，网络测试使用本地 httptest
// 服务器并通过明确命名的测试专用开关放行回环地址。
package avatar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	"image/jpeg"
	"image/png"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

const (
	// MaxUploadBytes 是单次上传/抓取的原始字节上限（2 MiB）。
	MaxUploadBytes = 2 << 20
	// MaxStoredBytes 是重编码后允许落盘的字节上限（防止 PNG 重编码后异常膨胀）。
	MaxStoredBytes = 6 << 20
	// MaxPixels 是解码后总像素上限（防止超大尺寸解压膨胀）。
	MaxPixels = 1 << 20
	// MaxDimension 是宽/高单边上限。
	MaxDimension = 1024
	// MinDimension 是宽/高单边下限。
	MinDimension = 8
	// MaxURLBytes 是网络头像 URL 长度上限。
	MaxURLBytes = 2048
)

const (
	// MediaTypePNG 是重编码后持久化的 PNG 类型。
	MediaTypePNG = "image/png"
	// MediaTypeJPEG 是重编码后持久化的 JPEG 类型。
	MediaTypeJPEG = "image/jpeg"
	// MediaTypeGIF 是允许上传的 GIF 输入类型；GIF 会被重编码为静态 PNG。
	MediaTypeGIF = "image/gif"
)

const (
	// SourceUpload 表示来自本地上传。
	SourceUpload = "upload"
	// SourceNetwork 表示来自受控网络抓取。
	SourceNetwork = "network"
)

// avatarIDPrefix 是稳定头像 ID 前缀；ID 由服务端 128 位安全随机数生成。
const avatarIDPrefix = "avt_"

// 领域错误哨兵。错误文本不包含用户内容、本机路径或远程地址明文。
var (
	ErrOptionsInvalid      = errors.New("头像服务选项无效")
	ErrInvalidRequest      = errors.New("头像请求无效")
	ErrAccessDenied        = errors.New("未获准访问该头像")
	ErrUserNotFound        = errors.New("用户不存在")
	ErrVersionConflict     = errors.New("头像已被其他操作修改")
	ErrInvalidImage        = errors.New("图片内容无效或不完整")
	ErrImageTooLarge       = errors.New("图片超过允许的大小")
	ErrUnsupportedMedia    = errors.New("不支持的图片类型")
	ErrSVGNotAllowed       = errors.New("默认不接受 SVG 等可执行图片")
	ErrContentTypeMismatch = errors.New("声明的图片类型与真实内容不一致")
	ErrRemoteBlocked       = errors.New("远程头像地址不被允许")
	ErrRemoteUnavailable   = errors.New("远程头像地址暂时不可用")
	ErrStorageUnavailable  = errors.New("头像文件存储暂时不可用")
	ErrStorageCorrupt      = errors.New("头像文件与记录不一致")
	ErrStoreUnavailable    = errors.New("头像记录存储暂时不可用")
	ErrAuditUnavailable    = errors.New("关键操作未能可靠记录")
)

// ErrorCode 是头像领域对根包错误码注册表的投影（只复用既有已登记码）。
type ErrorCode string

const (
	CodeReqInvalid        ErrorCode = "REQ_INVALID"
	CodeAccessDenied      ErrorCode = "ACCESS_DENIED"
	CodeResourceForbidden ErrorCode = "RESOURCE_FORBIDDEN"
	CodeConflict          ErrorCode = "CONFLICT"
	CodeChallengeInvalid  ErrorCode = "CHALLENGE_INVALID"
	CodeDBUnavailable     ErrorCode = "DB_UNAVAILABLE"
	CodeAuditWriteFailed  ErrorCode = "AUDIT_WRITE_FAILED"
	CodeInternalError     ErrorCode = "INTERNAL_ERROR"
)

// CodeOf 把头像领域错误映射为根包已登记错误码。远程目标被策略拒绝与普通请求
// 错误分开，便于调用者区分“地址不允许”与“内容不可用”；不新增错误码。
func CodeOf(err error) ErrorCode {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidImage),
		errors.Is(err, ErrImageTooLarge), errors.Is(err, ErrUnsupportedMedia),
		errors.Is(err, ErrSVGNotAllowed), errors.Is(err, ErrContentTypeMismatch),
		errors.Is(err, ErrRemoteUnavailable):
		return CodeReqInvalid
	case errors.Is(err, ErrRemoteBlocked):
		return CodeResourceForbidden
	case errors.Is(err, ErrAccessDenied):
		return CodeAccessDenied
	case errors.Is(err, ErrUserNotFound):
		return CodeChallengeInvalid
	case errors.Is(err, ErrVersionConflict):
		return CodeConflict
	case errors.Is(err, ErrStorageUnavailable), errors.Is(err, ErrStoreUnavailable):
		return CodeDBUnavailable
	case errors.Is(err, ErrAuditUnavailable):
		return CodeAuditWriteFailed
	default:
		return CodeInternalError
	}
}

// Caller 是可信调用身份；不能由请求参数自称。
type Caller struct {
	actor     audit.Actor
	requestID string
}

// UserCaller 构造已认证普通用户调用者。
func UserCaller(userID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorUser, ID: userID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 用户标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// SystemCaller 构造系统组件调用者。
func SystemCaller(componentID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorSystem, ID: componentID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 系统组件标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// LocalAdminCaller 构造本地受信管理员调用者。
func LocalAdminCaller(operatorID string) (Caller, error) {
	actor := audit.Actor{Type: audit.ActorLocalAdmin, ID: operatorID}
	if err := actor.Validate(); err != nil {
		return Caller{}, fmt.Errorf("%w: 本地操作者标识无效", ErrInvalidRequest)
	}
	return Caller{actor: actor}, nil
}

// Actor 返回审计身份副本。
func (c Caller) Actor() audit.Actor { return c.actor }

// IsUser 报告是否为普通用户身份。
func (c Caller) IsUser() bool { return c.actor.Type == audit.ActorUser }

// WithRequestID 返回带请求编号的副本。
func (c Caller) WithRequestID(requestID string) (Caller, error) {
	if err := account.ValidateRequestID(requestID); err != nil {
		return Caller{}, fmt.Errorf("%w: 请求编号无效", ErrInvalidRequest)
	}
	c.requestID = requestID
	return c, nil
}

// Avatar 是头像记录快照。它不包含存储键、本机路径或网络地址。
type Avatar struct {
	ID         string
	UserID     string
	MediaType  string
	SourceKind string
	ByteSize   int64
	Width      int
	Height     int
	// SHA256 是重编码后内容的十六进制摘要，用于 ETag 与展示前完整性校验。
	SHA256 string
	// RowVersion 是 users 表当前行版本；写操作要求客户端提供期望值。
	RowVersion int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Content 是已读取并校验完整性的头像内容；Data 只包含重编码后的静态图片。
type Content struct {
	Avatar Avatar
	Data   []byte
}

// avatarCacheControl 是展示头像的建议缓存策略：私有缓存、短时长，避免公共缓存
// 缓存他人头像。
const avatarCacheControl = "private, max-age=300"

// SetResponseHeaders 把展示头像所需的安全响应头写入 header：固定 Content-Type
// 来自服务端记录、Content-Length 精确、禁止内容嗅探、ETag 使用内容摘要、内联
// 文件名由服务端生成。它不写入本机路径、原始文件名或用户可控文本。
func (c Content) SetResponseHeaders(header http.Header) {
	if header == nil {
		return
	}
	mediaType := c.Avatar.MediaType
	if mediaType != MediaTypePNG && mediaType != MediaTypeJPEG {
		mediaType = MediaTypePNG
	}
	extension := ".png"
	if mediaType == MediaTypeJPEG {
		extension = ".jpg"
	}
	header.Set("Content-Type", mediaType)
	header.Set("Content-Length", strconv.Itoa(len(c.Data)))
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Disposition", `inline; filename="avatar`+extension+`"`)
	header.Set("Cache-Control", avatarCacheControl)
	if c.Avatar.SHA256 != "" {
		header.Set("ETag", `"`+c.Avatar.SHA256+`"`)
	}
}

// ProcessedImage 是校验并重编码后的图片结果。
type ProcessedImage struct {
	Data      []byte
	MediaType string
	// Extension 是服务端使用的扩展名（不含点）。
	Extension string
	Width     int
	Height    int
	SHA256    [32]byte
	// inputFormat 是重编码前的真实输入格式（png/jpeg/gif），GIF 会被重编码为
	// 静态 PNG，因此输出媒体类型不足以反推输入格式。
	inputFormat string
}

// InputFormat 报告重编码前的真实输入格式（png/jpeg/gif），供诊断与审计使用。
func (p ProcessedImage) InputFormat() string {
	if p.inputFormat == "" {
		return "unknown"
	}
	return p.inputFormat
}

// setInputFormat 保存真实输入格式，仅由 ProcessImage 填充。
func (p *ProcessedImage) setInputFormat(format string) { p.inputFormat = format }

// acceptedMediaTypes 是允许作为输入声明与真实解码结果的媒体类型。
var acceptedMediaTypes = map[string]bool{
	MediaTypePNG:  true,
	MediaTypeJPEG: true,
	MediaTypeGIF:  true,
}

// normalizeMediaType 去除参数并小写化声明的媒体类型。
func normalizeMediaType(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if index := strings.Index(value, ";"); index >= 0 {
		value = strings.TrimSpace(value[:index])
	}
	return value
}

// ProcessImage 按真实内容校验并重编码图片。
//
// 校验顺序：字节上限 -> 声明类型 -> 真实格式与尺寸（解码前先读配置，防解压
// 膨胀）-> 完整解码 -> 重编码为静态 PNG/JPEG。declaredMediaType 只作为快速拒绝
// 与一致性校验，最终格式由真实字节决定；声明与真实不一致一律拒绝。
func ProcessImage(data []byte, declaredMediaType string) (ProcessedImage, error) {
	if len(data) == 0 {
		return ProcessedImage{}, fmt.Errorf("%w: 图片内容为空", ErrInvalidImage)
	}
	if len(data) > MaxUploadBytes {
		return ProcessedImage{}, fmt.Errorf("%w: 超过 %d 字节上限", ErrImageTooLarge, MaxUploadBytes)
	}
	declared := normalizeMediaType(declaredMediaType)
	if declared != "" {
		switch {
		case declared == "image/svg+xml" || declared == "image/svg":
			return ProcessedImage{}, fmt.Errorf("%w: 不接受 SVG", ErrSVGNotAllowed)
		case !acceptedMediaTypes[declared]:
			return ProcessedImage{}, fmt.Errorf("%w: 声明的类型 %q 不在允许范围", ErrUnsupportedMedia, declared)
		}
	}
	config, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return ProcessedImage{}, fmt.Errorf("%w: 无法识别为受支持的静态图片", ErrUnsupportedMedia)
	}
	actual := ""
	switch format {
	case "png":
		actual = MediaTypePNG
	case "jpeg":
		actual = MediaTypeJPEG
	case "gif":
		actual = MediaTypeGIF
	default:
		return ProcessedImage{}, fmt.Errorf("%w: 不支持的图片格式 %q", ErrUnsupportedMedia, format)
	}
	if declared != "" && declared != actual {
		return ProcessedImage{}, fmt.Errorf("%w: 声明 %q 但真实内容为 %q", ErrContentTypeMismatch, declared, actual)
	}
	if err := checkDimensions(config.Width, config.Height); err != nil {
		return ProcessedImage{}, err
	}
	decoded, decodedFormat, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return ProcessedImage{}, fmt.Errorf("%w: 图片数据不完整或损坏", ErrInvalidImage)
	}
	if decodedFormat != format {
		return ProcessedImage{}, fmt.Errorf("%w: 图片格式在解码前后不一致", ErrInvalidImage)
	}
	processed, err := reencode(decoded, actual)
	if err != nil {
		return ProcessedImage{}, err
	}
	processed.setInputFormat(format)
	return processed, nil
}

// checkDimensions 校验宽高范围与总像素上限；任何越界都拒绝，不做静默缩放。
func checkDimensions(width, height int) error {
	if width < MinDimension || height < MinDimension {
		return fmt.Errorf("%w: 图片尺寸不能小于 %d 像素", ErrInvalidImage, MinDimension)
	}
	if width > MaxDimension || height > MaxDimension {
		return fmt.Errorf("%w: 图片单边不能超过 %d 像素", ErrImageTooLarge, MaxDimension)
	}
	if int64(width)*int64(height) > MaxPixels {
		return fmt.Errorf("%w: 图片总像素超过 %d", ErrImageTooLarge, MaxPixels)
	}
	return nil
}

// reencode 丢弃原始字节并重新编码：PNG 保持 PNG、JPEG 以质量 90 重编码、GIF 只取
// 首帧并转为静态 PNG（不保留动画/扩展块）。重编码同时移除 EXIF/文本块等元数据。
func reencode(decoded image.Image, inputMediaType string) (ProcessedImage, error) {
	bounds := decoded.Bounds()
	width, height := bounds.Dx(), bounds.Dy()
	if err := checkDimensions(width, height); err != nil {
		return ProcessedImage{}, err
	}
	var buffer bytes.Buffer
	outputMediaType := MediaTypePNG
	extension := "png"
	switch inputMediaType {
	case MediaTypeJPEG:
		outputMediaType = MediaTypeJPEG
		extension = "jpg"
		if err := jpeg.Encode(&buffer, decoded, &jpeg.Options{Quality: 90}); err != nil {
			return ProcessedImage{}, fmt.Errorf("%w: JPEG 重编码失败", ErrInvalidImage)
		}
	case MediaTypePNG, MediaTypeGIF:
		// GIF 走 PNG 输出：保留首帧但彻底去掉动画与扩展块。
		if err := png.Encode(&buffer, decoded); err != nil {
			return ProcessedImage{}, fmt.Errorf("%w: PNG 重编码失败", ErrInvalidImage)
		}
	default:
		return ProcessedImage{}, fmt.Errorf("%w: 不支持的重编码目标", ErrUnsupportedMedia)
	}
	data := buffer.Bytes()
	if len(data) == 0 || len(data) > MaxStoredBytes {
		return ProcessedImage{}, fmt.Errorf("%w: 重编码后大小超出限制", ErrImageTooLarge)
	}
	return ProcessedImage{
		Data:      append([]byte(nil), data...),
		MediaType: outputMediaType,
		Extension: extension,
		Width:     width,
		Height:    height,
		SHA256:    sha256.Sum256(data),
	}, nil
}

// NewAvatarID 生成服务端头像 ID（avt_ + 128 位安全随机数的十六进制）。
func NewAvatarID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("%w: 无法生成头像标识", ErrStorageUnavailable)
	}
	return avatarIDPrefix + hex.EncodeToString(buffer), nil
}

// validateAvatarID 校验头像 ID 格式，拒绝任何不是本服务生成的值。
func validateAvatarID(id string) bool {
	if len(id) != len(avatarIDPrefix)+32 || !strings.HasPrefix(id, avatarIDPrefix) {
		return false
	}
	_, err := hex.DecodeString(id[len(avatarIDPrefix):])
	return err == nil
}

// Target 是授权判定所需的用户快照（只含稳定 ID 与 root 标记，不含资料正文）。
type Target struct {
	UserID string
	IsRoot bool
}

// Authorizer 判定调用者能否读取/修改目标用户头像；实现应默认拒绝。未注入时
// 服务使用“仅本人与受信 system/local_admin”的默认口径。
type Authorizer interface {
	AuthorizeAvatar(ctx context.Context, caller Caller, target Target, write bool) error
}

// AuthorizerFunc 是 Authorizer 的函数适配器（宿主装配或测试）。
type AuthorizerFunc func(ctx context.Context, caller Caller, target Target, write bool) error

// AuthorizeAvatar 实现 Authorizer。
func (f AuthorizerFunc) AuthorizeAvatar(ctx context.Context, caller Caller, target Target, write bool) error {
	if f == nil {
		return ErrAccessDenied
	}
	return f(ctx, caller, target, write)
}

// AuditRecorder 是安全审计写入契约；实现必须 fail-closed。
type AuditRecorder interface {
	Record(ctx context.Context, event audit.Event) error
	RecordFailure(ctx context.Context, event audit.Event) error
	ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error
}

// UploadRequest 是本地头像上传请求。TargetUserID 为空表示调用者本人；只有受信
// system/local_admin 可以指定其他用户。
type UploadRequest struct {
	TargetUserID       string
	Data               []byte
	DeclaredMediaType  string
	ExpectedRowVersion int64
	RequestID          string
}

// FetchRequest 是网络头像请求；URL 只作为待抓取目标，不会写入数据库或审计明文。
type FetchRequest struct {
	TargetUserID       string
	URL                string
	ExpectedRowVersion int64
	RequestID          string
}

// RemoveRequest 是清除当前头像请求。
type RemoveRequest struct {
	TargetUserID       string
	ExpectedRowVersion int64
	RequestID          string
}
