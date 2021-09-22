package secrets

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Provider 是宿主提供密钥环文档的扩展点。实现可以从受保护文件、环境变量或
// 宿主自己的密钥管理设施（例如操作系统密钥库、远程 KMS）读取文档。返回内容
// 必须是 ParseKeyringDocument 可解析的 JSON 文档。
//
// 无论来源如何，实现都不得把密钥材料写入日志、数据库或普通临时文件，也不得
// 在文档缺失时返回一个自动生成的新密钥环来替代已丢失的主密钥。
type Provider interface {
	// KeyringDocument 返回密钥环 JSON 文档。若 ctx 被取消，实现应尽快返回。
	KeyringDocument(ctx context.Context) ([]byte, error)
}

// ProviderFunc 把函数适配为 Provider，方便宿主注入自定义密钥来源。
type ProviderFunc func(ctx context.Context) ([]byte, error)

// KeyringDocument 实现 Provider。nil 函数按“提供者不可用”明确失败，避免把
// typed nil 当成可调用实现而 panic；密钥缺失时不会退回到自动生成新密钥。
func (f ProviderFunc) KeyringDocument(ctx context.Context) ([]byte, error) {
	if f == nil {
		return nil, fmt.Errorf("%w: 密钥提供者函数为 nil", ErrProviderUnavailable)
	}
	return f(normalizeContext(ctx))
}

// FileProvider 从受保护文件读取密钥环文档。读取时按平台检查文件权限：非
// Windows 平台要求文件权限不向组和其他用户开放；Windows 平台检查文件安全
// 描述符，拒绝向当前进程主体、SYSTEM 和 Administrators 之外的主体授权。
//
// 注意：Unix 的 chmod 位在 Windows 上不是有效的访问控制，Windows 分支必须
// 检查 ACL，不能只复用 Unix 权限位判断。
type FileProvider struct {
	path string
}

// NewFileProvider 校验并保存密钥环文件路径。路径必须是绝对路径；实际读取与
// 权限检查在 KeyringDocument 时执行，因此轮换替换文件后会重新检查。
func NewFileProvider(path string) (*FileProvider, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: 密钥文件路径为空", ErrFileInvalid)
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: 密钥文件必须使用绝对路径", ErrFileInvalid)
	}
	return &FileProvider{path: path}, nil
}

// Path 返回密钥环文件路径。路径不是秘密，但调用方不应把它当成权限凭证。
func (p *FileProvider) Path() string {
	if p == nil {
		return ""
	}
	return p.path
}

// KeyringDocument 从受保护文件读取密钥环文档。文件不存在、不是普通文件、为空、
// 超过 MaxKeyringDocumentBytes 或权限不安全时失败；此时不会创建或替换任何文件。
func (p *FileProvider) KeyringDocument(ctx context.Context) ([]byte, error) {
	if p == nil || p.path == "" {
		return nil, fmt.Errorf("%w: 未配置密钥文件路径", ErrFileInvalid)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.Open(p.path)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法打开密钥文件", ErrFileInvalid)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取密钥文件状态", ErrFileInvalid)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: 密钥文件必须是普通文件", ErrFileInvalid)
	}
	if info.Size() <= 0 {
		return nil, fmt.Errorf("%w: 密钥文件为空", ErrKeyMaterialMissing)
	}
	if info.Size() > MaxKeyringDocumentBytes {
		return nil, fmt.Errorf("%w: 密钥文件超过 %d 字节", ErrFileInvalid, MaxKeyringDocumentBytes)
	}
	if err := checkFileProtection(file, info); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	doc, err := io.ReadAll(io.LimitReader(file, MaxKeyringDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: 读取密钥文件失败", ErrFileInvalid)
	}
	if len(doc) > MaxKeyringDocumentBytes {
		return nil, fmt.Errorf("%w: 密钥文件超过 %d 字节", ErrFileInvalid, MaxKeyringDocumentBytes)
	}
	if len(doc) == 0 {
		return nil, fmt.Errorf("%w: 密钥文件为空", ErrKeyMaterialMissing)
	}
	return doc, nil
}

// LoadKeyring 从提供者读取并解析密钥环。provider 为 nil、返回空文档或文档无效
// 时明确失败；本函数不会生成任何新密钥来掩盖主密钥丢失。
func LoadKeyring(ctx context.Context, provider Provider) (*Keyring, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: 未配置密钥提供者", ErrKeyMaterialMissing)
	}
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	doc, err := provider.KeyringDocument(ctx)
	if err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, fmt.Errorf("%w: 密钥提供者返回空文档", ErrProviderUnavailable)
	}
	return ParseKeyringDocument(doc)
}

// CheckProtectedFile 检查指定文件是普通文件且操作系统权限只允许当前进程主体
// 安全访问。它用于确认主密钥文件已经按平台要求保护；Windows 下检查 ACL，
// 非 Windows 下检查文件权限位。调用方只能把本函数当作基本前置检查，不能把它
// 当作对主机管理员、SYSTEM 或宿主任意代码的防护承诺。
func CheckProtectedFile(path string) error {
	if path == "" {
		return fmt.Errorf("%w: 文件路径为空", ErrFileInvalid)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%w: 无法打开文件", ErrFileInvalid)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("%w: 无法读取文件状态", ErrFileInvalid)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: 必须是普通文件", ErrFileInvalid)
	}
	return checkFileProtection(file, info)
}

// WriteProtectedFile 原子地把秘密文档写入受保护文件：在目标目录创建临时文件，
// 先按平台要求设置权限（Windows 显式 DACL、非 Windows 0600），再写入内容并
// 重命名覆盖目标。重命名前内容不会出现在权限未收紧的文件里；失败时清理临时
// 文件。该函数供密钥轮换后持久化新密钥环等受控操作使用，调用方仍需保护目标
// 目录本身并限制操作者权限。
func WriteProtectedFile(path string, data []byte) error {
	if path == "" {
		return fmt.Errorf("%w: 文件路径为空", ErrFileInvalid)
	}
	// 与 FileProvider 保持一致：写入主密钥必须使用显式绝对路径，避免因进程
	// 工作目录变化把密钥文件写进未预期目录。
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: 密钥文件必须使用绝对路径", ErrFileInvalid)
	}
	if len(data) == 0 {
		return fmt.Errorf("%w: 拒绝写入空秘密文档", ErrFileInvalid)
	}
	if len(data) > MaxKeyringDocumentBytes {
		return fmt.Errorf("%w: 秘密文档超过 %d 字节", ErrFileInvalid, MaxKeyringDocumentBytes)
	}
	return writeProtectedFile(path, data)
}

// ProtectFile 把已存在的普通文件收紧为平台受保护的权限，并在收紧后复核：
// Windows 设置显式 DACL（仅当前进程用户、SYSTEM、Administrators），非 Windows
// 设为 0600。它供离线导出工具在写入高敏数据后收紧落地文件，避免高敏内容停留
// 在从父目录继承的宽松 ACL 下。调用方必须传入已存在的普通文件绝对路径；函数
// 不接受目录、符号链接或相对路径，失败时不做静默降级。
func ProtectFile(path string) error {
	if path == "" {
		return fmt.Errorf("%w: 文件路径为空", ErrFileInvalid)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: 文件必须使用绝对路径", ErrFileInvalid)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%w: 无法读取文件状态", ErrFileInvalid)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%w: 必须是已存在的普通文件", ErrFileInvalid)
	}
	if err := protectExistingFile(path); err != nil {
		return err
	}
	return CheckProtectedFile(path)
}

// normalizeContext 把 nil ctx 当成 Background 处理，避免调用方因漏传上下文而
// panic；取消与期限语义由非 nil ctx 提供。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// validateUnixFileModePerm 检查 Unix 权限位是否只允许所有者访问。它被非 Windows
// 平台的文件检查复用；单独抽成纯函数是为了能在 Windows 测试环境验证判断逻辑，
// 避免把 Unix chmod 当成 Windows ACL 的替代。
func validateUnixFileModePerm(perm os.FileMode) error {
	if perm&0o077 != 0 {
		return fmt.Errorf("%w: 文件权限 %04o，必须仅所有者可读写", ErrInsecurePermissions, perm)
	}
	return nil
}
