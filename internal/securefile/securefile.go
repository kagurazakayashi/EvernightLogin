// Package securefile 提供本地秘密文件（一次性口令、密码输入文件）的受限读写。
//
// 安全目标（M3 MEDIUM-1）：
//   - 写入：新文件（O_EXCL，拒绝覆盖），随后按平台收紧访问控制并自检：
//     Windows 显式 DACL（当前用户 + SYSTEM + Administrators，受保护 DACL），
//     非 Windows 模式位 0600；加固/自检失败必须删除半成品并返回错误（fail-closed）。
//   - 读取：拒绝符号链接、非普通文件、超限文件；Windows 拒绝宽泛主体
//     （Everyone/Users/Authenticated Users/ANONYMOUS）拥有任何权限的文件，
//     非 Windows 要求模式位不得超过 0600。
//
// 本包不记录文件内容，不把秘密写到日志；错误信息不包含秘密。
package securefile

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// DefaultMaxBytes 是秘密文件的默认读取上限（64 KiB）。
const DefaultMaxBytes int64 = 64 << 10

// 稳定错误（便于调用方/审计区分；不包含文件内容）。
var (
	ErrExists        = errors.New("秘密文件已存在，拒绝覆盖")
	ErrNotRegular    = errors.New("秘密路径不是普通文件")
	ErrSymlink       = errors.New("秘密路径是符号链接，拒绝使用")
	ErrTooLarge      = errors.New("秘密文件超过大小上限")
	ErrInsecurePerm  = errors.New("秘密文件访问权限过宽")
	ErrProtectFailed = errors.New("秘密文件访问控制加固失败")
	ErrEmptyPath     = errors.New("秘密文件路径为空")
)

// Write 以新建方式写入秘密文件并收紧访问控制。
//
// 若目标已存在返回 ErrExists（不做任何修改）；任何加固/自检失败都会删除本次创建的
// 文件并返回错误，避免留下被误认为受保护的文件。
func Write(path string, data []byte) error {
	if path == "" {
		return ErrEmptyPath
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: %v", ErrExists, path)
		}
		return fmt.Errorf("创建秘密文件失败: %w", err)
	}
	writeErr := func() error {
		if _, err := file.Write(data); err != nil {
			return fmt.Errorf("写入秘密文件失败: %w", err)
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("同步秘密文件失败: %w", err)
		}
		return nil
	}()
	closeErr := file.Close()
	if writeErr == nil && closeErr != nil {
		writeErr = fmt.Errorf("关闭秘密文件失败: %w", closeErr)
	}
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if err := protect(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// Read 读取秘密文件一次，拒绝不安全的路径/权限/大小。
func Read(path string, maxBytes int64) ([]byte, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	if maxBytes <= 0 || maxBytes > DefaultMaxBytes {
		maxBytes = DefaultMaxBytes
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("读取秘密文件失败: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: %v", ErrSymlink, path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %v", ErrNotRegular, path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("%w（最大 %d 字节）", ErrTooLarge, maxBytes)
	}
	if err := verify(path, info); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开秘密文件失败: %w", err)
	}
	defer func() { _ = file.Close() }()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取秘密文件失败: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("%w（最大 %d 字节）", ErrTooLarge, maxBytes)
	}
	return raw, nil
}
