package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
)

// AvatarAttachmentSource 按数据库快照的 avatars 表引用枚举头像附件，并通过受控
// 头像存储读取字节。它只包含快照中被引用的文件；孤儿文件不在备份范围内。
type AvatarAttachmentSource struct {
	storage avatar.Storage
}

// NewAvatarAttachmentSource 包装宿主提供的头像存储契约。
func NewAvatarAttachmentSource(storage avatar.Storage) (*AvatarAttachmentSource, error) {
	if isNilDependency(storage) {
		return nil, fmt.Errorf("%w: 头像存储为空", ErrOptionsInvalid)
	}
	return &AvatarAttachmentSource{storage: storage}, nil
}

// avatarReference 是数据库快照中的一条头像引用。
type avatarReference struct {
	key      string
	sha256   [32]byte
	sizeByte int64
}

// List 读取数据库快照中的头像引用并逐个读取/校验附件字节。文件缺失、大小或摘要
// 与数据库记录不一致时返回 ErrAttachmentInconsistent（可由服务有界重试）。
func (s *AvatarAttachmentSource) List(ctx context.Context,
	snapshotPath string) ([]AttachmentInfo, error) {
	if s == nil || isNilDependency(s.storage) {
		return nil, fmt.Errorf("%w: 头像附件源未初始化", ErrOptionsInvalid)
	}
	references, err := readAvatarReferences(ctx, snapshotPath)
	if err != nil {
		return nil, err
	}
	infos := make([]AttachmentInfo, 0, len(references))
	for _, reference := range references {
		data, readErr := s.storage.Open(ctx, reference.key)
		if readErr != nil {
			return nil, fmt.Errorf("%w: 数据库快照引用的头像附件不可读", ErrAttachmentInconsistent)
		}
		digest := sha256.Sum256(data)
		if int64(len(data)) != reference.sizeByte || digest != reference.sha256 {
			return nil, fmt.Errorf("%w: 头像附件大小或摘要与数据库快照不一致",
				ErrAttachmentInconsistent)
		}
		infos = append(infos, AttachmentInfo{
			EntryName: attachmentEntryPrefix + reference.key,
			SizeBytes: int64(len(data)),
			SHA256:    digest,
		})
	}
	return infos, nil
}

// Open 重新读取已列出的附件内容。调用方在写入载荷前会再次核对清单摘要，因此
// 快照后被替换/删除的文件会在这里暴露为失败而不是静默写入新内容。
func (s *AvatarAttachmentSource) Open(ctx context.Context, entryName string) (io.ReadCloser, error) {
	if s == nil || isNilDependency(s.storage) {
		return nil, fmt.Errorf("%w: 头像附件源未初始化", ErrOptionsInvalid)
	}
	if !strings.HasPrefix(entryName, attachmentEntryPrefix) {
		return nil, fmt.Errorf("%w: 附件条目名非法", ErrInvalidRequest)
	}
	key := strings.TrimPrefix(entryName, attachmentEntryPrefix)
	data, err := s.storage.Open(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("%w: 头像附件不可读", ErrAttachmentInconsistent)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// readAvatarReferences 以只读方式打开数据库快照并读取 avatars 表引用。表不存在
// （迁移 0017 之前的旧库）按没有附件处理；查询失败明确失败。
func readAvatarReferences(ctx context.Context, snapshotPath string) ([]avatarReference, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", snapshotPath+"?_query_only=1&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("%w: 无法打开数据库快照读取附件引用", ErrSnapshotFailed)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var tableCount int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='avatars'`).
		Scan(&tableCount); err != nil {
		return nil, fmt.Errorf("%w: 无法检查头像表", ErrSnapshotFailed)
	}
	if tableCount == 0 {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx,
		`SELECT storage_key, content_sha256, byte_size FROM avatars ORDER BY storage_key`)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取头像引用", ErrSnapshotFailed)
	}
	defer rows.Close()
	references := make([]avatarReference, 0, 8)
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var key string
		var digest []byte
		var size int64
		if err := rows.Scan(&key, &digest, &size); err != nil {
			return nil, fmt.Errorf("%w: 头像引用行格式非法", ErrSnapshotFailed)
		}
		if len(digest) != sha256.Size || size <= 0 || key == "" {
			return nil, fmt.Errorf("%w: 头像引用行缺字段", ErrSnapshotFailed)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var reference avatarReference
		reference.key = key
		copy(reference.sha256[:], digest)
		reference.sizeByte = size
		references = append(references, reference)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("%w: 读取头像引用失败", ErrSnapshotFailed)
	}
	return references, nil
}
