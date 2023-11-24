// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package backupadmin

// 本文件为公开 Go 接口（步骤 231）提供“按备份编号检查/取恢复源”的内部能力：
//   - 不向公开 API 暴露任意磁盘路径；路径只在本包内由受控 OutputDir 与登记文件名解析；
//   - 检查在已登记文件摘要/大小基础上再做认证校验（有主密钥环时），失败如实拒绝；
//   - 恢复源只接受“已验证、未清理、文件存在”的产物，并写真实审计；实际恢复仍由
//     internal/restore 在排他锁/维护状态/预演后执行，其自身再复核 backups.restore 权限。

import (
	"context"
	"errors"
	"fmt"

	"github.com/kagurazakayashi/EvernightLogin/internal/account"
	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

// VerifyArtifact 按备份编号检查一个已登记备份：先复核登记摘要/大小与文件一致，
// 再在配置了主密钥环时做完整认证校验（解密、认证标签、清单与条目摘要）；无主密钥
// 环时只做无密钥结构检查，并如实返回 Encrypted/Authenticated 状态，不冒充已认证。
func (s *Service) VerifyArtifact(ctx context.Context, caller account.Caller,
	backupID, requestID string) (backup.VerifyReport, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return backup.VerifyReport{}, err
	}
	artifact, err := s.lookupArtifact(ctx, backupID)
	if err != nil {
		return backup.VerifyReport{}, err
	}
	path, err := s.backupPath(artifact)
	if err != nil {
		return backup.VerifyReport{}, err
	}
	if !s.artifactFileExists(artifact) {
		return backup.VerifyReport{}, ErrNotDownloadable
	}
	var report backup.VerifyReport
	if s.opts.Keyring != nil {
		document, docErr := s.opts.Keyring.KeyringDocument(ctx)
		if docErr != nil {
			return backup.VerifyReport{}, fmt.Errorf("%w: 主密钥环不可用", ErrStoreUnavailable)
		}
		keyring, keyErr := secrets.ParseKeyringDocument(document)
		if keyErr != nil {
			return backup.VerifyReport{}, fmt.Errorf("%w: 主密钥环无效", ErrStoreUnavailable)
		}
		report, err = backup.VerifyFile(ctx, path, keyring)
	} else {
		report, err = s.opts.Inspect(ctx, path)
	}
	if err != nil {
		s.recordBestEffort(ctx, audit.Event{Actor: caller.Actor(),
			Action: "backup.verify", Target: audit.Target{Type: "backup", ID: backupID},
			Outcome: audit.OutcomeFailure, RequestID: normalizeRequestID(requestID),
			Changes: []audit.FieldChange{{Field: "reason", After: "校验失败"}}})
		return backup.VerifyReport{}, err
	}
	if report.BackupID != artifact.BackupID || report.FileSHA256 != artifact.FileSHA256 ||
		report.FileSize != artifact.SizeBytes {
		s.recordBestEffort(ctx, audit.Event{Actor: caller.Actor(),
			Action: "backup.verify", Target: audit.Target{Type: "backup", ID: backupID},
			Outcome: audit.OutcomeFailure, RequestID: normalizeRequestID(requestID),
			Changes: []audit.FieldChange{{Field: "reason", After: "登记摘要或大小不一致"}}})
		return backup.VerifyReport{}, errors.New("备份登记摘要/大小与文件不一致")
	}
	if err := s.record(ctx, audit.Event{Actor: caller.Actor(), Action: "backup.verify",
		Target:  audit.Target{Type: "backup", ID: backupID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(requestID),
		Changes: []audit.FieldChange{
			{Field: "authenticated", After: fmt.Sprint(report.Authenticated)},
			{Field: "file_sha256", After: report.FileSHA256},
		}}); err != nil {
		return backup.VerifyReport{}, err
	}
	return report, nil
}

// ArtifactPathForRecovery 返回一个已验证、未清理且文件存在的备份受控路径，仅供
// internal/restore 在恢复流程内使用；普通公开 API 不返回该路径。调用者必须持有
// backups.read；实际恢复由 restore 服务复核 backups.restore 权限。
func (s *Service) ArtifactPathForRecovery(ctx context.Context, caller account.Caller,
	backupID, requestID string) (string, error) {
	if err := s.authorize(ctx, caller, PermissionRead); err != nil {
		return "", err
	}
	artifact, err := s.lookupArtifact(ctx, backupID)
	if err != nil {
		return "", err
	}
	if artifact.Verification != VerificationVerified ||
		artifact.Cleanup != CleanupRetained || !s.artifactFileExists(artifact) {
		return "", ErrNotDownloadable
	}
	path, err := s.backupPath(artifact)
	if err != nil {
		return "", err
	}
	if err := s.record(ctx, audit.Event{Actor: caller.Actor(), Action: "backup.restore_source",
		Target:  audit.Target{Type: "backup", ID: backupID},
		Outcome: audit.OutcomeSuccess, RequestID: normalizeRequestID(requestID),
		Changes: []audit.FieldChange{{Field: "file_sha256", After: artifact.FileSHA256}}}); err != nil {
		return "", err
	}
	return path, nil
}
