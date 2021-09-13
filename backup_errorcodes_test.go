package login

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/backup"
)

// TestBackupErrorCodesReuseRegisteredCodes 验证备份模块只复用已登记设计错误码、
// 不新增注册码，且领域哨兵到根包错误码的投影稳定（步骤 80）。
func TestBackupErrorCodesReuseRegisteredCodes(t *testing.T) {
	if count := len(RegisteredErrorCodes()); count != 48 {
		t.Fatalf("错误码注册表数量 = %d，期望 48（备份模块不新增错误码）", count)
	}
	tests := []struct {
		name string
		err  error
		want ErrorCode
	}{
		{"快照失败", fmt.Errorf("%w: %v", backup.ErrSnapshotFailed, errors.New("db")), CodeBackupFailed},
		{"附件不一致", backup.ErrAttachmentInconsistent, CodeBackupFailed},
		{"容量超限", backup.ErrTooLarge, CodeBackupFailed},
		{"清理失败", backup.ErrCleanupFailed, CodeBackupFailed},
		{"数据读写失败", backup.ErrBackupIO, CodeBackupFailed},
		{"取消禁止", backup.ErrCancelForbidden, CodeBackupCancelForbidden},
		{"解密失败", backup.ErrDecryptFailed, CodeBackupDecryptFailed},
		{"完整性失败", backup.ErrIntegrityFailed, CodeBackupInvalid},
		{"格式非法", backup.ErrFormatInvalid, CodeBackupInvalid},
		{"版本不支持", backup.ErrVersionUnsupported, CodeBackupVersionUnsupported},
		{"已取消", backup.ErrCancelled, CodeTaskCancelled},
		{"取消竞争", backup.ErrCancelConflict, CodeTaskCancelConflict},
		{"超时", backup.ErrTimeout, CodeTaskTimeout},
		{"审计不可用", backup.ErrAuditUnavailable, CodeAuditWriteFailed},
		{"输出目录不安全", backup.ErrOutputDirUnsafe, CodeExportPathUnsafe},
		{"越权", backup.ErrAccessDenied, CodeAccessDenied},
		{"请求非法", backup.ErrInvalidRequest, CodeReqInvalid},
		{"配置非法", backup.ErrOptionsInvalid, CodeReqInvalid},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got := ErrorCode(backup.CodeOf(testCase.err))
			if got != testCase.want {
				t.Fatalf("CodeOf(%v) = %s，期望 %s", testCase.err, got, testCase.want)
			}
			if !got.Valid() {
				t.Fatalf("映射错误码 %s 未在注册表登记", got)
			}
		})
	}
}
