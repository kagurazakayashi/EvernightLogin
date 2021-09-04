package reports

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Artifact 是一份受控报告产物的元数据（不包含宿主路径）。
type Artifact struct {
	Format    Format
	FileName  string
	SHA256    string
	Bytes     int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// ArtifactView 是公开视图中的产物摘要；可用性按当前时间判断，不含路径。
type ArtifactView struct {
	Format    Format    `json:"format"`
	Bytes     int64     `json:"bytes"`
	SHA256    string    `json:"sha256"`
	Available bool      `json:"available"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ArtifactFile 是宿主下载适配使用的受控产物句柄。HostPath 只能交给宿主文件流，
// 禁止写入页面、日志、错误或 API 响应。
type ArtifactFile struct {
	ReportID  string
	Format    Format
	HostPath  string
	Bytes     int64
	SHA256    string
	ExpiresAt time.Time
}

// artifactFileName 返回服务端受控文件名：report_<报告编号>.<格式>。
func artifactFileName(reportID string, format Format) string {
	return reportFilePrefix + reportID + "." + string(format)
}

// validateArtifactName 校验文件名属于受控命名空间且格式后缀匹配。
func validateArtifactName(name string, format Format) bool {
	if filepath.Base(name) != name || !strings.HasPrefix(name, reportFilePrefix) {
		return false
	}
	return strings.HasSuffix(name, "."+string(format))
}

// writeArtifact 把已渲染字节写入受控目录：O_EXCL 独占创建、0600、字节上限、
// SHA-256 与大小记录。失败删除未完成文件，不留下“假成功”产物。
func (s *Service) writeArtifact(reportID string, format Format, data []byte,
	expiresAt time.Time) (Artifact, error) {
	if !format.Valid() {
		return Artifact{}, fmt.Errorf("%w: 报告格式未定义", ErrInvalidRequest)
	}
	if int64(len(data)) > s.maxArtifactBytes {
		return Artifact{}, fmt.Errorf("%w: 报告产物超过字节上限", ErrInvalidRequest)
	}
	name := artifactFileName(reportID, format)
	if !validateArtifactName(name, format) {
		return Artifact{}, ErrArtifactUnsafe
	}
	path := filepath.Join(s.outputDir, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Artifact{}, fmt.Errorf("%w: 报告产物已存在", ErrArtifactUnsafe)
		}
		return Artifact{}, fmt.Errorf("%w: 无法创建报告产物", ErrArtifactUnsafe)
	}
	writeErr := func() error {
		if _, err := file.Write(data); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		return file.Close()
	}()
	if writeErr != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return Artifact{}, fmt.Errorf("%w: 报告产物写入失败", ErrArtifactUnsafe)
	}
	digest := sha256.Sum256(data)
	return Artifact{Format: format, FileName: name,
		SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(data)),
		CreatedAt: s.now(), ExpiresAt: expiresAt.UTC()}, nil
}

// cleanupArtifacts 删除本次生成产生的产物（失败/取消时清理，避免残留可下载的
// 不完整文件）。删除失败只告警，不掩盖真实失败结论。
func (s *Service) cleanupArtifacts(artifacts []Artifact) {
	for _, artifact := range artifacts {
		if !validateArtifactName(artifact.FileName, artifact.Format) {
			continue
		}
		path := filepath.Join(s.outputDir, artifact.FileName)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			s.opts.Logger.Warn("报告产物清理失败", "format", string(artifact.Format))
		}
	}
}

// openArtifact 校验并打开受控产物：文件名/格式/类型/大小/摘要全部匹配才返回
// 宿主路径。摘要重算用于防御目录内产物被替换或截断。
func (s *Service) openArtifact(stored Artifact) (string, error) {
	if !validateArtifactName(stored.FileName, stored.Format) {
		return "", ErrArtifactUnsafe
	}
	if len(stored.SHA256) != hex.EncodedLen(sha256.Size) {
		return "", fmt.Errorf("%w: 报告产物摘要元数据不完整", ErrArtifactUnsafe)
	}
	path := filepath.Join(s.outputDir, stored.FileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: 报告产物不存在或类型不安全", ErrArtifactUnsafe)
	}
	if info.Size() != stored.Bytes {
		return "", fmt.Errorf("%w: 报告产物大小不符", ErrArtifactUnsafe)
	}
	digest, err := fileSHA256(path)
	if err != nil {
		return "", fmt.Errorf("%w: 报告产物读取失败", ErrArtifactUnsafe)
	}
	if digest != stored.SHA256 {
		return "", fmt.Errorf("%w: 报告产物摘要不符", ErrArtifactUnsafe)
	}
	return path, nil
}

// fileSHA256 流式计算文件摘要。
func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
