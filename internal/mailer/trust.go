package mailer

import (
	"crypto/x509"
	"fmt"
	"os"
)

// MaxTrustedRootBytes 是单个信任根 PEM 文件的读取上限，避免误读大文件。
const MaxTrustedRootBytes = 1 << 20

// LoadTrustedRoots 构造邮件客户端信任根：以系统根证书池为基线，只追加调用方
// 显式提供的 PEM 文件，不提供关闭校验的入口。任一路径不可读、不是 PEM 或超过
// 大小上限都返回错误（装配期启动失败，不静默忽略）。
func LoadTrustedRoots(paths []string) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, path := range paths {
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("读取邮件信任根失败: %w", readErr)
		}
		if len(data) > MaxTrustedRootBytes {
			return nil, fmt.Errorf("邮件信任根 %s 超过 %d 字节上限", path, MaxTrustedRootBytes)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("邮件信任根不是有效 PEM 证书")
		}
	}
	return pool, nil
}
