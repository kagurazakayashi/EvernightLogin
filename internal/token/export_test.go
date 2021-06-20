package token

import (
	"context"
	"crypto/ecdsa"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
)

// 本文件只在测试构建中出现（_test.go），为外部测试包暴露受控测试接缝；不进入
// 生产二进制。用于构造负向令牌（任意声明/头部）与检查私钥解密，不扩大生产 API。

// SignClaimsForTest 用给定密钥对预制 payload 签名。
func (s *Service) SignClaimsForTest(record KeyRecord, payload []byte, typ string) (string, error) {
	return s.signClaims(record, payload, typ)
}

// OpenPrivateKeyForTest 解密签名私钥（测试构造负向令牌/断言密钥类型）。
func (s *Service) OpenPrivateKeyForTest(record KeyRecord) (*ecdsa.PrivateKey, error) {
	return s.openPrivateKey(record)
}

// OptionsForTest 返回构造用的 Options 副本（测试校验配置）。
func (s *Service) OptionsForTest() Options { return s.opts }

// EnsureActiveKeyForTest 返回/引导 active 密钥（测试检查引导路径）。
func (s *Service) EnsureActiveKeyForTest(ctx context.Context) (KeyRecord, error) {
	return s.ensureActiveKey(ctx)
}

var _ = audit.OutcomeSuccess
