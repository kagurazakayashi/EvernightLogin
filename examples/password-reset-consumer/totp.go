// Copyright (c) KagurazakaYashi(KagurazakaMiyabi)
// EvernightLogin is licensed under Mulan PSL v2.

package main

// 本文件按 RFC 6238（HMAC-SHA1、6 位、30 秒步长）计算 TOTP 验证码。
//
// 它等价于用户手机上的验证器 App：示例/回归程序据此完成公开 Go 门面的 TOTP
// 绑定与第二步验证，不使用任何伪造的“强认证已完成”事实或 internal 入口。

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// totpCode 按 RFC 6238 计算 base32 种子的当前验证码。
func totpCode(encodedSecret string, at time.Time) (string, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(encodedSecret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return "", fmt.Errorf("解码 TOTP 种子失败: %w", err)
	}
	step := uint64(at.Unix() / 30)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], step)
	mac := hmac.New(sha1.New, secret)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1000000), nil
}

// totpCodeNextStep 等到下一个 30 秒时间步再计算 TOTP，避免与刚完成的绑定/上一步
// 验证复用同一个时间步而被服务端的防重放策略拒绝（真实用户等待下一码即可）。
func totpCodeNextStep(secret string) (string, error) {
	const stepSeconds = int64(30)
	now := time.Now().Unix()
	wait := stepSeconds - now%stepSeconds + 1
	if wait > 0 {
		time.Sleep(time.Duration(wait) * time.Second)
	}
	return totpCode(secret, time.Now())
}
