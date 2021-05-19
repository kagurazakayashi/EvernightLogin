package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// PasswordScheme 是正式密码哈希方案稳定标识。只允许成熟库实现的 Argon2id，
	// 不支持自造算法或可逆编码。
	PasswordScheme = "argon2id"
	// PasswordSchemeVersion 是 Argon2 版本号（RFC 9106 / PHC 使用 v=19）。
	PasswordSchemeVersion = 19
	// 下列参数是工具级上下界：默认值取 OWASP 2023 对 Argon2id 的最低推荐组合
	// （19 MiB 内存、2 次迭代、1 并行度），生产可通过配置提升；测试可使用下限
	// 8 MiB/1 次以控制耗时，但任何低于下限的参数在解析旧哈希时仍可验证（便于
	// 升级），新哈希必须满足 Validate。
	MinMemoryKiB     uint32 = 8 * 1024
	DefaultMemoryKiB uint32 = 19 * 1024
	MaxMemoryKiB     uint32 = 256 * 1024
	// MinIterations/DefaultIterations/MaxIterations 是时间成本参数范围。
	MinIterations     uint32 = 1
	DefaultIterations uint32 = 2
	MaxIterations     uint32 = 10
	// MinParallelism/DefaultParallelism/MaxParallelism 是并行度参数范围。
	MinParallelism     uint8 = 1
	DefaultParallelism uint8 = 1
	MaxParallelism     uint8 = 8
	// MinSaltBytes/DefaultSaltBytes/MaxSaltBytes 是随机盐长度范围。
	MinSaltBytes     uint32 = 16
	DefaultSaltBytes uint32 = 16
	MaxSaltBytes     uint32 = 32
	// MinKeyBytes/DefaultKeyBytes/MaxKeyBytes 是派生长度范围。
	MinKeyBytes     uint32 = 16
	DefaultKeyBytes uint32 = 32
	MaxKeyBytes     uint32 = 64
)

// 哈希实现只依赖 golang.org/x/crypto v0.58.0 的 argon2（模块由 Go 官方维护，
// BSD-3-Clause 许可，锁定固定版本；不使用自造密码学或其他密码学实现）。
//
// ErrPasswordHashInvalid 表示存储的密码哈希格式非法、参数越界或字段长度异常。
// 它不能导致放行：登录路径按凭据损坏处理并拒绝（fail-closed）。
var ErrPasswordHashInvalid = errors.New("密码哈希格式无效")

// Params 是一组有界的 Argon2id 参数。零值使用 DefaultParams；新哈希必须满足
// Validate；解析历史哈希时允许低于下限但绝不允许超过上限，避免损坏数据或恶意
// 行造成超大内存/时间开销。
type Params struct {
	// MemoryKiB 是 Argon2 内存成本（KiB）。
	MemoryKiB uint32
	// Iterations 是时间成本（迭代次数）。
	Iterations uint32
	// Parallelism 是并行度（lane 数）。
	Parallelism uint8
	// SaltLength 是随机盐字节数。
	SaltLength uint32
	// KeyLength 是派生摘要字节数。
	KeyLength uint32
}

// DefaultParams 返回默认的 Argon2id 参数（OWASP 2023 最低推荐组合）。
func DefaultParams() Params {
	return Params{
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
		SaltLength:  DefaultSaltBytes,
		KeyLength:   DefaultKeyBytes,
	}
}

// Validate 校验新哈希参数是否都在允许范围内，并保证 Argon2 库的硬性要求
// （内存至少 8 KiB/并行度）。越界返回 ErrOptionsInvalid，不会静默截断。
func (p Params) Validate() error {
	if p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > MaxMemoryKiB {
		return fmt.Errorf("%w: Argon2 内存参数必须在 %d～%d KiB 之间",
			ErrOptionsInvalid, MinMemoryKiB, MaxMemoryKiB)
	}
	if p.Iterations < MinIterations || p.Iterations > MaxIterations {
		return fmt.Errorf("%w: Argon2 迭代次数必须在 %d～%d 之间",
			ErrOptionsInvalid, MinIterations, MaxIterations)
	}
	if p.Parallelism < MinParallelism || p.Parallelism > MaxParallelism {
		return fmt.Errorf("%w: Argon2 并行度必须在 %d～%d 之间",
			ErrOptionsInvalid, MinParallelism, MaxParallelism)
	}
	if p.MemoryKiB < 8*uint32(p.Parallelism) {
		return fmt.Errorf("%w: Argon2 内存参数低于并行度硬性要求", ErrOptionsInvalid)
	}
	if p.SaltLength < MinSaltBytes || p.SaltLength > MaxSaltBytes {
		return fmt.Errorf("%w: 盐长度必须在 %d～%d 字节之间",
			ErrOptionsInvalid, MinSaltBytes, MaxSaltBytes)
	}
	if p.KeyLength < MinKeyBytes || p.KeyLength > MaxKeyBytes {
		return fmt.Errorf("%w: 摘要长度必须在 %d～%d 字节之间",
			ErrOptionsInvalid, MinKeyBytes, MaxKeyBytes)
	}
	return nil
}

// String 返回脱敏的参数摘要，用于审计/日志与测试（不含盐与摘要）。
func (p Params) String() string {
	return fmt.Sprintf("%s(m=%d,t=%d,p=%d,k=%d)", PasswordScheme, p.MemoryKiB, p.Iterations,
		p.Parallelism, p.KeyLength)
}

// WeakerThan 报告 p 的成本参数是否低于 other（用于判断登录成功后是否需要按当前
// 策略重新哈希）。盐/摘要长度差异也视为需要升级。
func (p Params) WeakerThan(other Params) bool {
	switch {
	case p.MemoryKiB < other.MemoryKiB,
		p.Iterations < other.Iterations,
		p.Parallelism < other.Parallelism,
		p.SaltLength < other.SaltLength,
		p.KeyLength < other.KeyLength:
		return true
	default:
		return false
	}
}

// HashPassword 用给定参数生成 Argon2id PHC 编码字符串：
//
//	$argon2id$v=19$m=<KiB>,t=<iterations>,p=<parallelism>$<b64 salt>$<b64 hash>
//
// 盐来自 random（nil 使用 crypto/rand.Reader）。参数必须是合法的新哈希参数；
// 明文长度超过 MaxPasswordBytes 时拒绝，避免把超大输入带进计算。
func HashPassword(plain string, params Params, random io.Reader) (string, error) {
	if len(plain) > MaxPasswordBytes {
		return "", fmt.Errorf("%w: 密码输入过长", ErrInvalidRequest)
	}
	if err := params.Validate(); err != nil {
		return "", err
	}
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, params.SaltLength)
	if _, err := io.ReadFull(random, salt); err != nil {
		return "", fmt.Errorf("%w: 无法生成密码盐", ErrOptionsInvalid)
	}
	derived := argon2.IDKey([]byte(plain), salt, params.Iterations, params.MemoryKiB,
		params.Parallelism, params.KeyLength)
	return encodePasswordHash(params, salt, derived), nil
}

// encodePasswordHash 把参数、盐与摘要编码为 PHC 字符串。
func encodePasswordHash(params Params, salt, derived []byte) string {
	return fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		PasswordScheme, PasswordSchemeVersion, params.MemoryKiB, params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(derived),
	)
}

// VerifyResult 是一次哈希校验结果。
type VerifyResult struct {
	// Matched 表示密码与摘要一致（恒定时间比较）。
	Matched bool
	// Params 是存储哈希使用的参数，供调用方判断是否需要升级。
	Params Params
}

// VerifyPassword 解析 PHC 哈希并对明文做恒定时间比较。
//
// 安全语义：
//   - 解析失败、参数越界、盐/摘要长度异常返回 ErrPasswordHashInvalid；调用方
//     必须按凭据损坏拒绝登录，绝不能把解析失败当作“密码正确”。
//   - 比较使用 subtle.ConstantTimeCompare，避免字节级提前返回。
//   - 参数上限与应用参数上界一致，即使数据库中写入超大参数也不会触发 OOM/长耗时。
func VerifyPassword(encoded, plain string) (VerifyResult, error) {
	params, salt, expected, err := parsePasswordHash(encoded)
	if err != nil {
		return VerifyResult{}, err
	}
	if len(plain) > MaxPasswordBytes {
		return VerifyResult{Params: params}, nil
	}
	derived := argon2.IDKey([]byte(plain), salt, params.Iterations, params.MemoryKiB,
		params.Parallelism, params.KeyLength)
	if len(expected) != len(derived) {
		return VerifyResult{Params: params}, nil
	}
	return VerifyResult{
		Matched: subtle.ConstantTimeCompare(expected, derived) == 1,
		Params:  params,
	}, nil
}

// parsePasswordHash 严格解析 PHC 编码并校验参数边界。
func parsePasswordHash(encoded string) (Params, []byte, []byte, error) {
	if len(encoded) < 32 || len(encoded) > 512 || !strings.HasPrefix(encoded, "$"+PasswordScheme+"$") {
		return Params{}, nil, nil, fmt.Errorf("%w: 方案前缀无效", ErrPasswordHashInvalid)
	}
	parts := strings.Split(encoded, "$")
	// 形如 ["", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash]。
	if len(parts) != 6 {
		return Params{}, nil, nil, fmt.Errorf("%w: 字段数量无效", ErrPasswordHashInvalid)
	}
	versionText, ok := strings.CutPrefix(parts[2], "v=")
	if !ok {
		return Params{}, nil, nil, fmt.Errorf("%w: 版本字段无效", ErrPasswordHashInvalid)
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version != PasswordSchemeVersion {
		return Params{}, nil, nil, fmt.Errorf("%w: 不支持的哈希版本", ErrPasswordHashInvalid)
	}
	var params Params
	values := strings.Split(parts[3], ",")
	if len(values) != 3 {
		return Params{}, nil, nil, fmt.Errorf("%w: 参数字段无效", ErrPasswordHashInvalid)
	}
	for _, value := range values {
		name, text, found := strings.Cut(value, "=")
		if !found {
			return Params{}, nil, nil, fmt.Errorf("%w: 参数格式无效", ErrPasswordHashInvalid)
		}
		number, parseErr := strconv.ParseUint(text, 10, 32)
		if parseErr != nil {
			return Params{}, nil, nil, fmt.Errorf("%w: 参数数值无效", ErrPasswordHashInvalid)
		}
		switch name {
		case "m":
			params.MemoryKiB = uint32(number)
		case "t":
			params.Iterations = uint32(number)
		case "p":
			if number > 255 {
				return Params{}, nil, nil, fmt.Errorf("%w: 并行度越界", ErrPasswordHashInvalid)
			}
			params.Parallelism = uint8(number)
		default:
			return Params{}, nil, nil, fmt.Errorf("%w: 未知参数 %q", ErrPasswordHashInvalid, name)
		}
	}
	// 历史哈希允许低于新哈希下限（便于升级），但绝不允许超过上限或违反库硬性要求。
	if params.MemoryKiB == 0 || params.MemoryKiB > MaxMemoryKiB ||
		params.Iterations == 0 || params.Iterations > MaxIterations ||
		params.Parallelism == 0 || params.Parallelism > MaxParallelism ||
		params.MemoryKiB < 8*uint32(params.Parallelism) {
		return Params{}, nil, nil, fmt.Errorf("%w: 参数超出安全边界", ErrPasswordHashInvalid)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return Params{}, nil, nil, fmt.Errorf("%w: 盐数据无效", ErrPasswordHashInvalid)
	}
	derived, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(derived) < 8 || len(derived) > 128 {
		return Params{}, nil, nil, fmt.Errorf("%w: 摘要数据无效", ErrPasswordHashInvalid)
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(derived))
	return params, salt, derived, nil
}
