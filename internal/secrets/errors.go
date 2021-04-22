package secrets

import "errors"

// 本包的错误都是可安全展示的哨兵错误：消息只说明失败类别，不包含密钥材料、
// 明文、密文或其它敏感字段。调用方应使用 errors.Is 判断类别，并把详细原因
// 保留在受限诊断中；公开响应不得直接输出本包错误的内部原因链。
var (
	// ErrKeyringInvalid 表示密钥环文档结构、版本或内容不符合要求。
	ErrKeyringInvalid = errors.New("secrets: 密钥环文档无效")
	// ErrKeyMaterialMissing 表示没有提供主密钥材料。密码学服务不会自行生成
	// 默认密钥来继续运行。
	ErrKeyMaterialMissing = errors.New("secrets: 未提供主密钥材料")
	// ErrKeyNotFound 表示密钥环中没有密文所引用的 key_id。通常是主密钥文件被
	// 替换或丢失；必须明确失败，不能生成新密钥并覆盖旧数据。
	ErrKeyNotFound = errors.New("secrets: 密钥环中不存在所需的密钥")
	// ErrBindingInvalid 表示用途、对象或所属范围为空、过长或包含非法字符。
	ErrBindingInvalid = errors.New("secrets: 密文绑定信息无效")
	// ErrSealedMalformed 表示密文信封结构损坏或字段不合法。
	ErrSealedMalformed = errors.New("secrets: 密文格式无效")
	// ErrSealedVersionUnsupported 表示密文格式版本不受支持。
	ErrSealedVersionUnsupported = errors.New("secrets: 不支持的密文格式版本")
	// ErrDecryptFailed 表示认证解密失败。错误密钥、密文篡改与绑定信息不匹配
	// 共用该类别，避免向调用方细分可利用的差异。
	ErrDecryptFailed = errors.New("secrets: 密文认证失败")
	// ErrPlaintextTooLarge 表示待加密数据超过本包上限。
	ErrPlaintextTooLarge = errors.New("secrets: 明文超过允许上限")
	// ErrSealedTooLarge 表示待解密的密文超过本包上限。
	ErrSealedTooLarge = errors.New("secrets: 密文超过允许上限")
	// ErrRandomSource 表示安全随机源失败。此时不会产出密文。
	ErrRandomSource = errors.New("secrets: 安全随机源不可用")
	// ErrInsecurePermissions 表示密钥文件权限过宽或安全描述符无法确认。
	ErrInsecurePermissions = errors.New("secrets: 密钥文件权限不安全")
	// ErrFileInvalid 表示密钥文件不是普通文件、为空、过大或不可读。
	ErrFileInvalid = errors.New("secrets: 密钥文件无效")
	// ErrProviderUnavailable 表示宿主密钥提供者调用失败或返回了空文档。
	ErrProviderUnavailable = errors.New("secrets: 密钥提供者不可用")
	// ErrStoreUnavailable 表示重加密存储读写失败。
	ErrStoreUnavailable = errors.New("secrets: 重加密存储不可用")
	// ErrOptionsInvalid 表示调用方传入的选项值不合法（例如批大小超限）。
	ErrOptionsInvalid = errors.New("secrets: 选项无效")
	// ErrRecordStale 表示存储层记录已被其他写入修改，重加密不覆盖并发写入。
	ErrRecordStale = errors.New("secrets: 记录已被并发修改")
	// ErrReencryptIncomplete 表示重加密扫描结束后仍有记录引用源密钥，通常是
	// 存储层 Replace 未真正更新记录或仍有并发写入使用旧密钥。
	ErrReencryptIncomplete = errors.New("secrets: 重加密未完成，仍有记录引用旧密钥")
	// ErrKeyStillReferenced 表示旧密钥仍被数据引用，拒绝退役。
	ErrKeyStillReferenced = errors.New("secrets: 旧密钥仍被数据引用，拒绝退役")
	// ErrCurrentKeyRetire 表示试图退役当前写密钥；必须先轮换出新的写密钥。
	ErrCurrentKeyRetire = errors.New("secrets: 不能退役当前写密钥")
)
