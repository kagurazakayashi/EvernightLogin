package secrets

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

const (
	// KeyringFormat 是密钥环文档的格式标识。文档格式与密文信封格式分别演进，
	// 修改任何字段都必须提升对应版本号。
	KeyringFormat = "evernight-login-keyring"
	// KeyringVersion 是当前支持的密钥环文档版本。
	KeyringVersion = 1
	// KeyMaterialSize 是单个密钥材料的字节数，固定为 AES-256 的 32 字节。
	KeyMaterialSize = 32
	// MaxKeyIDBytes 是 key_id 的最大长度。
	MaxKeyIDBytes = 64
	// MaxKeyringKeys 是单个密钥环允许保存的密钥数量上限（含当前写密钥）。
	MaxKeyringKeys = 16
	// MaxKeyringDocumentBytes 是密钥环文档的大小上限，与配置秘密文件上限一致。
	MaxKeyringDocumentBytes = 64 * 1024
)

// keyringDocument 是密钥环文件的 JSON 结构。Material 是 base64 编码的 32 字节
// 原始密钥材料；密钥环文件必须按受保护文件处理，不能提交到版本库。
type keyringDocument struct {
	Format       string         `json:"format"`
	Version      int            `json:"version"`
	CurrentKeyID string         `json:"current_key_id"`
	Keys         []keyringEntry `json:"keys"`
}

// keyringEntry 是密钥环中的一个密钥。
type keyringEntry struct {
	ID        string `json:"id"`
	Material  string `json:"material"`
	CreatedAt string `json:"created_at,omitempty"`
}

// keyringKey 是校验后的密钥条目；material 在 Keyring 生命周期内不可变。
type keyringKey struct {
	material  []byte
	createdAt time.Time
}

// Keyring 是一组已加载的密钥及其当前写密钥。它同时保存当前写密钥与历史读
// 密钥：Seal 只使用当前写密钥，Open 可以使用任一密钥，因此轮换新密钥后旧密文
// 仍可读取。
//
// Keyring 构造后不可变，方法返回新的 Keyring，不修改接收者；多个并发读取安全。
// 密钥材料不导出，只通过 Document 以 JSON 文档形式输出，调用方必须写入受保护
// 文件，不能写入日志、数据库或普通临时目录。
type Keyring struct {
	currentKeyID string
	keys         map[string]keyringKey
}

// ParseKeyringDocument 解析并校验密钥环 JSON 文档。文档要求严格模式：未知字段、
// 重复 key_id、非法格式/版本、非 32 字节密钥材料、缺失当前密钥都会失败。
func ParseKeyringDocument(doc []byte) (*Keyring, error) {
	if len(doc) == 0 {
		return nil, fmt.Errorf("%w: 文档为空", ErrKeyMaterialMissing)
	}
	if len(doc) > MaxKeyringDocumentBytes {
		return nil, fmt.Errorf("%w: 文档超过 %d 字节", ErrKeyringInvalid, MaxKeyringDocumentBytes)
	}
	var parsed keyringDocument
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("%w: 无法解析 JSON 文档", ErrKeyringInvalid)
	}
	// 只接受单个 JSON 值，拒绝在文档后追加第二个值来绕过解析。
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: 文档只能包含一个 JSON 对象", ErrKeyringInvalid)
	}
	return newKeyringFromDocument(parsed)
}

// newKeyringFromDocument 校验文档字段并构造 Keyring。
func newKeyringFromDocument(doc keyringDocument) (*Keyring, error) {
	if doc.Format != KeyringFormat {
		return nil, fmt.Errorf("%w: 不支持的格式标识", ErrKeyringInvalid)
	}
	if doc.Version != KeyringVersion {
		return nil, fmt.Errorf("%w: 不支持的文档版本 %d", ErrKeyringInvalid, doc.Version)
	}
	if err := validateToken("当前写密钥编号", doc.CurrentKeyID, MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("%w: 密钥环至少需要一个密钥", ErrKeyringInvalid)
	}
	if len(doc.Keys) > MaxKeyringKeys {
		return nil, fmt.Errorf("%w: 密钥数量超过 %d 个上限", ErrKeyringInvalid, MaxKeyringKeys)
	}
	keys := make(map[string]keyringKey, len(doc.Keys))
	for _, entry := range doc.Keys {
		if err := validateToken("密钥编号", entry.ID, MaxKeyIDBytes); err != nil {
			return nil, err
		}
		if _, exists := keys[entry.ID]; exists {
			return nil, fmt.Errorf("%w: 密钥编号重复", ErrKeyringInvalid)
		}
		material, err := base64.StdEncoding.Strict().DecodeString(entry.Material)
		if err != nil {
			return nil, fmt.Errorf("%w: 密钥材料不是有效的 base64 编码", ErrKeyringInvalid)
		}
		if err := validateKeyMaterial(material); err != nil {
			return nil, err
		}
		key := keyringKey{material: material}
		if entry.CreatedAt != "" {
			createdAt, err := time.Parse(time.RFC3339, entry.CreatedAt)
			if err != nil {
				return nil, fmt.Errorf("%w: 密钥创建时间不是 RFC3339 格式", ErrKeyringInvalid)
			}
			key.createdAt = createdAt.UTC()
		}
		keys[entry.ID] = key
	}
	if _, ok := keys[doc.CurrentKeyID]; !ok {
		return nil, fmt.Errorf("%w: 当前写密钥不在密钥列表中", ErrKeyringInvalid)
	}
	return &Keyring{currentKeyID: doc.CurrentKeyID, keys: keys}, nil
}

// CurrentKeyID 返回当前写密钥编号。编号不是秘密，可用于日志和密文检查。
func (k *Keyring) CurrentKeyID() string {
	if k == nil {
		return ""
	}
	return k.currentKeyID
}

// KeyIDs 返回全部密钥编号，按字典序排列（包含当前写密钥和历史读密钥）。
func (k *Keyring) KeyIDs() []string {
	if k == nil {
		return nil
	}
	ids := make([]string, 0, len(k.keys))
	for id := range k.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// HasKey 报告密钥环是否包含指定 key_id。
func (k *Keyring) HasKey(keyID string) bool {
	if k == nil {
		return false
	}
	_, ok := k.keys[keyID]
	return ok
}

// keyMaterial 返回指定密钥材料的内部引用；仅限本包派生加密密钥使用。调用方
// 不得修改返回值或把它暴露到包外。
func (k *Keyring) keyMaterial(keyID string) ([]byte, bool) {
	key, ok := k.keys[keyID]
	if !ok {
		return nil, false
	}
	return key.material, true
}

// Document 把密钥环序列化为 JSON 文档，供调用方写入受保护文件。返回值包含
// 原始密钥材料，属于高度敏感数据：只允许写入受保护的主密钥文件，禁止写入
// 日志、数据库、报告或普通临时文件。
func (k *Keyring) Document() ([]byte, error) {
	if k == nil || len(k.keys) == 0 {
		return nil, fmt.Errorf("%w: 密钥环为空", ErrKeyMaterialMissing)
	}
	ids := k.KeyIDs()
	doc := keyringDocument{
		Format:       KeyringFormat,
		Version:      KeyringVersion,
		CurrentKeyID: k.currentKeyID,
		Keys:         make([]keyringEntry, 0, len(ids)),
	}
	for _, id := range ids {
		key := k.keys[id]
		entry := keyringEntry{
			ID:       id,
			Material: base64.StdEncoding.EncodeToString(key.material),
		}
		if !key.createdAt.IsZero() {
			entry.CreatedAt = key.createdAt.UTC().Format(time.RFC3339)
		}
		doc.Keys = append(doc.Keys, entry)
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: 无法序列化密钥环文档", ErrKeyringInvalid)
	}
	return append(encoded, '\n'), nil
}

// validateKeyMaterial 校验密钥材料长度正确且不是全零。全零材料通常表示调用方
// 使用了未初始化的缓冲区或错误配置；继续用它会生成可被任意人解密的密文，因此
// 默认拒绝，而不是把错误配置变成“加密成功”。
func validateKeyMaterial(material []byte) error {
	if len(material) != KeyMaterialSize {
		return fmt.Errorf("%w: 密钥材料必须为 %d 字节", ErrKeyringInvalid, KeyMaterialSize)
	}
	allZero := true
	for _, b := range material {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: 密钥材料不能全为零", ErrKeyringInvalid)
	}
	return nil
}

// RotateTo 返回一个加入新密钥并把新密钥设为当前写密钥的新密钥环。已有密钥
// 全部保留为历史读密钥，因此轮换后旧密文仍可读取；旧密钥的退役必须经过
// Rotator.RetireKey 确认没有数据引用。
//
// newMaterial 必须正好 KeyMaterialSize 字节；调用方应使用 GenerateKeyMaterial
// 或宿主自己的安全随机源生成。newKeyID 不能与已有密钥重复。
func (k *Keyring) RotateTo(newKeyID string, newMaterial []byte, now time.Time) (*Keyring, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: 密钥环为空", ErrKeyMaterialMissing)
	}
	if err := validateToken("新密钥编号", newKeyID, MaxKeyIDBytes); err != nil {
		return nil, err
	}
	if k.HasKey(newKeyID) {
		return nil, fmt.Errorf("%w: 新密钥编号已存在", ErrKeyringInvalid)
	}
	if err := validateKeyMaterial(newMaterial); err != nil {
		return nil, err
	}
	if len(k.keys) >= MaxKeyringKeys {
		return nil, fmt.Errorf("%w: 密钥数量超过 %d 个上限", ErrKeyringInvalid, MaxKeyringKeys)
	}
	keys := make(map[string]keyringKey, len(k.keys)+1)
	for id, key := range k.keys {
		keys[id] = keyringKey{material: append([]byte(nil), key.material...), createdAt: key.createdAt}
	}
	keys[newKeyID] = keyringKey{
		material:  append([]byte(nil), newMaterial...),
		createdAt: now.UTC(),
	}
	return &Keyring{currentKeyID: newKeyID, keys: keys}, nil
}

// WithoutKey 返回移除指定历史读密钥的新密钥环。它拒绝移除当前写密钥。该方
// 法本身不检查数据引用；正常路径应使用 Rotator.RetireKey，由它先确认没有
// 密文继续引用该密钥，避免无提示删除仍被使用的旧密钥。
func (k *Keyring) WithoutKey(keyID string) (*Keyring, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: 密钥环为空", ErrKeyMaterialMissing)
	}
	if keyID == k.currentKeyID {
		return nil, ErrCurrentKeyRetire
	}
	if !k.HasKey(keyID) {
		return nil, ErrKeyNotFound
	}
	keys := make(map[string]keyringKey, len(k.keys)-1)
	for id, key := range k.keys {
		if id == keyID {
			continue
		}
		keys[id] = keyringKey{material: append([]byte(nil), key.material...), createdAt: key.createdAt}
	}
	return &Keyring{currentKeyID: k.currentKeyID, keys: keys}, nil
}

// GenerateKeyMaterial 使用 crypto/rand 生成 KeyMaterialSize 字节密钥材料。
// 随机源失败时返回错误，绝不回退到弱随机或固定值。
func GenerateKeyMaterial() ([]byte, error) {
	material := make([]byte, KeyMaterialSize)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		return nil, fmt.Errorf("%w: 无法生成密钥材料", ErrRandomSource)
	}
	return material, nil
}

// GenerateKeyring 生成只含一个当前写密钥的新密钥环，用于首次初始化。密钥材料
// 来自安全随机源；本包不提供任何硬编码默认密钥或“空密钥环自动生成”的隐式
// 回退路径。
func GenerateKeyring(keyID string, now time.Time) (*Keyring, error) {
	if err := validateToken("密钥编号", keyID, MaxKeyIDBytes); err != nil {
		return nil, err
	}
	material, err := GenerateKeyMaterial()
	if err != nil {
		return nil, err
	}
	return &Keyring{
		currentKeyID: keyID,
		keys: map[string]keyringKey{
			keyID: {material: material, createdAt: now.UTC()},
		},
	}, nil
}
