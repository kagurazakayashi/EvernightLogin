package secrets

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"
)

const (
	// DefaultReencryptBatchSize 是重加密默认每批读取的记录数。
	DefaultReencryptBatchSize = 100
	// MaxReencryptBatchSize 是调用方可指定的最大批大小，避免一次读入过多记录。
	MaxReencryptBatchSize = 1000
)

// SealedRecord 是存储层读出的一条带绑定信息的密文记录。
type SealedRecord struct {
	// ID 是存储内稳定且可比较的记录标识，用于分批游标与并发更新检查。
	ID string
	// Binding 是该记录密文绑定的用途、对象与所属范围，存储在记录自身的列里。
	Binding Binding
	// Sealed 是当前的完整密文信封。
	Sealed []byte
}

// SealedStore 是重加密所需的最小持久化契约，由后续接入数据库仓储的步骤实现。
// 本步不提供生产数据库实现，测试使用内存替身；接口本身不是对空占位的承诺，
// 而是重加密算法的真实依赖。
//
// 实现约定：
//   - LoadBatch 按 ID 升序返回“当前仍以 sourceKeyID 加密、且 ID 大于 afterID”
//     的最多 limit 条记录。实现可以用 key_id 列过滤，也可以解析信封头；两种
//     方式都必须返回真实当前状态。afterID 为空表示从头开始。
//   - Replace 用 newSealed 原子替换 oldSealed 对应的记录，并保证 oldSealed 与
//     存储中的当前值一致，否则返回 ErrRecordStale，不覆盖并发写入。若表中有
//     key_id 列，实现应同时把它更新为 KeyIDOf(newSealed) 的结果。
//   - 两个方法都必须传播 ctx；存储不可用时返回安全错误，不返回记录内容以外
//     的敏感信息。
type SealedStore interface {
	LoadBatch(ctx context.Context, sourceKeyID, afterID string, limit int) ([]SealedRecord, error)
	Replace(ctx context.Context, id string, oldSealed, newSealed []byte) error
}

// Rotator 负责密钥轮换、可中断重加密与旧密钥退役保护。它不拥有数据库连接，
// 不启动后台任务；调用方传入密钥环与存储契约，并负责在轮换后持久化新密钥环
// 文档、切换服务使用的 Sealer。
type Rotator struct {
	ring   *Keyring
	sealer *Sealer
	store  SealedStore
	logger *slog.Logger
}

// NewRotator 基于当前密钥环和存储创建 Rotator。store 可以为 nil，此时只能
// 使用 Rotate 生成新密钥环，任何重加密/退役操作都会明确失败而不是假装完成。
func NewRotator(ring *Keyring, store SealedStore, logger *slog.Logger) (*Rotator, error) {
	sealer, err := NewSealer(ring, logger)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = discardLogger()
	}
	return &Rotator{ring: ring, sealer: sealer, store: store, logger: logger}, nil
}

// CurrentKeyID 返回当前写密钥编号。
func (r *Rotator) CurrentKeyID() string {
	if r == nil {
		return ""
	}
	return r.ring.CurrentKeyID()
}

// Rotate 生成新的安全随机密钥材料，把密钥环切换到新写密钥并保留全部旧密钥为
// 历史读密钥。它只返回新密钥环，不写文件、不重加密数据；调用方必须用
// WriteProtectedFile 持久化新密钥环，再创建新的 Rotator/Sealer 处理历史数据。
// 轮换日志只包含密钥编号与数量，不包含密钥材料。
func (r *Rotator) Rotate(newKeyID string) (*Keyring, error) {
	if r == nil || r.ring == nil {
		return nil, fmt.Errorf("%w: Rotator 未初始化", ErrKeyMaterialMissing)
	}
	material, err := GenerateKeyMaterial()
	if err != nil {
		return nil, err
	}
	rotated, err := r.ring.RotateTo(newKeyID, material, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	r.logger.Info("密钥环已轮换",
		"previous_key_id", maskKeyID(r.ring.CurrentKeyID()),
		"current_key_id", maskKeyID(newKeyID),
		"historical_key_count", len(rotated.keys)-1,
	)
	return rotated, nil
}

// ReencryptOptions 控制一次重加密的范围与批大小。
type ReencryptOptions struct {
	// SourceKeyIDs 是要重加密的旧密钥编号；为空表示当前写密钥之外的所有
	// 历史读密钥。调用方不能把当前写密钥列为源密钥。
	SourceKeyIDs []string
	// BatchSize 是每批读取记录数；0 使用 DefaultReencryptBatchSize。
	BatchSize int
}

// ReencryptReport 汇总一次重加密的进度。即使返回错误也会给出已完成部分，便于
// 调用方记录真实状态。
type ReencryptReport struct {
	// SourceKeyIDs 是本次处理的源密钥编号（已排序去重）。
	SourceKeyIDs []string
	// Updated 是已成功替换为新写密钥的记录数。
	Updated int
	// Remaining 是完成扫描后仍引用源密钥的记录数；成功完成时必然为 0。
	Remaining int
}

// Reencrypt 把源旧密钥加密的记录逐条重加密为当前写密钥。
//
// 可中断与恢复语义：每条记录在存储层单独原子替换，成功替换的记录 key_id 变为
// 当前写密钥，失败或取消时已完成记录保持新密钥、未处理记录保持旧密钥，二者都
// 可以正常解密。重新调用 Reencrypt 会以源密钥重新扫描，自然跳过已经更新的记录，
// 因此不需要额外的进度表或补偿日志。调用方应在重试前确认服务没有其它写入者
// 仍在使用旧密钥加密新数据；本函数在每个源密钥处理完后会再次扫描，若仍有记录
// 引用它则返回 ErrReencryptIncomplete，不把未完成当成成功。
//
// 任何记录无法解析、无法解密、绑定信息不匹配或替换时发生并发修改都会中止并
// 返回错误，错误只包含记录 ID、密钥编号等非秘密信息，不含明文或密钥材料。
func (r *Rotator) Reencrypt(ctx context.Context, opts ReencryptOptions) (ReencryptReport, error) {
	var report ReencryptReport
	if r == nil || r.sealer == nil || r.store == nil {
		return report, fmt.Errorf("%w: Rotator 缺少密钥环或存储", ErrStoreUnavailable)
	}
	ctx = normalizeContext(ctx)
	sourceKeyIDs, err := r.resolveSourceKeyIDs(opts.SourceKeyIDs)
	if err != nil {
		return report, err
	}
	batchSize, err := reencryptBatchSize(opts.BatchSize)
	if err != nil {
		return report, err
	}
	report.SourceKeyIDs = sourceKeyIDs
	if len(sourceKeyIDs) == 0 {
		r.logger.Info("没有需要重加密的旧密钥", "current_key_id", maskKeyID(r.ring.CurrentKeyID()))
		return report, nil
	}
	r.logger.Info("开始重加密秘密记录",
		"source_key_ids", sourceKeyIDs,
		"current_key_id", maskKeyID(r.ring.CurrentKeyID()),
		"batch_size", batchSize,
	)
	for _, sourceKeyID := range sourceKeyIDs {
		updatedForKey, err := r.reencryptKey(ctx, sourceKeyID, batchSize, &report)
		if err != nil {
			r.logger.Warn("重加密中断",
				"source_key_id", maskKeyID(sourceKeyID),
				"updated", report.Updated,
			)
			return report, err
		}
		remaining, err := r.countReferences(ctx, sourceKeyID, batchSize)
		if err != nil {
			return report, err
		}
		report.Remaining = remaining
		if remaining > 0 {
			r.logger.Error("重加密后仍存在旧密钥引用",
				"source_key_id", maskKeyID(sourceKeyID),
				"remaining", remaining,
			)
			return report, fmt.Errorf("%w: key_id=%s 仍被 %d 条记录引用",
				ErrReencryptIncomplete, maskKeyID(sourceKeyID), remaining)
		}
		r.logger.Info("旧密钥记录重加密完成",
			"source_key_id", maskKeyID(sourceKeyID),
			"updated", updatedForKey,
		)
	}
	r.logger.Info("秘密记录重加密完成", "updated", report.Updated)
	return report, nil
}

// reencryptKey 处理单个源密钥的全部记录，返回该密钥下本次更新的记录数。
func (r *Rotator) reencryptKey(ctx context.Context, sourceKeyID string, batchSize int, report *ReencryptReport) (int, error) {
	afterID := ""
	updated := 0
	for {
		if err := ctx.Err(); err != nil {
			return updated, err
		}
		records, err := r.store.LoadBatch(ctx, sourceKeyID, afterID, batchSize)
		if err != nil {
			return updated, storeLoadFailure(ctx, err, "读取待重加密记录失败")
		}
		if len(records) == 0 {
			return updated, nil
		}
		for _, record := range records {
			if err := ctx.Err(); err != nil {
				return updated, err
			}
			if record.ID == "" {
				return updated, fmt.Errorf("%w: 存储返回了空记录标识", ErrStoreUnavailable)
			}
			if record.ID <= afterID {
				// 防御存储实现不按 ID 递增返回造成死循环。
				return updated, fmt.Errorf("%w: 存储返回的记录顺序没有前进", ErrStoreUnavailable)
			}
			actualKeyID, err := KeyIDOf(record.Sealed)
			if err != nil {
				return updated, fmt.Errorf("记录 %s 的密文无法解析: %w", record.ID, err)
			}
			if actualKeyID != sourceKeyID {
				return updated, fmt.Errorf("%w: 记录 %s 的密钥与批量查询结果不一致", ErrStoreUnavailable, record.ID)
			}
			plaintext, err := r.sealer.Open(record.Binding, record.Sealed)
			if err != nil {
				return updated, fmt.Errorf("记录 %s 无法解密: %w", record.ID, err)
			}
			newSealed, err := r.sealer.Seal(record.Binding, plaintext)
			wipeBytes(plaintext)
			if err != nil {
				return updated, fmt.Errorf("记录 %s 无法重新加密: %w", record.ID, err)
			}
			if err := r.store.Replace(ctx, record.ID, record.Sealed, newSealed); err != nil {
				if ctxErr := ctx.Err(); ctxErr != nil {
					return updated, ctxErr
				}
				return updated, fmt.Errorf("记录 %s 替换失败: %w", record.ID, err)
			}
			updated++
			report.Updated++
			afterID = record.ID
		}
	}
}

// countReferences 统计存储中仍以 keyID 加密的记录数。ctx 取消或存储失败时返回
// 错误，调用方必须按“无法确认”处理，不能当成零引用。
func (r *Rotator) countReferences(ctx context.Context, keyID string, batchSize int) (int, error) {
	afterID := ""
	total := 0
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		records, err := r.store.LoadBatch(ctx, keyID, afterID, batchSize)
		if err != nil {
			return total, storeLoadFailure(ctx, err, "统计旧密钥引用失败")
		}
		if len(records) == 0 {
			return total, nil
		}
		lastID := records[len(records)-1].ID
		if lastID == "" || lastID <= afterID {
			return total, fmt.Errorf("%w: 存储返回的记录顺序没有前进", ErrStoreUnavailable)
		}
		total += len(records)
		afterID = lastID
	}
}

// RetireOptions 控制退役旧密钥前的引用检查批大小。
type RetireOptions struct {
	// BatchSize 是检查引用时每批读取的记录数；0 使用默认值。
	BatchSize int
}

// RetireReport 汇总旧密钥退役检查结果。
type RetireReport struct {
	// Referenced 是退役前扫描到的、仍由该密钥加密的记录数；非零时拒绝退役。
	Referenced int
}

// RetireKey 在确认没有数据继续引用 keyID 后，返回移除该历史读密钥的新密钥环。
// 它拒绝退役当前写密钥；扫描发现任何引用、存储不可用或无法确认引用时都返回
// 错误且不返回新密钥环，不会无提示删除仍被使用的旧密钥。
//
// 返回的新密钥环需要由调用方持久化；持久化前不应切换运行中的密钥环，否则
// 下次启动会重新加载包含旧密钥的文件，退役不会生效。
func (r *Rotator) RetireKey(ctx context.Context, keyID string, opts RetireOptions) (*Keyring, RetireReport, error) {
	var report RetireReport
	if r == nil || r.ring == nil || r.store == nil {
		return nil, report, fmt.Errorf("%w: Rotator 缺少密钥环或存储", ErrStoreUnavailable)
	}
	ctx = normalizeContext(ctx)
	if keyID == r.ring.CurrentKeyID() {
		return nil, report, ErrCurrentKeyRetire
	}
	if !r.ring.HasKey(keyID) {
		return nil, report, ErrKeyNotFound
	}
	batchSize, err := reencryptBatchSize(opts.BatchSize)
	if err != nil {
		return nil, report, err
	}
	referenced, err := r.countReferences(ctx, keyID, batchSize)
	if err != nil {
		return nil, report, err
	}
	report.Referenced = referenced
	if referenced > 0 {
		r.logger.Warn("旧密钥仍被引用，拒绝退役",
			"key_id", maskKeyID(keyID),
			"referenced", referenced,
		)
		return nil, report, fmt.Errorf("%w: key_id=%s 仍被 %d 条记录引用",
			ErrKeyStillReferenced, maskKeyID(keyID), referenced)
	}
	retired, err := r.ring.WithoutKey(keyID)
	if err != nil {
		return nil, report, err
	}
	r.logger.Info("旧密钥已退役",
		"key_id", maskKeyID(keyID),
		"current_key_id", maskKeyID(retired.CurrentKeyID()),
	)
	return retired, report, nil
}

// resolveSourceKeyIDs 校验并规范化源密钥列表：为空时选全部历史读密钥；显式
// 列表必须存在、去重、不含当前写密钥，并按字典序稳定处理。
func (r *Rotator) resolveSourceKeyIDs(requested []string) ([]string, error) {
	if len(requested) == 0 {
		ids := make([]string, 0, len(r.ring.keys))
		for _, id := range r.ring.KeyIDs() {
			if id != r.ring.CurrentKeyID() {
				ids = append(ids, id)
			}
		}
		return ids, nil
	}
	seen := make(map[string]struct{}, len(requested))
	ids := make([]string, 0, len(requested))
	for _, id := range requested {
		if id == "" {
			return nil, fmt.Errorf("%w: 源密钥编号为空", ErrKeyringInvalid)
		}
		if id == r.ring.CurrentKeyID() {
			return nil, fmt.Errorf("%w: 源密钥不能是当前写密钥", ErrKeyringInvalid)
		}
		if !r.ring.HasKey(id) {
			return nil, fmt.Errorf("%w: 源密钥不存在", ErrKeyNotFound)
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// reencryptBatchSize 校验并返回批大小。
func reencryptBatchSize(size int) (int, error) {
	if size == 0 {
		return DefaultReencryptBatchSize, nil
	}
	if size < 0 || size > MaxReencryptBatchSize {
		return 0, fmt.Errorf("%w: 批大小必须为 1-%d", ErrOptionsInvalid, MaxReencryptBatchSize)
	}
	return size, nil
}

// storeLoadFailure 把存储读取错误映射为本包的安全错误，但保留 context 取消与
// 超时语义：调用方仍可用 errors.Is 判断 context.Canceled/DeadlineExceeded，
// 不会把它误当成普通存储故障而重试。其他错误的原始细节不进入错误文本，避免
// 泄露存储路径、SQL 或记录内容。
func storeLoadFailure(ctx context.Context, err error, detail string) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%w: %s", ErrStoreUnavailable, detail)
}

// wipeBytes 尽力清零临时明文副本，缩短秘密在内存中的可见时间。Go 的垃圾回收
// 可能已经复制过数据，本函数不是对内存取证的防护承诺。
func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
