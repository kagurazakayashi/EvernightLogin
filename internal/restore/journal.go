// 本文件实现恢复操作的库外追加审计日志（恢复操作审计独立保存、恢复后可靠合并）。
//
// 设计：
//   - 日志是库外受控目录中的 JSONL 文件；每行一条事件，带单调序号与 SHA-256 哈希链
//     （hash = SHA-256(prev_hash || 规范化行内容)），写入后 fsync。数据库被替换/回滚
//     不会影响该文件，因此恢复过程审计不会随数据库回滚丢失。
//   - 链末锚点（seq/hash）写入**受主密钥 HMAC 保护**的 restore-state.json：日志短于
//     锚点（尾部截断/删除）或锚点位置哈希不符（整链重写）都 fail-closed；日志多于
//     锚点只可能是“追加 fsync 后、锚点未更新”的崩溃窗口，下一次追加会重新锚定。
//   - 追加使用跨进程排他锁（restore-journal.lock），同一时刻只有一个进程写日志；
//     读取时逐行校验哈希链，任何断链/篡改/截断按 fail-closed 拒绝。
//   - 恢复成功后按幂等去重键把日志事件合并进恢复后数据库的安全审计（见 merge.go），
//     合并失败不会删除或改写库外日志。
package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	"github.com/kagurazakayashi/EvernightLogin/internal/maintenance"
)

// JournalEntry 是库外恢复审计日志中的一条事件。字段与 audit.Event 对齐但使用
// 稳定 JSON 表示以便跨版本读取；不包含秘密、备份正文或明文数据库内容。
type JournalEntry struct {
	Seq        int64               `json:"seq"`
	RestoreID  string              `json:"restore_id"`
	At         time.Time           `json:"at"`
	ActorType  string              `json:"actor_type"`
	ActorID    string              `json:"actor_id,omitempty"`
	Action     string              `json:"action"`
	TargetType string              `json:"target_type"`
	TargetID   string              `json:"target_id,omitempty"`
	Outcome    string              `json:"outcome"`
	ErrorCode  string              `json:"error_code,omitempty"`
	ReasonCode string              `json:"reason_code,omitempty"`
	RequestID  string              `json:"request_id,omitempty"`
	Changes    []audit.FieldChange `json:"changes,omitempty"`
	PrevHash   string              `json:"prev_hash"`
	Hash       string              `json:"hash"`
}

// journal 是库外追加审计日志。构造时加载并校验现有链；Append 在锁内追加并 fsync。
type journal struct {
	directory  string
	path       string
	lockPath   string
	controller *maintenance.Controller

	mu       sync.Mutex
	lastSeq  int64
	lastHash string
}

// openJournal 打开（必要时创建）库外审计日志并校验已有内容的哈希链与条目格式。
func openJournal(controller *maintenance.Controller) (*journal, error) {
	if controller == nil {
		return nil, fmt.Errorf("%w: 恢复审计日志缺少状态锚点控制器", ErrOptionsInvalid)
	}
	directory := filepath.Dir(controller.StatePath())
	log := &journal{
		directory:  directory,
		path:       filepath.Join(directory, restoreJournalFileName),
		lockPath:   filepath.Join(directory, restoreJournalLockName),
		controller: controller,
	}
	entries, err := log.load()
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		log.lastSeq = last.Seq
		log.lastHash = last.Hash
	}
	return log, nil
}

// Entries 返回经哈希链校验的全部日志条目副本。
func (j *journal) Entries() ([]JournalEntry, error) {
	if j == nil {
		return nil, fmt.Errorf("%w: 恢复审计日志未初始化", ErrOptionsInvalid)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.load()
}

// Append 追加一条事件：填充序号/时间/前序哈希并计算哈希，写入后 fsync。调用方应在
// 关键步骤（开始、切换前、切换后、完成）落盘日志；失败必须 fail-closed 中止操作。
func (j *journal) Append(ctx context.Context, entry JournalEntry) (JournalEntry, error) {
	if j == nil {
		return JournalEntry{}, fmt.Errorf("%w: 恢复审计日志未初始化", ErrOptionsInvalid)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return JournalEntry{}, err
	}
	if entry.Seq != 0 {
		return JournalEntry{}, fmt.Errorf("%w: 日志序号由服务生成", ErrInternal)
	}
	if entry.At.IsZero() {
		entry.At = time.Now().UTC().Truncate(time.Millisecond)
	} else {
		entry.At = entry.At.UTC().Truncate(time.Millisecond)
	}
	if err := validateJournalEntryFields(entry); err != nil {
		return JournalEntry{}, err
	}
	release, err := maintenance.AcquireFileLock(j.lockPath)
	if err != nil {
		if errors.Is(err, maintenance.ErrLockBusy) {
			return JournalEntry{}, fmt.Errorf("%w: 恢复审计日志正被其他流程写入",
				ErrAuditUnavailable)
		}
		return JournalEntry{}, fmt.Errorf("%w: 无法取得审计日志锁", ErrAuditUnavailable)
	}
	defer release()
	// 在锁内重新加载，防止其他进程刚刚追加过条目。
	entries, err := j.loadWithoutLock()
	if err != nil {
		return JournalEntry{}, err
	}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		j.lastSeq = last.Seq
		j.lastHash = last.Hash
	}
	entry.Seq = j.lastSeq + 1
	entry.PrevHash = j.lastHash
	entry.Hash = ""
	if err := validateJournalEntry(entry); err != nil {
		return JournalEntry{}, err
	}
	hash, err := journalEntryHash(entry)
	if err != nil {
		return JournalEntry{}, err
	}
	entry.Hash = hash
	line, err := json.Marshal(entry)
	if err != nil {
		return JournalEntry{}, fmt.Errorf("%w: 无法序列化审计日志", ErrAuditUnavailable)
	}
	if len(line) > journalMaxLineBytes {
		return JournalEntry{}, fmt.Errorf("%w: 审计日志条目过大", ErrAuditUnavailable)
	}
	file, err := os.OpenFile(j.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return JournalEntry{}, fmt.Errorf("%w: 无法打开审计日志", ErrAuditUnavailable)
	}
	if info, statErr := file.Stat(); statErr == nil && info.Size()+int64(len(line))+1 > journalMaxBytes {
		_ = file.Close()
		return JournalEntry{}, fmt.Errorf("%w: 恢复审计日志超过大小上限", ErrAuditUnavailable)
	}
	writeErr := writeAllBytes(file, append(line, '\n'))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return JournalEntry{}, fmt.Errorf("%w: 无法持久化审计日志", ErrAuditUnavailable)
	}
	maintenance.SyncDirectory(j.directory)
	j.lastSeq = entry.Seq
	j.lastHash = entry.Hash
	// 把链末锚点写入受主密钥 HMAC 保护的库外状态；失败按审计不可用 fail-closed，
	// 避免出现“日志已追加但尾部截断不可检出”的窗口。
	if err := j.controller.UpdateJournalAnchor(ctx, entry.Seq, entry.Hash); err != nil {
		return JournalEntry{}, fmt.Errorf("%w: 无法更新审计日志锚点", ErrAuditUnavailable)
	}
	return entry, nil
}

// load 在进程内互斥下读取并校验日志。
func (j *journal) load() ([]JournalEntry, error) {
	release, err := maintenance.AcquireFileLock(j.lockPath)
	if err != nil {
		if errors.Is(err, maintenance.ErrLockBusy) {
			return nil, fmt.Errorf("%w: 恢复审计日志正被其他流程读取", ErrAuditUnavailable)
		}
		return nil, fmt.Errorf("%w: 无法取得审计日志锁", ErrAuditUnavailable)
	}
	defer release()
	return j.loadWithoutLock()
}

// loadWithoutLock 读取并校验日志文件；调用方必须持有审计日志锁。
func (j *journal) loadWithoutLock() ([]JournalEntry, error) {
	file, err := os.Open(j.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: 无法读取恢复审计日志", ErrAuditUnavailable)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取恢复审计日志状态", ErrAuditUnavailable)
	}
	if info.Size() > journalMaxBytes {
		return nil, fmt.Errorf("%w: 恢复审计日志超过大小上限", ErrAuditUnavailable)
	}
	data, err := os.ReadFile(j.path)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法读取恢复审计日志", ErrAuditUnavailable)
	}
	lines := strings.Split(string(data), "\n")
	entries := make([]JournalEntry, 0, len(lines))
	previousHash := ""
	var expectedSeq int64 = 1
	for index, rawLine := range lines {
		if rawLine == "" {
			if index != len(lines)-1 {
				return nil, fmt.Errorf("%w: 审计日志包含空行（第 %d 行）",
					ErrAuditUnavailable, index+1)
			}
			continue
		}
		if len(rawLine) > journalMaxLineBytes {
			return nil, fmt.Errorf("%w: 审计日志单行过大（第 %d 行）",
				ErrAuditUnavailable, index+1)
		}
		var entry JournalEntry
		decoder := json.NewDecoder(strings.NewReader(rawLine))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("%w: 审计日志第 %d 行格式非法", ErrAuditUnavailable, index+1)
		}
		if err := validateJournalEntry(entry); err != nil {
			return nil, fmt.Errorf("%w: 审计日志第 %d 行内容非法", ErrAuditUnavailable, index+1)
		}
		if entry.Seq != expectedSeq {
			return nil, fmt.Errorf("%w: 审计日志序号不连续（第 %d 行）",
				ErrAuditUnavailable, index+1)
		}
		if entry.PrevHash != previousHash {
			return nil, fmt.Errorf("%w: 审计日志哈希链断裂（第 %d 行）",
				ErrAuditUnavailable, index+1)
		}
		expectedHash, err := journalEntryHash(entry)
		if err != nil || !strings.EqualFold(expectedHash, entry.Hash) {
			return nil, fmt.Errorf("%w: 审计日志哈希不匹配（第 %d 行）",
				ErrAuditUnavailable, index+1)
		}
		entries = append(entries, entry)
		previousHash = entry.Hash
		expectedSeq++
	}
	// 与库外 HMAC 保护的链末锚点核对：日志短于锚点（尾部截断/删除）或锚点位置
	// 哈希不符（整链重写）都 fail-closed；日志多于锚点只可能是“追加已 fsync、锚点
	// 尚未更新”的崩溃窗口，允许并在下一次追加时重新锚定。
	anchorSeq, anchorHash, ok := j.controller.JournalAnchor()
	if ok {
		if int64(len(entries)) < anchorSeq {
			return nil, fmt.Errorf("%w: 恢复审计日志短于受保护锚点（疑似尾部截断）",
				ErrAuditUnavailable)
		}
		if entries[anchorSeq-1].Hash != anchorHash {
			return nil, fmt.Errorf("%w: 恢复审计日志锚点哈希不匹配（疑似整链重写）",
				ErrAuditUnavailable)
		}
		// 正常 Append 在每次成功追加后更新锚点，因此最多容忍 1 条“已 fsync 但锚点
		// 尚未更新”的崩溃窗口尾；更多未锚定尾部无法解释为崩溃窗口，按疑似篡改拒绝。
		if int64(len(entries)) > anchorSeq+1 {
			return nil, fmt.Errorf("%w: 恢复审计日志存在多条未锚定尾部（疑似篡改）",
				ErrAuditUnavailable)
		}
	}
	return entries, nil
}

// journalEntryHash 计算条目哈希：SHA-256(前序哈希 + 去掉 Hash 字段后的规范化 JSON)。
// 规范化使用结构体字段顺序（encoding/json 对结构体稳定），确保跨读取可复算。
func journalEntryHash(entry JournalEntry) (string, error) {
	copyEntry := entry
	copyEntry.Hash = ""
	encoded, err := json.Marshal(copyEntry)
	if err != nil {
		return "", fmt.Errorf("%w: 无法计算审计日志哈希", ErrAuditUnavailable)
	}
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(entry.PrevHash)); err != nil {
		return "", fmt.Errorf("%w: 无法计算审计日志哈希", ErrAuditUnavailable)
	}
	if _, err := hasher.Write(encoded); err != nil {
		return "", fmt.Errorf("%w: 无法计算审计日志哈希", ErrAuditUnavailable)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// validateJournalEntry 校验日志条目的稳定字段取值（不校验哈希，由调用方计算/比较）。
func validateJournalEntry(entry JournalEntry) error {
	if err := validateJournalEntryFields(entry); err != nil {
		return err
	}
	if entry.Seq <= 0 {
		return fmt.Errorf("%w: 审计日志序号非法", ErrInternal)
	}
	return nil
}

// validateJournalEntryFields 校验除序号外的稳定字段取值（追加前条目的序号尚未分配）。
func validateJournalEntryFields(entry JournalEntry) error {
	if entry.RestoreID == "" || len(entry.RestoreID) > 64 {
		return fmt.Errorf("%w: 审计日志恢复编号非法", ErrInternal)
	}
	if entry.At.IsZero() {
		return fmt.Errorf("%w: 审计日志时间缺失", ErrInternal)
	}
	if entry.ActorType == "" {
		return fmt.Errorf("%w: 审计日志操作者类别缺失", ErrInternal)
	}
	actor := audit.Actor{Type: audit.ActorKind(entry.ActorType), ID: entry.ActorID}
	if err := actor.Validate(); err != nil {
		return fmt.Errorf("%w: 审计日志操作者非法", ErrInternal)
	}
	if entry.Action == "" || len(entry.Action) > 128 {
		return fmt.Errorf("%w: 审计日志动作缺失或过长", ErrInternal)
	}
	if entry.TargetType == "" || len(entry.TargetType) > 64 {
		return fmt.Errorf("%w: 审计日志目标类型缺失或过长", ErrInternal)
	}
	if entry.TargetID != "" && len(entry.TargetID) > 128 {
		return fmt.Errorf("%w: 审计日志目标编号过长", ErrInternal)
	}
	switch audit.Outcome(entry.Outcome) {
	case audit.OutcomeSuccess, audit.OutcomeFailure, audit.OutcomeDenied:
	default:
		return fmt.Errorf("%w: 审计日志结果类别非法", ErrInternal)
	}
	if entry.ErrorCode != "" && len(entry.ErrorCode) > 64 {
		return fmt.Errorf("%w: 审计日志错误码过长", ErrInternal)
	}
	if entry.ReasonCode != "" && len(entry.ReasonCode) > 64 {
		return fmt.Errorf("%w: 审计日志原因码过长", ErrInternal)
	}
	if entry.RequestID != "" && len(entry.RequestID) > 64 {
		return fmt.Errorf("%w: 审计日志关联编号过长", ErrInternal)
	}
	return nil
}

// toAuditEvent 把库外日志条目转换为可直接合并进恢复后数据库审计的事件；去重键
// 由恢复编号与序号组成，重复合并按 audit.ErrDuplicateEvent 幂等处理。
func (entry JournalEntry) toAuditEvent() audit.Event {
	return audit.Event{
		OccurredAt: entry.At,
		Actor:      audit.Actor{Type: audit.ActorKind(entry.ActorType), ID: entry.ActorID},
		Action:     entry.Action,
		Target:     audit.Target{Type: entry.TargetType, ID: entry.TargetID},
		Outcome:    audit.Outcome(entry.Outcome),
		ErrorCode:  entry.ErrorCode,
		ReasonCode: entry.ReasonCode,
		RequestID:  entry.RequestID,
		Changes:    entry.Changes,
		DedupeKey:  "restore:" + entry.RestoreID + ":" + strconv.FormatInt(entry.Seq, 10),
	}
}

// writeAllBytes 把完整字节写入文件，返回写入错误。
func writeAllBytes(file *os.File, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if err != nil {
			return err
		}
		if written <= 0 {
			return fmt.Errorf("%w: 短写", ErrAuditUnavailable)
		}
		data = data[written:]
	}
	return nil
}
