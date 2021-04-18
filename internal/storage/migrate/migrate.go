// Package migrate 实现版本化数据库迁移的执行机制。
//
// 本包只包含与数据库方言无关的机制：迁移文件加载与校验、版本排序、已应用记录
// 前缀校验、SHA-256 校验和、失败记录、排他锁与事务契约。具体 SQL 执行、事务与
// 数据库连接由实现 Backend 的存储后端提供（SQLite 在步骤 07 接入）；测试使用
// 可控内存后端，不把测试替身当作生产实现。
//
// 迁移文件一旦被部署执行就不能修改，只能在末尾追加新版本；执行器会拒绝与已应用
// 记录校验和不一致的迁移。结构变更的 DDL（CREATE/ALTER/DROP）在不同数据库的
// 事务行为不同，不支持事务的数据库必须用非事务标记并在失败后人工核对，不能假装
// 自动回滚。
package migrate

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
)

const (
	// maxMigrationFileBytes 是单个迁移文件的大小上限，避免误读大文件。
	maxMigrationFileBytes = 1 << 20

	// directivePrefix 是迁移文件头部指令的固定前缀。
	directivePrefix = "-- +migrate "
)

// 迁移机制的可识别错误。调用方应使用 errors.Is 判断；错误文本不包含迁移 SQL
// 内容或数据库凭据。
var (
	// ErrInvalidMigration 表示迁移定义不合法（文件名、版本、语句或指令错误）。
	ErrInvalidMigration = errors.New("迁移定义不合法")
	// ErrDuplicateMigrationVersion 表示迁移版本重复。
	ErrDuplicateMigrationVersion = errors.New("迁移版本重复")
	// ErrChecksumMismatch 表示已应用迁移的校验和与当前文件不一致。
	ErrChecksumMismatch = errors.New("迁移文件校验和与已应用记录不一致")
	// ErrMigrationOrder 表示已应用迁移不是当前迁移列表的前缀，顺序不一致。
	ErrMigrationOrder = errors.New("迁移历史顺序与当前迁移文件不一致")
	// ErrUnknownAppliedMigration 表示已应用迁移不在当前迁移文件中。
	ErrUnknownAppliedMigration = errors.New("已应用迁移不在当前迁移文件中")
	// ErrMigrationHistoryInvalid 表示迁移历史不合法（重复、失败记录与已应用冲突等）。
	ErrMigrationHistoryInvalid = errors.New("迁移历史不合法")
	// ErrFailurePending 表示存在未处理的迁移失败记录，必须人工核对后清理。
	ErrFailurePending = errors.New("存在未处理的迁移失败记录")
)

// migrationFileNamePattern 约束迁移文件名：四位版本号加小写描述，扩展名 .sql。
var migrationFileNamePattern = regexp.MustCompile(`^([0-9]{4})_([a-z0-9]+(?:_[a-z0-9]+)*)\.sql$`)

// migrationVersionPattern 约束手工构造迁移时的版本格式。
var migrationVersionPattern = regexp.MustCompile(`^[0-9]{4}$`)

// Migration 是一个已解析的迁移文件。
type Migration struct {
	// Version 是四位数字版本号，例如 "0001"；版本按字符串升序执行。
	Version string
	// Description 是文件名描述部分，下划线替换为空格，仅用于记录与展示。
	Description string
	// FileName 是原始文件名，便于诊断。
	FileName string
	// Checksum 是原始文件内容的 SHA-256 十六进制摘要。
	Checksum string
	// Statements 是按顺序执行的 SQL 语句；非事务迁移可能只应用一部分。
	Statements []string
	// NonTransactional 表示该迁移可能包含无法在事务中安全执行的 DDL；后端应尽量
	// 逐条执行，失败后不承诺自动回滚。
	NonTransactional bool
}

// LoadMigrations 从文件系统加载并验证全部迁移。
//
// 文件名必须匹配 NNNN_description.sql；只读取根目录下扩展名为 .sql 的普通文件，
// 其他文件忽略。文件头部可包含指令（位于首个 SQL 语句之前的注释行）：
//
//	-- +migrate non-transactional  迁移可能包含非事务 DDL
//	-- +migrate whole-file         整个文件作为一条语句（触发器/复合语句）
//
// 未知指令会报错，避免拼写错误被静默忽略。返回的迁移按版本升序排列，版本必须
// 唯一；校验和基于原始文件字节，即使只改注释也会被视为内容变化。
func LoadMigrations(fsys fs.FS) ([]Migration, error) {
	if fsys == nil {
		return nil, fmt.Errorf("%w：迁移文件系统为空", ErrInvalidMigration)
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%w：读取迁移目录失败：%v", ErrInvalidMigration, err)
	}

	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fileName := entry.Name()
		if !strings.HasSuffix(fileName, ".sql") {
			continue
		}
		migration, err := loadMigrationFile(fsys, fileName)
		if err != nil {
			return nil, err
		}
		migrations = append(migrations, migration)
	}

	sort.Slice(migrations, func(left, right int) bool {
		return migrations[left].Version < migrations[right].Version
	})
	for index := 1; index < len(migrations); index++ {
		if migrations[index].Version == migrations[index-1].Version {
			return nil, fmt.Errorf("%w：%s 与 %s",
				ErrDuplicateMigrationVersion, migrations[index-1].FileName, migrations[index].FileName)
		}
	}
	return migrations, nil
}

// loadMigrationFile 读取、校验并解析单个迁移文件。
func loadMigrationFile(fsys fs.FS, fileName string) (Migration, error) {
	matches := migrationFileNamePattern.FindStringSubmatch(fileName)
	if matches == nil {
		return Migration{}, fmt.Errorf("%w：文件名 %q 必须符合 NNNN_description.sql",
			ErrInvalidMigration, fileName)
	}
	info, err := fs.Stat(fsys, fileName)
	if err != nil {
		return Migration{}, fmt.Errorf("%w：无法读取 %s 信息：%v", ErrInvalidMigration, fileName, err)
	}
	if !info.Mode().IsRegular() {
		return Migration{}, fmt.Errorf("%w：%s 不是普通文件", ErrInvalidMigration, fileName)
	}
	if info.Size() > maxMigrationFileBytes {
		return Migration{}, fmt.Errorf("%w：%s 超过 %d 字节上限",
			ErrInvalidMigration, fileName, maxMigrationFileBytes)
	}
	raw, err := fs.ReadFile(fsys, fileName)
	if err != nil {
		return Migration{}, fmt.Errorf("%w：读取 %s 失败：%v", ErrInvalidMigration, fileName, err)
	}
	if len(raw) > maxMigrationFileBytes {
		return Migration{}, fmt.Errorf("%w：%s 超过 %d 字节上限",
			ErrInvalidMigration, fileName, maxMigrationFileBytes)
	}

	script, nonTransactional, wholeFile, err := parseDirectives(string(raw))
	if err != nil {
		return Migration{}, fmt.Errorf("%w：%s：%v", ErrInvalidMigration, fileName, err)
	}
	if strings.TrimSpace(script) == "" {
		return Migration{}, fmt.Errorf("%w：%s 不包含 SQL", ErrInvalidMigration, fileName)
	}

	var statements []string
	if wholeFile {
		statements = []string{strings.TrimSpace(script)}
	} else {
		statements, err = SplitStatements(script)
		if err != nil {
			return Migration{}, fmt.Errorf("%w：%s：%v", ErrInvalidMigration, fileName, err)
		}
	}
	if len(statements) == 0 {
		return Migration{}, fmt.Errorf("%w：%s 没有可执行语句", ErrInvalidMigration, fileName)
	}

	digest := sha256.Sum256(raw)
	return Migration{
		Version:          matches[1],
		Description:      strings.ReplaceAll(matches[2], "_", " "),
		FileName:         fileName,
		Checksum:         hex.EncodeToString(digest[:]),
		Statements:       statements,
		NonTransactional: nonTransactional,
	}, nil
}

// parseDirectives 读取脚本头部的 -- +migrate 指令，并返回去掉头部注释后的 SQL
// 脚本。头部注释（包括普通说明注释）不进入执行语句，但校验和仍基于原始文件。
func parseDirectives(script string) (sqlText string, nonTransactional, wholeFile bool, err error) {
	scanner := bufio.NewScanner(strings.NewReader(script))
	scanner.Buffer(make([]byte, 0, 64*1024), maxMigrationFileBytes)

	var body strings.Builder
	leading := true
	first := true
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if leading && (strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "--")) {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "-- +migrate ") {
				directive := strings.TrimSpace(strings.TrimPrefix(trimmed, directivePrefix))
				switch directive {
				case "non-transactional":
					nonTransactional = true
				case "whole-file":
					wholeFile = true
				default:
					return "", false, false, fmt.Errorf("未知迁移指令 %q", directive)
				}
			}
			continue
		}
		leading = false
		if !first {
			body.WriteString("\n")
		}
		first = false
		body.WriteString(line)
	}
	if err := scanner.Err(); err != nil {
		return "", false, false, fmt.Errorf("读取迁移脚本失败：%v", err)
	}
	return body.String(), nonTransactional, wholeFile, nil
}

// SplitStatements 把 SQL 脚本拆成按顺序执行的语句。
//
// 支持单引号、双引号、反引号、方括号标识符内的分号，以及 -- 行注释与 /* */ 块
// 注释；注释不进入语句文本。字符串/注释未闭合、块注释未结束时返回错误。
//
// 注意：BEGIN...END 触发器/复合语句内部的 END; 会被当作语句分隔符，此类迁移必须
// 使用 -- +migrate whole-file 指令把整个文件作为一条语句执行。当前迁移未使用
// 触发器；该限制集中在此处并写入设计文档。
func SplitStatements(script string) ([]string, error) {
	var statements []string
	var current strings.Builder
	line := 1

	const (
		stateNormal = iota
		stateSingleQuote
		stateDoubleQuote
		stateBacktick
		stateBracket
		stateLineComment
		stateBlockComment
	)
	state := stateNormal

	for index := 0; index < len(script); index++ {
		character := script[index]
		if character == '\n' {
			line++
		}

		switch state {
		case stateLineComment:
			if character == '\n' {
				current.WriteByte(character)
				state = stateNormal
			}
			continue
		case stateBlockComment:
			if character == '*' && index+1 < len(script) && script[index+1] == '/' {
				index++
				current.WriteByte(' ')
				state = stateNormal
			}
			continue
		case stateSingleQuote:
			current.WriteByte(character)
			if character == '\'' {
				if index+1 < len(script) && script[index+1] == '\'' {
					index++
					current.WriteByte('\'')
					continue
				}
				state = stateNormal
			}
			continue
		case stateDoubleQuote:
			current.WriteByte(character)
			if character == '"' {
				if index+1 < len(script) && script[index+1] == '"' {
					index++
					current.WriteByte('"')
					continue
				}
				state = stateNormal
			}
			continue
		case stateBacktick:
			current.WriteByte(character)
			if character == '`' {
				state = stateNormal
			}
			continue
		case stateBracket:
			current.WriteByte(character)
			if character == ']' {
				state = stateNormal
			}
			continue
		}

		// 普通状态。
		switch {
		case character == '-' && index+1 < len(script) && script[index+1] == '-':
			index++
			state = stateLineComment
		case character == '/' && index+1 < len(script) && script[index+1] == '*':
			index++
			state = stateBlockComment
		case character == '\'':
			state = stateSingleQuote
			current.WriteByte(character)
		case character == '"':
			state = stateDoubleQuote
			current.WriteByte(character)
		case character == '`':
			state = stateBacktick
			current.WriteByte(character)
		case character == '[':
			state = stateBracket
			current.WriteByte(character)
		case character == ';':
			if statement := strings.TrimSpace(current.String()); statement != "" {
				statements = append(statements, statement)
			}
			current.Reset()
		default:
			current.WriteByte(character)
		}
	}

	switch state {
	case stateSingleQuote, stateDoubleQuote, stateBacktick, stateBracket:
		return nil, fmt.Errorf("第 %d 行：字符串或标识符未闭合", line)
	case stateBlockComment:
		return nil, fmt.Errorf("第 %d 行：块注释未结束", line)
	}
	if statement := strings.TrimSpace(current.String()); statement != "" {
		statements = append(statements, statement)
	}
	return statements, nil
}

// validateMigrationSet 校验调用方直接构造的迁移集合（Loader 之外的使用方式）。
func validateMigrationSet(migrations []Migration) error {
	seen := make(map[string]bool, len(migrations))
	previous := ""
	for _, migration := range migrations {
		if !migrationVersionPattern.MatchString(migration.Version) {
			return fmt.Errorf("%w：版本 %q 不是四位数字", ErrInvalidMigration, migration.Version)
		}
		if seen[migration.Version] {
			return fmt.Errorf("%w：版本 %s", ErrDuplicateMigrationVersion, migration.Version)
		}
		seen[migration.Version] = true
		if previous != "" && migration.Version <= previous {
			return fmt.Errorf("%w：版本 %s 未按升序排列", ErrInvalidMigration, migration.Version)
		}
		previous = migration.Version
		if len(migration.Statements) == 0 {
			return fmt.Errorf("%w：版本 %s 没有语句", ErrInvalidMigration, migration.Version)
		}
		for _, statement := range migration.Statements {
			if strings.TrimSpace(statement) == "" {
				return fmt.Errorf("%w：版本 %s 包含空语句", ErrInvalidMigration, migration.Version)
			}
		}
		if migration.Checksum == "" {
			return fmt.Errorf("%w：版本 %s 缺少校验和", ErrInvalidMigration, migration.Version)
		}
	}
	return nil
}
