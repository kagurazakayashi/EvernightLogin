package mysql

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/migrations"
	migrationsmysql "github.com/kagurazakayashi/EvernightLogin/migrations/mysql"
)

// repositorySQLKeywords 用于识别 Go 源码中的 SQL 字符串字面量。
var repositorySQLKeywords = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "REPLACE"}

// TestRepositorySQLCorpusTranslatable 是「逐项映射已使用仓储方法」的机器可查证据：
// 扫描 internal/*/sqlite 全部非测试源码中的 SQL 字面量，逐个送入 MySQL 重写器；
// 任何一个无法等价翻译就失败，避免上线后才发现方言缺口。它同时输出每个仓储包的
// 方法数与 SQL 字面量数，供报告覆盖清单引用。
func TestRepositorySQLCorpusTranslatable(t *testing.T) {
	root := moduleRoot(t)
	internalDir := filepath.Join(root, "internal")
	packages, err := os.ReadDir(internalDir)
	if err != nil {
		t.Fatalf("读取 internal 目录失败: %v", err)
	}

	stats := map[string]*packageStat{}
	featureCounts := map[string]int{}
	rowidAliasPattern := regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)(?:\s+(?:AS\s+)?([a-z_][a-z0-9_]*))?`)
	rowidQualifiedPattern := regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\.rowid\b`)
	unqualifiedRowidPattern := regexp.MustCompile(`(?i)(^|[^.a-z0-9_])rowid([^a-z0-9_]|$)`)
	rowidTables := map[string]bool{}
	literalCount := 0
	plainChecked := 0

	for _, entry := range packages {
		if !entry.IsDir() {
			continue
		}
		repoDir := filepath.Join(internalDir, entry.Name(), "sqlite")
		if info, err := os.Stat(repoDir); err != nil || !info.IsDir() {
			continue
		}
		files, err := filepath.Glob(filepath.Join(repoDir, "*.go"))
		if err != nil {
			t.Fatalf("列出 %s 失败: %v", repoDir, err)
		}
		stat := &packageStat{}
		stats[entry.Name()] = stat
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				t.Fatalf("解析 %s 失败: %v", file, err)
			}
			// 统计仓储方法数（func (s *Store) X）。
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Recv == nil {
					continue
				}
				if len(function.Recv.List) == 0 {
					continue
				}
				stat.methods++
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					return true
				}
				upper := strings.ToUpper(strings.TrimSpace(value))
				looksSQL := false
				for _, keyword := range repositorySQLKeywords {
					if strings.HasPrefix(upper, keyword) || strings.Contains(upper, " "+keyword+" ") {
						looksSQL = true
						break
					}
				}
				if !looksSQL && !strings.Contains(upper, "ON CONFLICT") &&
					!strings.Contains(upper, "ROWID") && !strings.Contains(upper, "INSERT OR") {
					return true
				}
				hasDialectMarker := strings.Contains(upper, "ON CONFLICT") ||
					strings.Contains(upper, "INSERT OR IGNORE") || strings.Contains(upper, "ROWID")
				if !hasDialectMarker {
					// 不含已实现标记的 SQL 也必须过禁用词检查（RETURNING/json_extract/
					// strftime/AUTOINCREMENT/GLOB/PRAGMA/|| 等会显式失败，不静默跳过）。
					plainChecked++
					if err := CheckForbiddenSQLiteDialect(value); err != nil {
						t.Errorf("%s 中的 SQL 含无法等价翻译的 SQLite 方言: %v\nSQL: %s", file, err, value)
					}
					return true
				}
				literalCount++
				stat.sql++
				if strings.Contains(upper, "ON CONFLICT") {
					featureCounts["ON CONFLICT"]++
				}
				if strings.Contains(upper, "INSERT OR IGNORE") {
					featureCounts["INSERT OR IGNORE"]++
				}
				if strings.Contains(upper, "ROWID") {
					stat.rowid++
					featureCounts["rowid"]++
					aliases := map[string]string{}
					for _, match := range rowidAliasPattern.FindAllStringSubmatch(value, -1) {
						table := strings.ToLower(match[1])
						if len(match) > 2 && match[2] != "" {
							aliases[strings.ToLower(match[2])] = table
						} else {
							rowidTables[table] = true
						}
					}
					for _, match := range rowidQualifiedPattern.FindAllStringSubmatch(value, -1) {
						alias := strings.ToLower(match[1])
						if table, ok := aliases[alias]; ok {
							rowidTables[table] = true
						}
					}
					if unqualifiedRowidPattern.MatchString(value) {
						// 未限定 rowid 指向当前语句的目标/主表（FROM/INTO/UPDATE/DELETE FROM 后首个表）。
						target := regexp.MustCompile(`(?i)\b(?:FROM|INTO|UPDATE)\s+([a-z_][a-z0-9_]*)`).FindStringSubmatch(value)
						if target != nil {
							rowidTables[strings.ToLower(target[1])] = true
						}
					}
				}
				translated, err := TranslateRepositorySQL(value)
				if err != nil {
					t.Errorf("%s 中的 SQL 无法翻译为 MySQL: %v\nSQL: %s", file, err, value)
					return true
				}
				if strings.Contains(strings.ToUpper(translated), "ON CONFLICT") ||
					strings.Contains(strings.ToUpper(translated), "INSERT OR IGNORE") {
					t.Errorf("%s 翻译后仍含 SQLite 方言: %s", file, translated)
				}
				return true
			})
		}
	}

	if len(stats) < 40 {
		t.Fatalf("只扫描到 %d 个仓储包，疑似扫描路径错误", len(stats))
	}
	if featureCounts["ON CONFLICT"] == 0 || featureCounts["rowid"] == 0 || featureCounts["INSERT OR IGNORE"] == 0 {
		t.Fatalf("仓储 SQL 特征语料不完整（可能扫描器失效）: %v", featureCounts)
	}
	t.Logf("仓储 SQL 兼容审计：%d 个包、%d 个方法；含方言标记 SQL %d 个（全部翻译成功），"+
		"其余标准 SQL/拼接片段 %d 个（禁用词检查通过）；特征 %v；rowid 表 %v",
		len(stats), totalMethods(stats), literalCount, plainChecked, featureCounts, sortedKeys(rowidTables))

	// rowid 使用必须落在迁移声明过的代理列表内，否则 SQL 会引用不存在的列。
	declared := migrationsmysql.RowidSurrogateTables()
	for table := range rowidTables {
		if !declared[table] {
			t.Errorf("仓储 SQL 使用了 rowid 表 %s，但迁移没有为它追加 _rowid 代理列", table)
		}
	}
	_ = migrations.SQLite
}

type packageStat struct {
	methods int
	sql     int
	rowid   int
}

func totalMethods(stats map[string]*packageStat) int {
	total := 0
	for _, stat := range stats {
		total += stat.methods
	}
	return total
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// moduleRoot 从当前测试目录向上查找 go.mod，避免依赖工作目录。
func moduleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("获取工作目录失败: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatal("找不到模块根目录（go.mod）")
		}
		directory = parent
	}
}
