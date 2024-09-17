package main

// 步骤 267：能力清单证据分级与只读校验（-check）的定向测试。
// 覆盖：maturity 校验、partial 必须有缺口/环境/子模块证据、正向/拒绝/环境/子模块
// 证据核验、-check 比较忽略生成时间但能发现语义漂移。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTrustFile 在临时根目录写入含 token 的文件。
func writeTrustFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("创建目录失败: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写入文件失败: %v", err)
	}
}

// TestValidateCapabilityEvidenceClassification 验证 partial/未测/子模块证据分类。
func TestValidateCapabilityEvidenceClassification(t *testing.T) {
	root := t.TempDir()
	writeTrustFile(t, root, "truth.md", "D-252-1\n非 SQLite 运行未测\n远端不可获取\nR10-22\n")
	inv := &inventory{TestsByPackage: map[string][]string{}}
	result := validateCapability(root, capability{
		ID: "x", Title: "x", Maturity: "partial",
		Gaps:                 []gapClaim{{Summary: "gap", Evidence: []string{"truth.md:R10-22"}}},
		EnvironmentUntested:  []string{"truth.md:非 SQLite 运行未测"},
		SubmoduleUnavailable: []string{"truth.md:远端不可获取"},
		PositiveEvidence:     []string{"truth.md:D-252-1"},
		RejectionEvidence:    []string{"truth.md:R10-22"},
	}, inv)
	if result.Status != "partial" {
		t.Fatalf("状态 = %s，期望 partial（missing=%v）", result.Status, result.Missing)
	}
	if len(result.EnvironmentEvidence) != 1 || !result.EnvironmentEvidence[0].Found {
		t.Fatalf("环境未测证据未核验: %+v", result.EnvironmentEvidence)
	}
	if len(result.SubmoduleEvidence) != 1 || !result.SubmoduleEvidence[0].Found {
		t.Fatalf("子模块阻塞证据未核验: %+v", result.SubmoduleEvidence)
	}
	if len(result.PositiveEvidenceMatched) != 1 || len(result.RejectionEvidenceMatched) != 1 {
		t.Fatalf("正向/拒绝证据未核验: %+v %+v", result.PositiveEvidenceMatched,
			result.RejectionEvidenceMatched)
	}
	// 证据标记缺失必须变成 missing，不能当通过。
	broken := validateCapability(root, capability{ID: "y", Title: "y", Maturity: "partial",
		Gaps: []gapClaim{{Summary: "gap", Evidence: []string{"truth.md:NOT-PRESENT"}}},
	}, inv)
	if broken.Status != "missing" {
		t.Fatalf("缺口证据缺失状态 = %s，期望 missing", broken.Status)
	}
}

// TestLoadCatalogRejectsInvalidMaturity 验证 maturity/partial 声明格式校验。
func TestLoadCatalogRejectsInvalidMaturity(t *testing.T) {
	cases := []string{
		`{"schema":"evernight.capability-catalog/v1","capabilities":[{"id":"a","title":"a","maturity":"green"}]}`,
		`{"schema":"evernight.capability-catalog/v1","capabilities":[{"id":"a","title":"a","expect":"unimplemented","maturity":"partial"}]}`,
		`{"schema":"evernight.capability-catalog/v1","capabilities":[{"id":"a","title":"a","maturity":"partial"}]}`,
	}
	for _, raw := range cases {
		path := filepath.Join(t.TempDir(), "catalog.json")
		if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
			t.Fatalf("写临时声明失败: %v", err)
		}
		if _, err := loadCatalog(path); err == nil {
			t.Fatalf("非法声明应被拒绝: %s", raw)
		}
	}
}

// TestCompareOutputsIgnoresGeneratedAtButDetectsDrift 验证 -check 只读校验语义。
func TestCompareOutputsIgnoresGeneratedAtButDetectsDrift(t *testing.T) {
	root := t.TempDir()
	report := matrixReport{Schema: matrixSchema,
		Metadata: metadata{GeneratedAt: "2026-11-26T00:00:00Z", RepoRoot: "."},
		Summary:  summary{Total: 1, ByStatus: map[string]int{"implemented": 1}}}
	jsonBytes, err := renderJSON(report)
	if err != nil {
		t.Fatalf("渲染 JSON: %v", err)
	}
	writeTrustFile(t, root, "matrix.json", string(jsonBytes))
	writeTrustFile(t, root, "matrix.md", string(renderMarkdown(report)))
	opts := options{OutJSON: "matrix.json", OutMarkdown: "matrix.md"}
	// 同内容（生成时间不同也应通过：比较前删除 generated_at）。
	report.Metadata.GeneratedAt = "2026-11-26T01:02:03Z"
	mismatches, err := compareOutputs(root, opts, report)
	if err != nil {
		t.Fatalf("比较失败: %v", err)
	}
	if len(mismatches) != 0 {
		t.Fatalf("同一内容不应报差异: %v", mismatches)
	}
	// 语义漂移（汇总数变化）必须被发现。
	report.Summary.Total = 2
	report.Summary.ByStatus["implemented"] = 2
	if mismatches, _ := compareOutputs(root, opts, report); len(mismatches) == 0 {
		t.Fatal("语义漂移未检出")
	}
}

// TestStrictFailureDoesNotWriteOutputs 验证 N-267-1：strict 失败时不得写产物
// （否则会把 tracked 矩阵覆盖成失败/半绿结果）。用临时 catalog 制造 missing 能力，
// 输出指向临时文件并预置哨兵内容；断言退出码 3 且哨兵未被覆盖。
func TestStrictFailureDoesNotWriteOutputs(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("仓库根: %v", err)
	}
	// 共享工作树可能含并行写者在研的语法错误文件；此时扫描器本身无法运行，
	// 该集成失败路径测试应在干净树执行（CI/审计用 git archive + 本步文件复验），
	// 脏树跳过并明确原因，而不是把扫描环境故障误报成功能失败。
	if _, _, scanErr := scanRepo(root); scanErr != nil {
		t.Skipf("当前工作树源码暂不可解析（并行写者在研），跳过集成失败路径测试: %v", scanErr)
	}
	rawCatalog, err := os.ReadFile(filepath.Join(root, "scripts", "capabilities", "catalog.json"))
	if err != nil {
		t.Fatalf("读取能力声明: %v", err)
	}
	var catalog map[string]any
	if err := json.Unmarshal(rawCatalog, &catalog); err != nil {
		t.Fatalf("解析能力声明: %v", err)
	}
	capabilities, _ := catalog["capabilities"].([]any)
	catalog["capabilities"] = append(capabilities, map[string]any{
		"id": "test.strict_failure", "title": "测试缺失能力", "domain": "测试",
		"app_api": []any{"DefinitelyMissingPublicSymbol"},
	})
	brokenCatalog := filepath.Join(t.TempDir(), "catalog.json")
	brokenJSON, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		t.Fatalf("序列化临时声明: %v", err)
	}
	if err := os.WriteFile(brokenCatalog, brokenJSON, 0o644); err != nil {
		t.Fatalf("写临时声明: %v", err)
	}
	outJSON := filepath.Join(t.TempDir(), "matrix.json")
	outMD := filepath.Join(t.TempDir(), "matrix.md")
	const sentinel = "SENTINEL-DO-NOT-OVERWRITE"
	for _, path := range []string{outJSON, outMD} {
		if err := os.WriteFile(path, []byte(sentinel), 0o644); err != nil {
			t.Fatalf("写哨兵: %v", err)
		}
	}
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	defer stdoutFile.Close()
	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatalf("stderr: %v", err)
	}
	defer stderrFile.Close()
	code := run([]string{"-root", root, "-catalog", brokenCatalog,
		"-out-json", outJSON, "-out-md", outMD, "-strict"}, stdoutFile, stderrFile)
	if code != 3 {
		t.Fatalf("strict 失败退出码 = %d，期望 3", code)
	}
	for _, path := range []string{outJSON, outMD} {
		actual, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取输出: %v", err)
		}
		if string(actual) != sentinel {
			t.Fatalf("strict 失败仍改写输出 %s（内容: %.80s）", path, string(actual))
		}
	}
}
