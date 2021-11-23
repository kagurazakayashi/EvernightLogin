package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
)

// writeTestKeyringFile 生成密钥环文档并写入受保护文件，返回路径与密钥环。
func writeTestKeyringFile(t *testing.T, dir, name, keyID string) (string, *Keyring) {
	t.Helper()
	ring := mustGenerateKeyring(t, keyID)
	doc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := WriteProtectedFile(path, doc); err != nil {
		t.Fatalf("WriteProtectedFile 失败: %v", err)
	}
	return path, ring
}

func TestFileProviderLoadsProtectedKeyring(t *testing.T) {
	path, ring := writeTestKeyringFile(t, testutil.TempDir(t), "master-key.json", "k1")
	wantDoc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if provider.Path() != path {
		t.Fatalf("Path = %q, 期望 %q", provider.Path(), path)
	}
	loaded, err := LoadKeyring(context.Background(), provider)
	if err != nil {
		t.Fatalf("LoadKeyring 失败: %v", err)
	}
	if loaded.CurrentKeyID() != "k1" {
		t.Fatalf("加载后当前密钥 = %q", loaded.CurrentKeyID())
	}
	gotDoc, err := loaded.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if !bytes.Equal(gotDoc, wantDoc) {
		t.Fatal("加载后的密钥环文档与写入内容不一致")
	}
}

func TestFileProviderRejectsMissingFile(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "does-not-exist.json")
	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("缺失文件错误 = %v, 期望 ErrFileInvalid", err)
	}
	// 缺失主密钥时不得静默创建新文件或新密钥。
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("加载失败后文件状态 = %v, 期望不存在", err)
	}
}

func TestFileProviderRejectsInvalidDocument(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "master-key.json")
	if err := WriteProtectedFile(path, []byte(`{"format":"wrong"}`)); err != nil {
		t.Fatalf("WriteProtectedFile 失败: %v", err)
	}
	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrKeyringInvalid) {
		t.Fatalf("非法文档错误 = %v, 期望 ErrKeyringInvalid", err)
	}
}

func TestFileProviderRejectsEmptyAndOversizedFiles(t *testing.T) {
	dir := testutil.TempDir(t)

	emptyPath := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatalf("创建空文件失败: %v", err)
	}
	provider, err := NewFileProvider(emptyPath)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("空文件错误 = %v, 期望 ErrKeyMaterialMissing", err)
	}

	bigPath := filepath.Join(dir, "big.json")
	if err := os.WriteFile(bigPath, bytes.Repeat([]byte("x"), MaxKeyringDocumentBytes+1), 0o600); err != nil {
		t.Fatalf("创建超大文件失败: %v", err)
	}
	provider, err = NewFileProvider(bigPath)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("超大文件错误 = %v, 期望 ErrFileInvalid", err)
	}
}

func TestFileProviderRejectsDirectory(t *testing.T) {
	dir := testutil.TempDir(t)
	provider, err := NewFileProvider(dir)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("目录路径错误 = %v, 期望 ErrFileInvalid", err)
	}
}

func TestProviderFunc(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	doc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	provider := ProviderFunc(func(ctx context.Context) ([]byte, error) {
		return doc, nil
	})
	loaded, err := LoadKeyring(context.Background(), provider)
	if err != nil {
		t.Fatalf("LoadKeyring 失败: %v", err)
	}
	if loaded.CurrentKeyID() != "k1" {
		t.Fatalf("加载后当前密钥 = %q", loaded.CurrentKeyID())
	}

	providerErr := ProviderFunc(func(context.Context) ([]byte, error) {
		return nil, ErrProviderUnavailable
	})
	if _, err := LoadKeyring(context.Background(), providerErr); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("提供者错误 = %v", err)
	}

	emptyProvider := ProviderFunc(func(context.Context) ([]byte, error) { return nil, nil })
	if _, err := LoadKeyring(context.Background(), emptyProvider); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("空文档错误 = %v, 期望 ErrProviderUnavailable", err)
	}

	if _, err := LoadKeyring(context.Background(), nil); !errors.Is(err, ErrKeyMaterialMissing) {
		t.Fatalf("nil 提供者错误 = %v, 期望 ErrKeyMaterialMissing", err)
	}
}

func TestProviderFuncNilFailsClosed(t *testing.T) {
	// typed nil 函数不是合法提供者：必须明确失败，不能调用时 panic。
	var nilFunc ProviderFunc
	if _, err := nilFunc.KeyringDocument(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil ProviderFunc 错误 = %v, 期望 ErrProviderUnavailable", err)
	}
	var provider Provider = nilFunc
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("nil ProviderFunc 加载错误 = %v, 期望 ErrProviderUnavailable", err)
	}
}

func TestLoadKeyringRespectsCanceledContext(t *testing.T) {
	ring := mustGenerateKeyring(t, "k1")
	doc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	provider := ProviderFunc(func(ctx context.Context) ([]byte, error) {
		return doc, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LoadKeyring(ctx, provider); !errors.Is(err, context.Canceled) {
		t.Fatalf("取消错误 = %v, 期望 context.Canceled", err)
	}
}

func TestNewFileProviderPathValidation(t *testing.T) {
	if _, err := NewFileProvider(""); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("空路径错误 = %v", err)
	}
	if _, err := NewFileProvider("relative/master-key.json"); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("相对路径错误 = %v", err)
	}
	abs := filepath.Join(testutil.TempDir(t), "missing.json")
	if _, err := NewFileProvider(abs); err != nil {
		t.Fatalf("绝对路径不应在构造阶段失败: %v", err)
	}
}

func TestCheckProtectedFile(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "master-key.json")
	if err := WriteProtectedFile(path, []byte("data")); err != nil {
		t.Fatalf("WriteProtectedFile 失败: %v", err)
	}
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("受保护文件检查失败: %v", err)
	}
	if err := CheckProtectedFile(filepath.Join(dir, "missing.json")); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("缺失文件错误 = %v", err)
	}
	if err := CheckProtectedFile(dir); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("目录错误 = %v", err)
	}
	if err := CheckProtectedFile(""); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("空路径错误 = %v", err)
	}
}

func TestWriteProtectedFileValidations(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "master-key.json")
	if err := WriteProtectedFile(path, nil); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("空内容错误 = %v", err)
	}
	if err := WriteProtectedFile(path, bytes.Repeat([]byte("x"), MaxKeyringDocumentBytes+1)); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("超长内容错误 = %v", err)
	}
	if err := WriteProtectedFile("", []byte("x")); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("空路径错误 = %v", err)
	}
	// 主密钥写入必须使用显式绝对路径，避免随进程工作目录写到意外位置。
	if err := WriteProtectedFile("master-key.json", []byte("x")); !errors.Is(err, ErrFileInvalid) {
		t.Fatalf("相对路径错误 = %v, 期望 ErrFileInvalid", err)
	}
}

func TestWriteProtectedFileAtomicReplace(t *testing.T) {
	dir := testutil.TempDir(t)
	path := filepath.Join(dir, "master-key.json")
	first, err := mustGenerateKeyring(t, "k1").Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	second, err := mustGenerateKeyring(t, "k2").Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if err := WriteProtectedFile(path, first); err != nil {
		t.Fatalf("第一次写入失败: %v", err)
	}
	if err := WriteProtectedFile(path, second); err != nil {
		t.Fatalf("第二次写入失败: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if !bytes.Equal(got, second) {
		t.Fatal("原子替换后内容不是第二次写入的文档")
	}
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("替换后权限检查失败: %v", err)
	}
	// 目标目录里不应残留临时文件。
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".evernight-secret-") {
			t.Fatalf("残留临时密钥文件: %s", entry.Name())
		}
	}
}

func TestValidateUnixFileModePerm(t *testing.T) {
	allowed := []os.FileMode{0o600, 0o400, 0}
	for _, perm := range allowed {
		if err := validateUnixFileModePerm(perm); err != nil {
			t.Fatalf("权限 %04o 应被接受: %v", perm, err)
		}
	}
	rejected := []os.FileMode{0o640, 0o604, 0o660, 0o666, 0o607, 0o777, 0o020, 0o002}
	for _, perm := range rejected {
		if err := validateUnixFileModePerm(perm); !errors.Is(err, ErrInsecurePermissions) {
			t.Fatalf("权限 %04o 应被拒绝，错误 = %v", perm, err)
		}
	}
}
