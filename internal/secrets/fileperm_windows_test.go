//go:build windows

package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/windows"
)

// 本文件在 Windows 上实际验证 ACL 检查，而不是只依赖 Unix 权限位的逻辑。
// 测试只操作 t.TempDir() 下的临时文件，不修改系统路径或用户主目录。

// everyoneSID 返回 Everyone（S-1-1-0）SID。
func everyoneSID(t *testing.T) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatalf("StringToSid 失败: %v", err)
	}
	return sid
}

// addAllowACE 在路径现有 DACL 上追加一条允许项。inheritance 为 ACE 继承标志。
func addAllowACE(t *testing.T, path string, sid *windows.SID, mask windows.ACCESS_MASK, inheritance uint32) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		t.Fatalf("GetNamedSecurityInfo 失败: %v", err)
	}
	oldDACL, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("读取 DACL 失败: %v", err)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(sid)
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	acl, err := windows.ACLFromEntries(entries, oldDACL)
	if err != nil {
		t.Fatalf("ACLFromEntries 失败: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo 失败: %v", err)
	}
}

// clearDACL 把文件 DACL 设为 NULL（完全开放），用于验证默认拒绝行为。
func clearDACL(t *testing.T, path string) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, nil, nil); err != nil {
		t.Fatalf("设置 NULL DACL 失败: %v", err)
	}
}

func TestWindowsProtectedFileACL(t *testing.T) {
	path, ring := writeTestKeyringFile(t, t.TempDir(), "master-key.json", "k1")
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("受保护文件检查失败: %v", err)
	}
	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	loaded, err := LoadKeyring(context.Background(), provider)
	if err != nil {
		t.Fatalf("LoadKeyring 失败: %v", err)
	}
	if loaded.CurrentKeyID() != ring.CurrentKeyID() {
		t.Fatalf("加载后当前密钥 = %q", loaded.CurrentKeyID())
	}
}

func TestWindowsWideExplicitACLRejected(t *testing.T) {
	path, ring := writeTestKeyringFile(t, t.TempDir(), "master-key.json", "k1")
	addAllowACE(t, path, everyoneSID(t), windows.GENERIC_READ, 0)

	err := CheckProtectedFile(path)
	if !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("宽 ACL 检查错误 = %v, 期望 ErrInsecurePermissions", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("S-1-1-0")) {
		t.Fatalf("错误信息未指出越权主体 SID: %v", err)
	}

	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("宽 ACL 密钥加载错误 = %v, 期望 ErrInsecurePermissions", err)
	}
	// 权限检查失败不应删除或改写原密钥文件。
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("密钥文件被意外删除: %v", err)
	}
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取密钥文件失败: %v", err)
	}
	wantDoc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	if !bytes.Equal(doc, wantDoc) {
		t.Fatal("权限检查失败路径修改了密钥文件内容")
	}
}

func TestWindowsNullDACLRejected(t *testing.T) {
	path, _ := writeTestKeyringFile(t, t.TempDir(), "master-key.json", "k1")
	clearDACL(t, path)
	if err := CheckProtectedFile(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("NULL DACL 检查错误 = %v, 期望 ErrInsecurePermissions", err)
	}
}

func TestWindowsWideInheritedACLRejected(t *testing.T) {
	dir := t.TempDir()
	// 在父目录上增加可继承的 Everyone 读取 ACE，子文件创建后会继承它。
	addAllowACE(t, dir, everyoneSID(t), windows.GENERIC_READ,
		uint32(windows.CONTAINER_INHERIT_ACE|windows.OBJECT_INHERIT_ACE))
	path := filepath.Join(dir, "inherited-key.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("创建继承 ACL 文件失败: %v", err)
	}
	if err := CheckProtectedFile(path); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("继承宽 ACL 检查错误 = %v, 期望 ErrInsecurePermissions", err)
	}
}

func TestWindowsWriteProtectedFileOverridesPermissiveParent(t *testing.T) {
	dir := t.TempDir()
	addAllowACE(t, dir, everyoneSID(t), windows.GENERIC_READ,
		uint32(windows.CONTAINER_INHERIT_ACE|windows.OBJECT_INHERIT_ACE))
	path := filepath.Join(dir, "protected-in-bad-dir.json")
	ring := mustGenerateKeyring(t, "k1")
	doc, err := ring.Document()
	if err != nil {
		t.Fatalf("Document 失败: %v", err)
	}
	// 父目录权限过宽时，写入函数必须显式收紧文件 DACL 并阻断继承。
	if err := WriteProtectedFile(path, doc); err != nil {
		t.Fatalf("WriteProtectedFile 失败: %v", err)
	}
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("受保护写入后检查失败: %v", err)
	}
	provider, err := NewFileProvider(path)
	if err != nil {
		t.Fatalf("NewFileProvider 失败: %v", err)
	}
	if _, err := LoadKeyring(context.Background(), provider); err != nil {
		t.Fatalf("受保护写入后加载失败: %v", err)
	}
}

func TestWindowsInheritOnlyACEAllowed(t *testing.T) {
	path, _ := writeTestKeyringFile(t, t.TempDir(), "master-key.json", "k1")
	// 仅继承给子对象的 ACE 不影响文件自身访问，允许存在。
	addAllowACE(t, path, everyoneSID(t), windows.GENERIC_READ, uint32(windows.INHERIT_ONLY_ACE))
	if err := CheckProtectedFile(path); err != nil {
		t.Fatalf("INHERIT_ONLY ACE 不应导致失败: %v", err)
	}
}
