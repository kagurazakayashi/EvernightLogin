//go:build windows

package securefile

// Windows DACL 专项测试：正确 ACL 通过、宽 ACL 拒绝、受保护位检查。

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsWriteAppliesRestrictedDACL 新建秘密文件的 DACL 必须通过 verify。
func TestWindowsWriteAppliesRestrictedDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := Write(path, []byte("secret")); err != nil {
		t.Fatalf("写入并加固秘密文件: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(path, info); err != nil {
		t.Fatalf("新建秘密文件 DACL 自检失败: %v", err)
	}
	if _, err := Read(path, DefaultMaxBytes); err != nil {
		t.Fatalf("受保护秘密文件应可读: %v", err)
	}
}

// TestWindowsReadRejectsWideACL 显式授予 Everyone 读取后，Read 必须拒绝。
func TestWindowsReadRejectsWideACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wide.txt")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := grantEveryoneRead(path); err != nil {
		t.Fatalf("构造宽 ACL: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(path, info); !errors.Is(err, ErrInsecurePerm) {
		t.Fatalf("宽 ACL 应被拒绝，得到 %v", err)
	}
	if _, err := Read(path, DefaultMaxBytes); !errors.Is(err, ErrInsecurePerm) {
		t.Fatalf("Read 应拒绝宽 ACL，得到 %v", err)
	}
}

// TestWindowsReadRejectsUnprotectedDACL 去掉受保护位（模拟父目录继承）后拒绝。
func TestWindowsReadRejectsUnprotectedDACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inherited.txt")
	if err := Write(path, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	// 用显式 DACL 重新设置但不带 PROTECTED 位，模拟继承来的宽松 ACE。
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, daclErr := descriptor.DACL()
	if daclErr != nil || dacl == nil {
		t.Fatalf("读取 DACL: %v", daclErr)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.UNPROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("设置未保护 DACL: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verify(path, info); !errors.Is(err, ErrInsecurePerm) {
		t.Fatalf("未保护 DACL 应被拒绝，得到 %v", err)
	}
}

// grantEveryoneRead 给文件追加 Everyone 读取 ACE（不设 PROTECTED 位）。
func grantEveryoneRead(path string) error {
	sid, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		return err
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_READ,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
