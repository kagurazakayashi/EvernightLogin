//go:build windows

package main

// Windows 密码文件读取校验：正确受保护文件通过；显式宽 ACL 文件拒绝。
// 与 internal/securefile 的 DACL 实现配套，验证 CLI 确实调用了受保护读取。

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/kagurazakayashi/EvernightLogin/internal/securefile"
)

func TestPasswordFileWindowsACL(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "protected.pwd")
	if err := securefile.Write(protected, []byte("Protected-Pass-1!\n")); err != nil {
		t.Fatalf("创建受保护密码文件: %v", err)
	}
	password, _, err := readCLISecret(cliEnv{}, "root", false, protected, false)
	if err != nil || password != "Protected-Pass-1!" {
		t.Fatalf("受保护密码文件读取失败: %q %v", password, err)
	}
	wide := filepath.Join(dir, "wide.pwd")
	if err := os.WriteFile(wide, []byte("Wide-Acl-Pass-1!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := grantEveryoneReadForTest(wide); err != nil {
		t.Fatalf("构造宽 ACL: %v", err)
	}
	if _, _, err := readCLISecret(cliEnv{}, "root", false, wide, false); err == nil {
		t.Fatal("宽 ACL 密码文件必须被拒绝")
	}
}

// grantEveryoneReadForTest 给文件追加 Everyone 读取 ACE（不设 PROTECTED 位）。
func grantEveryoneReadForTest(path string) error {
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
