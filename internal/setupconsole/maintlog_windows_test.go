//go:build windows

package setupconsole

// SEC LOW-1 Windows 定向测试：维护日志 DACL 加固与宽泛 ACL 自检拒绝。

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsMaintenanceLogACLSelfCheck 验证加固后自检通过、宽泛 ACL 被拒绝。
func TestWindowsMaintenanceLogACLSelfCheck(t *testing.T) {
	dir := t.TempDir()
	logStore, err := OpenMaintenanceLog(dir)
	if err != nil {
		t.Fatalf("打开维护日志（应成功加固 ACL）: %v", err)
	}
	meta, ok := logStore.(*maintenanceLog)
	if !ok {
		t.Fatalf("维护日志类型异常")
	}
	if err := verifyMaintenanceLogProtection(meta.Path()); err != nil {
		t.Fatalf("加固后自检应通过: %v", err)
	}
	// 故意放开 Everyone 写权限：自检必须识别为宽泛 ACL 并拒绝。
	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatalf("解析 Everyone SID: %v", err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.FILE_GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone),
		},
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, nil)
	if err != nil {
		t.Fatalf("构造宽泛 ACL: %v", err)
	}
	// 合并到既有 DACL（ACLFromEntries 第二个参数为空会得到仅 Everyone 的 DACL，
	// 同样属于宽泛 ACL 且足够验证自检）。
	if err := windows.SetNamedSecurityInfo(meta.Path(), windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("设置宽泛 ACL: %v", err)
	}
	if err := verifyMaintenanceLogProtection(meta.Path()); err == nil {
		t.Fatal("宽泛 ACL（Everyone 可写）必须被维护日志自检拒绝")
	}
	// 重新加固后可恢复通过。
	if err := prepareMaintenanceLogFile(meta.Path()); err != nil {
		t.Fatalf("重新加固维护日志: %v", err)
	}
	if err := verifyMaintenanceLogProtection(meta.Path()); err != nil {
		t.Fatalf("重新加固后自检应通过: %v", err)
	}
}

// TestWindowsMaintenanceLogPreexistingWideACL 预置宽 ACL 文件在打开时应被纠正加固。
func TestWindowsMaintenanceLogPreexistingWideACL(t *testing.T) {
	dir := t.TempDir()
	path := dir + string(os.PathSeparator) + maintenanceLogFileName
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("预置日志文件: %v", err)
	}
	everyone, _ := windows.StringToSid("S-1-1-0")
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.FILE_GENERIC_WRITE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(everyone)},
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, nil)
	if err != nil {
		t.Fatalf("构造宽泛 ACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatalf("设置宽泛 ACL: %v", err)
	}
	if _, err := OpenMaintenanceLog(dir); err != nil {
		t.Fatalf("打开时应加固既有日志而不是失败: %v", err)
	}
	if err := verifyMaintenanceLogProtection(path); err != nil {
		t.Fatalf("打开后应完成加固并通过自检: %v", err)
	}
}
