//go:build windows

package setupconsole

// Windows 维护日志文件 ACL 加固（SEC LOW-1 修复，选项 a+b）。
//
// Windows 上 os.Chmod(0600) 不会映射为「仅当前用户」的 NTFS ACL（实测可能得到
// Everyone/Users 可写）。本文件在创建维护日志后显式设置受保护 DACL：
//   - 只授予当前 OS 用户、SYSTEM、本机 Administrators 组完全控制；
//   - 设置 PROTECTED_DACL，阻止父目录继承的宽松 ACE；
//   - 随后做启动自检：枚举 DACL，若发现 Everyone/Users/Authenticated Users/
//     ANONYMOUS 等宽泛主体拥有写/改 ACL 权限，则拒绝继续（fail-closed），
//     不能把关键维护操作记录写入可能被他人篡改的文件。
// 无法应用或校验 DACL 时同样 fail-closed。

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// prepareMaintenanceLogFile 对维护日志应用并自检 Windows DACL。
func prepareMaintenanceLogFile(path string) error {
	if err := restrictMaintenanceLogDACL(path); err != nil {
		return fmt.Errorf("%w: 设置 Windows ACL 失败: %v", ErrLogUnavailable, err)
	}
	if err := verifyMaintenanceLogProtection(path); err != nil {
		return fmt.Errorf("%w: Windows ACL 自检失败: %v", ErrLogUnavailable, err)
	}
	return nil
}

// restrictMaintenanceLogDACL 把文件 DACL 限制为当前用户+SYSTEM+Administrators。
func restrictMaintenanceLogDACL(path string) error {
	currentUserSID, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	allowedSIDs := []string{currentUserSID, "S-1-5-18", "S-1-5-32-544"}
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(allowedSIDs))
	for _, sidText := range allowedSIDs {
		sid, sidErr := windows.StringToSid(sidText)
		if sidErr != nil {
			return fmt.Errorf("解析受信 SID 失败: %v", sidErr)
		}
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("构造 DACL 失败: %v", err)
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
}

// currentProcessUserSID 返回当前进程令牌的用户 SID 文本（不含域名）。
func currentProcessUserSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("打开进程令牌失败: %v", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("读取令牌用户失败: %v", err)
	}
	return user.User.Sid.String(), nil
}

// verifyMaintenanceLogProtection 枚举 DACL，拒绝宽泛主体拥有写权限的日志文件。
func verifyMaintenanceLogProtection(path string) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("读取安全描述符失败: %v", err)
	}
	if descriptor == nil {
		return fmt.Errorf("安全描述符为空")
	}
	dacl, _, daclErr := descriptor.DACL()
	if daclErr != nil {
		return fmt.Errorf("读取 DACL 失败: %v", daclErr)
	}
	if dacl == nil {
		return fmt.Errorf("文件没有 DACL（等于无保护）")
	}
	aceCount := int(dacl.AceCount)
	for index := 0; index < aceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if aceErr := windows.GetAce(dacl, uint32(index), &ace); aceErr != nil || ace == nil {
			return fmt.Errorf("枚举 ACE 失败: %v", aceErr)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		writeMask := uint32(windows.FILE_GENERIC_WRITE) | uint32(windows.GENERIC_WRITE) |
			uint32(windows.FILE_WRITE_DATA) | uint32(windows.FILE_APPEND_DATA) |
			uint32(windows.WRITE_DAC) | uint32(windows.WRITE_OWNER)
		if uint32(ace.Mask)&writeMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if isBroadSID(sid.String()) {
			return fmt.Errorf("DACL 授予宽泛主体 %s 写/改 ACL 权限", sid.String())
		}
	}
	return nil
}

// isBroadSID 判断 SID 是否属于不应拥有维护日志写权限的宽泛主体。
func isBroadSID(sid string) bool {
	switch sid {
	case "S-1-1-0", // Everyone
		"S-1-5-7",      // ANONYMOUS LOGON
		"S-1-5-11",     // Authenticated Users
		"S-1-5-32-545": // BUILTIN\Users
		return true
	}
	return false
}
