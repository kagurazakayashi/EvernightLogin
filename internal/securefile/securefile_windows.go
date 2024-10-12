//go:build windows

package securefile

// Windows：os.Chmod(0600) 不会映射为「仅当前用户」的 NTFS ACL，必须显式设置
// 受保护 DACL 并自检，否则拒绝把文件当作秘密文件。
//
// 允许的主体：当前 OS 用户、SYSTEM、内置 Administrators。
// 拒绝的主体（拥有任何访问权限即失败）：Everyone、ANONYMOUS LOGON、
// Authenticated Users、BUILTIN\Users。
// 同时要求 DACL 已设置 PROTECTED 位，避免父目录继承的宽松 ACE 重新进入。

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect 对新文件设置受保护 DACL 并自检；失败由 Write 删除半成品。
func protect(path string) error {
	if err := restrictDACL(path); err != nil {
		return fmt.Errorf("%w: 设置 Windows ACL 失败: %v", ErrProtectFailed, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%w: 读取文件状态失败: %v", ErrProtectFailed, err)
	}
	return verify(path, info)
}

// restrictDACL 把文件 DACL 限制为当前用户+SYSTEM+Administrators。
func restrictDACL(path string) error {
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

// currentProcessUserSID 返回当前进程令牌的用户 SID 文本。
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

// verify 校验 Windows DACL：必须存在、受保护，且没有宽泛主体的允许 ACE。
func verify(path string, _ os.FileInfo) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%w: 读取安全描述符失败: %v", ErrInsecurePerm, err)
	}
	if descriptor == nil {
		return fmt.Errorf("%w: 安全描述符为空", ErrInsecurePerm)
	}
	control, _, controlErr := descriptor.Control()
	if controlErr != nil {
		return fmt.Errorf("%w: 读取安全描述符控制位失败: %v", ErrInsecurePerm, controlErr)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: DACL 未设置受保护位（可能继承父目录 ACE）", ErrInsecurePerm)
	}
	dacl, _, daclErr := descriptor.DACL()
	if daclErr != nil {
		return fmt.Errorf("%w: 读取 DACL 失败: %v", ErrInsecurePerm, daclErr)
	}
	if dacl == nil {
		return fmt.Errorf("%w: 文件没有 DACL（等于无保护）", ErrInsecurePerm)
	}
	aceCount := int(dacl.AceCount)
	for index := 0; index < aceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if aceErr := windows.GetAce(dacl, uint32(index), &ace); aceErr != nil || ace == nil {
			return fmt.Errorf("%w: 枚举 ACE 失败: %v", ErrInsecurePerm, aceErr)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask) == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if isBroadSID(sid.String()) {
			return fmt.Errorf("%w: DACL 授予宽泛主体 %s 访问权限", ErrInsecurePerm,
				sid.String())
		}
	}
	return nil
}

// isBroadSID 判断 SID 是否属于不应访问秘密文件的宽泛主体。
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
