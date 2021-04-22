//go:build windows

package secrets

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 本文件实现 Windows 下的密钥文件保护。Windows 的访问控制由安全描述符与
// DACL 决定，Unix 的 chmod 位在 Windows 上不是有效的访问控制，因此这里不使用
// os.FileMode 判断权限，而是读取实际 DACL：
//
//   - 文件所有者必须是当前进程用户、SYSTEM 或 Administrators；
//   - DACL 必须存在（NULL DACL 等于所有人完全访问，直接拒绝）；
//   - 除当前进程用户、SYSTEM、Administrators 之外，任何允许访问的 ACE 都视为
//     权限过宽；无法识别的 ACE 类型按失败处理（默认拒绝）；
//   - 仅作用于子对象的 INHERIT_ONLY_ACE 不影响文件本身，允许存在。
//
// 受信任主体列表是保守白名单：主机管理员与 SYSTEM 本来就能读取进程与文件，
// 本检查的目标是防止普通用户或其它主体读取密钥文件，不承诺抵御主机失陷。

const (
	systemSIDString = "S-1-5-18"     // LOCAL SYSTEM
	adminsSIDString = "S-1-5-32-544" // BUILTIN\Administrators
)

// checkFileProtection 读取已打开文件的安全描述符并确认 DACL 只向受信任主体授权。
// 使用文件句柄而不是路径，避免检查与读取之间被替换目标。
func checkFileProtection(file *os.File, _ os.FileInfo) error {
	sd, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: 无法读取文件安全描述符", ErrInsecurePermissions)
	}
	return checkSecurityDescriptor(sd)
}

// checkSecurityDescriptor 检查所有者与 DACL 是否只允许受信任主体访问。
func checkSecurityDescriptor(sd *windows.SECURITY_DESCRIPTOR) error {
	me, system, admins, err := trustedPrincipals()
	if err != nil {
		return fmt.Errorf("%w: 无法确认当前进程身份", ErrInsecurePermissions)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: 无法确认文件所有者", ErrInsecurePermissions)
	}
	if !isTrustedPrincipal(owner, me, system, admins) {
		return fmt.Errorf("%w: 文件所有者不是当前受信任主体", ErrInsecurePermissions)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: 文件缺少可用的 DACL", ErrInsecurePermissions)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return fmt.Errorf("%w: 无法读取 DACL 项", ErrInsecurePermissions)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			// 该 ACE 只继承给子对象，不影响这个文件本身。
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if !isTrustedPrincipal(sid, me, system, admins) {
				return fmt.Errorf("%w: DACL 向非授权主体 %s 授予访问", ErrInsecurePermissions, sid.String())
			}
		case windows.ACCESS_DENIED_ACE_TYPE:
			// 拒绝项缩小访问范围，不构成泄露风险。
		default:
			return fmt.Errorf("%w: DACL 含无法识别的 ACE 类型 %d", ErrInsecurePermissions, ace.Header.AceType)
		}
	}
	return nil
}

// trustedPrincipals 返回当前进程用户 SID、SYSTEM SID 与 Administrators SID。
// 返回的 SID 都是 Go 堆上的副本，调用方在使用期间必须保持引用以维持存活。
func trustedPrincipals() (me, system, admins *windows.SID, err error) {
	token := windows.GetCurrentProcessToken()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, nil, nil, err
	}
	me, err = tokenUser.User.Sid.Copy()
	if err != nil {
		return nil, nil, nil, err
	}
	system, err = windows.StringToSid(systemSIDString)
	if err != nil {
		return nil, nil, nil, err
	}
	admins, err = windows.StringToSid(adminsSIDString)
	if err != nil {
		return nil, nil, nil, err
	}
	return me, system, admins, nil
}

// isTrustedPrincipal 报告 SID 是否属于允许访问密钥文件的主体白名单。
func isTrustedPrincipal(sid *windows.SID, me, system, admins *windows.SID) bool {
	if sid == nil {
		return false
	}
	return sid.Equals(me) || sid.Equals(system) || sid.Equals(admins)
}

// writeProtectedFile 原子地写入受保护文件：先创建临时文件，立刻收紧 DACL，
// 再写入内容并重命名；重命名后重新检查权限。这样内容不会在任何时间段出现在
// 权限未收紧的文件中。
func writeProtectedFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".evernight-secret-*.tmp")
	if err != nil {
		return fmt.Errorf("%w: 无法在目标目录创建临时文件", ErrFileInvalid)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := setProtectedDACL(tmpName); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("%w: 写入临时密钥文件失败", ErrFileInvalid)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("%w: 同步临时密钥文件失败", ErrFileInvalid)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: 关闭临时密钥文件失败", ErrFileInvalid)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("%w: 无法替换目标密钥文件", ErrFileInvalid)
	}
	// 重命名后按实际文件重新检查，确认目标文件权限确实已收紧。
	return CheckProtectedFile(path)
}

// setProtectedDACL 为指定文件设置受保护 DACL：只允许当前用户、SYSTEM 和
// Administrators 完全控制，并阻止从父目录继承更宽的权限。
func setProtectedDACL(path string) error {
	sd, err := buildProtectedDescriptor()
	if err != nil {
		return err
	}
	absoluteSD, err := sd.ToAbsolute()
	if err != nil {
		return fmt.Errorf("%w: 无法转换安全描述符", ErrInsecurePermissions)
	}
	dacl, _, err := absoluteSD.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: 无法从安全描述符取得 DACL", ErrInsecurePermissions)
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
	if err != nil {
		return fmt.Errorf("%w: 无法设置文件 DACL", ErrInsecurePermissions)
	}
	return nil
}

// buildProtectedDescriptor 构造只授权当前用户、SYSTEM 与 Administrators 的
// 安全描述符。SID 指针在调用期间必须保持存活，因此用 runtime.Pinner 固定。
func buildProtectedDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	me, system, admins, err := trustedPrincipals()
	if err != nil {
		return nil, fmt.Errorf("%w: 无法确认当前进程身份", ErrInsecurePermissions)
	}
	var pinner runtime.Pinner
	defer pinner.Unpin()
	for _, sid := range []*windows.SID{me, system, admins} {
		pinner.Pin(sid)
	}
	entries := []windows.EXPLICIT_ACCESS{
		explicitAccess(me, windows.TRUSTEE_IS_USER),
		explicitAccess(system, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
		explicitAccess(admins, windows.TRUSTEE_IS_WELL_KNOWN_GROUP),
	}
	sd, err := windows.BuildSecurityDescriptor(nil, nil, entries, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: 无法构造安全描述符", ErrInsecurePermissions)
	}
	return sd, nil
}

// explicitAccess 构造一条“完全控制”允许项。
func explicitAccess(sid *windows.SID, trusteeType windows.TRUSTEE_TYPE) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  trusteeType,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}
