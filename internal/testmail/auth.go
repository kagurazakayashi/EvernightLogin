package testmail

import (
	"crypto/sha256"
	"crypto/subtle"
)

// credentialsMatch 以恒定时间比较检查模拟测试凭据。遍历全部配置用户，避免因为
// 提前返回而暴露用户名是否存在的时序差异（测试凭据数量很少，开销可忽略）。
//
// 安全边界：只比较 AuthOptions.Users 中显式配置的测试凭据；不读取环境变量、
// 凭证库或任何真实秘密。该函数只返回布尔值，不记录、不回显传入的凭据。
func credentialsMatch(users map[string]string, user, pass string) bool {
	gotUser := sha256.Sum256([]byte(user))
	gotPass := sha256.Sum256([]byte(pass))
	matched := false
	for wantUser, wantPass := range users {
		wu := sha256.Sum256([]byte(wantUser))
		wp := sha256.Sum256([]byte(wantPass))
		userOK := subtle.ConstantTimeCompare(gotUser[:], wu[:]) == 1
		passOK := subtle.ConstantTimeCompare(gotPass[:], wp[:]) == 1
		if userOK && passOK {
			matched = true
		}
	}
	return matched
}
