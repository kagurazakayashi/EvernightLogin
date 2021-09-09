package testmail

import "strings"

// SessionEventKind 是会话轨迹事件的类型。
type SessionEventKind string

// 会话轨迹事件类型。轨迹只用于调试与人工观察，不承载业务数据。
const (
	// SessionEventConnected 表示连接已建立（尚未发送问候语）。
	SessionEventConnected SessionEventKind = "connected"
	// SessionEventCommand 表示收到一条客户端命令。参数已做凭据脱敏。
	SessionEventCommand SessionEventKind = "command"
	// SessionEventReply 表示服务端已成功写出一段应答。
	SessionEventReply SessionEventKind = "reply"
	// SessionEventTLS 表示 STARTTLS 握手完成（无法在此报告失败细节）。
	SessionEventTLS SessionEventKind = "tls"
	// SessionEventAuth 表示认证成功，Parameter 为用户名。
	SessionEventAuth SessionEventKind = "auth"
	// SessionEventClosed 表示会话结束（连接被关闭或对端断开）。
	SessionEventClosed SessionEventKind = "closed"
)

// SessionEvent 是一次 SMTP 会话中的可观察事件，供调试输出使用。
//
// 安全边界：事件中的 AUTH 命令参数始终替换为脱敏文本；DATA 内容与 AUTH 客户端
// 响应（包括 AUTH LOGIN 的用户名/密码行）不会进入事件。用户名属于测试配置本身，
// 可以出现在认证成功事件中；密码永远不会出现。
type SessionEvent struct {
	// Kind 是事件类型。
	Kind SessionEventKind
	// SessionID 是服务内自增的会话编号（从 1 开始），用于区分并发连接。
	SessionID uint64
	// RemoteAddr 是客户端地址（host:port）。
	RemoteAddr string
	// Command 是命令动词（大写）、响应码或事件名，含义随 Kind 而定。
	Command string
	// Parameter 是命令参数（已脱敏）、响应文本或事件补充信息。
	Parameter string
}

// redactCommandArg 返回可安全写入调试轨迹的命令参数。
//
// AUTH 的初始响应（PLAIN 的 base64 口令、LOGIN 的用户名）必须脱敏：只保留机制名。
// 其余命令的参数（信封地址、EHLO 主机名等）本来就是测试数据，可原样记录。
func redactCommandArg(verb, arg string) string {
	if strings.EqualFold(verb, "AUTH") {
		fields := strings.Fields(arg)
		if len(fields) == 0 {
			return "[凭据已脱敏]"
		}
		return fields[0] + " [凭据已脱敏]"
	}
	return arg
}
