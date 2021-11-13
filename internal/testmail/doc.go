// Package testmail 提供仅供测试使用的本地 SMTP 接收服务器，并可选择提供只读
// IMAP4rev1 与 POP3 收件箱，供真实邮件客户端（Thunderbird、Outlook、Foxmail 等）
// 连接查看模拟账户收到的测试邮件。
//
// 该包只用于在没有真实外发的前提下验证邮件相关功能（例如后续的邮件模板与投递、
// 敏感操作邮件告知）：测试或本地工具在回环地址上启动一个最小邮件服务器，把收到
// 的消息保存在内存中，供调用方断言信封收发件人、头部、主题、日期与原始字节；
// 同一批消息可以按模拟账户隔离后，通过只读 IMAP/POP3 在邮件客户端中查看。
//
// 安全边界与设计约束：
//   - 本包不投递、不中继、不连接任何外部邮件服务；收到的消息无论收件人域名是什么
//     都只保存在本地内存中。整个包的实现中不存在向外拨号的代码路径（有测试守护）。
//   - 默认只监听 127.0.0.1:0（随机端口）；监听非回环地址必须显式设置
//     Options.AllowNonLoopback，避免测试基础设施被误暴露到网络。IMAP/POP3 的
//     明文监听只允许回环地址；非回环监听必须同时启用隐式 TLS。
//   - 本包是测试基础设施，不是产品能力，不得被 cmd/login-server 或其他生产装配
//     路径导入（有测试守护）。生产邮件发送实现必须另行编写，不能把本包当作投递器。
//   - AUTH、IMAP LOGIN 与 POP3 USER/PASS 只接受显式配置的测试凭据；不读取环境
//     变量、配置文件或凭证库。凭据不会出现在错误、日志或消息记录中。
//   - 所有会话有读超时与总时长上限；单消息大小、收件人数、并发连接数与内存中保留
//     的消息数都有硬上限，超限时返回标准协议错误码而不是继续占用资源。
//   - IMAP/POP3 收件箱按模拟账户隔离：消息按信封收件人与 To/Cc/Bcc 本地部分映射，
//     非收件账户看不到消息；所有写操作（标记、删除、追加、复制）一律拒绝，POP3 的
//     DELE 只在本会话内隐藏消息，不会真正删除共享存储。
//
// 最小 SMTP 会话支持 EHLO/HELO、MAIL FROM、RCPT TO、DATA（含点填充还原）、RSET、
// NOOP、QUIT，以及可选的 AUTH PLAIN/AUTH LOGIN 和 STARTTLS。消息体按原样保存
// （行尾统一为 CRLF）；头部按原文保留并额外解析常用字段（Subject 按 RFC 2047
// 尽力解码，Date 按 mail.ParseDate 尽力解析）。
//
// 可选只读 IMAP4rev1 会话支持 CAPABILITY、NOOP、LOGIN、LIST/LSUB、SELECT/EXAMINE、
// FETCH/UID FETCH（UID、FLAGS、INTERNALDATE、SIZE、BODY[]、RFC822、RFC822.HEADER、
// RFC822.TEXT、BODY[HEADER.FIELDS (...)]、ENVELOPE）、STATUS、CLOSE、LOGOUT；
// 可选只读 POP3 会话支持 USER/PASS、STAT、LIST、RETR、TOP、DELE（仅本会话）、
// RSET、NOOP、QUIT、CAPA。两者都不支持 BODYSTRUCTURE 等高级 FETCH 项。
//
// 典型用法：
//
//	srv, err := testmail.New(testmail.Options{
//		Auth: &testmail.AuthOptions{Users: map[string]string{"tester": "test-pass"}},
//		IMAP: &testmail.IMAPOptions{},
//	})
//	if err != nil {
//		return err
//	}
//	if err := srv.Start(); err != nil {
//		return err
//	}
//	defer srv.Close()
//	// 用标准 SMTP 客户端连接 srv.Addr()，用邮件客户端连接 srv.IMAPAddr()。
//	msgs, err := srv.Wait(ctx, testmail.Query{To: "user@example.test"})
//	if err != nil {
//		return err
//	}
//	_ = msgs[0].Data
package testmail
