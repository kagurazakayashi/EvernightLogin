package testmail

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// closeTimeout 是 Close 等待会话 goroutine 退出的上限；超过后报告错误但不再阻塞。
const closeTimeout = 10 * time.Second

// waitPollInterval 是 Wait 轮询内存仓库的间隔。
const waitPollInterval = 10 * time.Millisecond

// ErrCloseTimeout 表示 Close 等待会话 goroutine 退出超时（正常路径不应出现）。
var ErrCloseTimeout = errors.New("testmail: 等待会话退出超时")

// protocol 是监听器承载的协议类型。
type protocol int

const (
	// protocolSMTP 是默认的 SMTP 收信监听器。
	protocolSMTP protocol = iota
	// protocolIMAP 是只读 IMAP4rev1 收件箱监听器。
	protocolIMAP
	// protocolPOP3 是只读 POP3 收件箱监听器。
	protocolPOP3
)

// Server 是本地测试邮件服务器（SMTP 收信，可选只读 IMAP/POP3 收件箱）。
//
// 生命周期：New 只校验配置，Start 才监听端口并开始接受连接；Close 停止接受新
// 连接、强制关闭仍活动的连接并等待会话退出（端口在 Listen 关闭后释放）。Close
// 是幂等的，可在 Start 之前调用。SMTP、IMAP、POP3 共用同一个内存仓库与同一份
// 模拟账户配置，因此通过 SMTP 收到的邮件可以立即在邮件客户端中读到。
type Server struct {
	opts        Options
	tlsConf     *tls.Config
	imapTLSConf *tls.Config
	pop3TLSConf *tls.Config
	store       *store

	mu       sync.Mutex
	ln       net.Listener
	imapLn   net.Listener
	pop3Ln   net.Listener
	started  bool
	closed   bool
	conns    map[net.Conn]struct{}
	sem      chan struct{}
	imapSem  chan struct{}
	pop3Sem  chan struct{}
	closedCh chan struct{}
	acceptWG sync.WaitGroup
	sessWG   sync.WaitGroup
	closeOne sync.Once
	closeErr error

	// sessionSeq 为调试轨迹分配自增会话编号；只用于区分并发连接。
	sessionSeq atomic.Uint64
}

// New 校验配置并创建服务器（尚未监听端口）。
func New(opts Options) (*Server, error) {
	normalized, err := opts.normalize()
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:     normalized,
		store:    newStore(normalized.MaxMessages),
		conns:    make(map[net.Conn]struct{}),
		sem:      make(chan struct{}, normalized.MaxConnections),
		closedCh: make(chan struct{}),
	}
	if normalized.TLS != nil {
		s.tlsConf = newTLSConfig(normalized.TLS.Certificate)
	}
	if normalized.IMAP != nil {
		s.imapSem = make(chan struct{}, normalized.MaxConnections)
		if normalized.IMAP.TLS != nil {
			s.imapTLSConf = newTLSConfig(normalized.IMAP.TLS.Certificate)
		}
	}
	if normalized.POP3 != nil {
		s.pop3Sem = make(chan struct{}, normalized.MaxConnections)
		if normalized.POP3.TLS != nil {
			s.pop3TLSConf = newTLSConfig(normalized.POP3.TLS.Certificate)
		}
	}
	return s, nil
}

// newTLSConfig 由测试证书构造 TLS 配置；最低版本固定 TLS 1.2。
func newTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}

// Start 开始监听并接受连接。配置了 IMAP/POP3 时会同时启动对应监听器；任一监听器
// 启动失败都会关闭已建立的监听器并返回错误，服务器保持未启动状态，避免半启动。
// 重复调用返回 ErrAlreadyStarted；已经 Close 过的服务器不能再启动（返回
// ErrClosed），需要新的 Server 实例。
func (s *Server) Start() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return ErrAlreadyStarted
	}
	s.mu.Unlock()

	// 先在锁外创建全部监听器：失败时逐个关闭，避免留下半启动状态。
	var listeners []net.Listener
	closeAll := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}
	open := func(addr string) (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, err
		}
		// 复核实际绑定地址：即使配置校验通过，也只允许回环地址（除非调用方
		// 显式选择 AllowNonLoopback）。这封堵空主机名等写法被 net.Listen
		// 解释为全部接口的绕过路径。
		if err := ensureLoopbackListener(ln, s.opts.AllowNonLoopback); err != nil {
			_ = ln.Close()
			return nil, err
		}
		return ln, nil
	}

	smtpLn, err := open(s.opts.Addr)
	if err != nil {
		return err
	}
	listeners = append(listeners, smtpLn)

	var imapLn, pop3Ln net.Listener
	if s.opts.IMAP != nil {
		if imapLn, err = open(s.opts.IMAP.Addr); err != nil {
			closeAll()
			return fmt.Errorf("testmail: IMAP 监听 %s 失败: %w", s.opts.IMAP.Addr, err)
		}
		listeners = append(listeners, imapLn)
	}
	if s.opts.POP3 != nil {
		if pop3Ln, err = open(s.opts.POP3.Addr); err != nil {
			closeAll()
			return fmt.Errorf("testmail: POP3 监听 %s 失败: %w", s.opts.POP3.Addr, err)
		}
		listeners = append(listeners, pop3Ln)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		closeAll()
		return ErrClosed
	}
	s.ln = smtpLn
	s.imapLn = imapLn
	s.pop3Ln = pop3Ln
	s.started = true
	s.acceptWG.Add(len(listeners))
	s.mu.Unlock()

	go s.acceptLoop(smtpLn, protocolSMTP, s.sem)
	if imapLn != nil {
		go s.acceptLoop(imapLn, protocolIMAP, s.imapSem)
	}
	if pop3Ln != nil {
		go s.acceptLoop(pop3Ln, protocolPOP3, s.pop3Sem)
	}
	return nil
}

// Addr 返回 SMTP 实际监听地址；未启动或未监听时返回 nil。监听端口为 0 时这里给出
// 操作系统分配的真实端口，测试应据此连接。
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

// IMAPAddr 返回 IMAP 实际监听地址；未配置 IMAP 或未启动时返回 nil。
func (s *Server) IMAPAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.imapLn == nil {
		return nil
	}
	return s.imapLn.Addr()
}

// POP3Addr 返回 POP3 实际监听地址；未配置 POP3 或未启动时返回 nil。
func (s *Server) POP3Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pop3Ln == nil {
		return nil
	}
	return s.pop3Ln.Addr()
}

// ensureLoopbackListener 复核监听器实际绑定地址。除调用方显式 AllowNonLoopback
// 外，只接受回环地址；否则关闭监听并返回配置错误，避免测试服务器被意外暴露。
func ensureLoopbackListener(ln net.Listener, allowNonLoopback bool) error {
	if allowNonLoopback {
		return nil
	}
	addr := ln.Addr()
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok || tcpAddr.IP == nil || !tcpAddr.IP.IsLoopback() {
		return fmt.Errorf("%w: 实际绑定地址 %s 不是回环地址", ErrInvalidOptions, addr)
	}
	return nil
}

// acceptLoop 接受连接：并发额度耗尽时按协议立即拒绝新连接，其余交给会话 goroutine。
// 每个协议监听器有独立的并发额度，互不占用。
func (s *Server) acceptLoop(ln net.Listener, kind protocol, sem chan struct{}) {
	defer s.acceptWG.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.closedCh:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			// 监听器已失效（例如被并发 Close 关闭），退出接受循环。
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			// 并发连接数已达上限：立即按协议拒绝并关闭，不做排队，
			// 避免测试时被未读取的连接拖住。
			rejectTooManyConnections(conn, kind)
			continue
		}
		if !s.track(conn) {
			<-sem
			_ = conn.Close()
			return
		}
		s.sessWG.Add(1)
		go func() {
			defer s.sessWG.Done()
			defer func() {
				s.untrack(conn)
				<-sem
				_ = conn.Close()
			}()
			s.serveConn(conn, kind)
		}()
	}
}

// rejectTooManyConnections 在并发额度耗尽时按协议发送拒绝信息并关闭连接。
// 响应文本保持 ASCII，避免严格客户端因非 ASCII 应答解析失败。
func rejectTooManyConnections(conn net.Conn, kind protocol) {
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	var msg string
	switch kind {
	case protocolIMAP:
		msg = "* BYE Too many connections, try again later\r\n"
	case protocolPOP3:
		msg = "-ERR too many connections, try again later\r\n"
	default:
		msg = "421 4.3.2 Too many connections, try again later\r\n"
	}
	_, _ = conn.Write([]byte(msg))
	_ = conn.Close()
}

// track 记录活动连接；服务已关闭时返回 false 并拒绝登记。
func (s *Server) track(conn net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

// untrack 移除活动连接记录。
func (s *Server) untrack(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, conn)
}

// Close 停止服务并释放全部监听端口。仍在会话中的连接会被强制关闭；本方法等待
// 会话 goroutine 退出，最多等待 closeTimeout，超时返回 ErrCloseTimeout。
func (s *Server) Close() error {
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.closedCh)
		listeners := []net.Listener{s.ln, s.imapLn, s.pop3Ln}
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()

		for _, ln := range listeners {
			if ln == nil {
				continue
			}
			if err := ln.Close(); err != nil && s.closeErr == nil {
				s.closeErr = err
			}
		}
		for _, c := range conns {
			_ = c.Close()
		}
		s.acceptWG.Wait()

		waited := make(chan struct{})
		go func() {
			s.sessWG.Wait()
			close(waited)
		}()
		select {
		case <-waited:
		case <-time.After(closeTimeout):
			if s.closeErr == nil {
				s.closeErr = ErrCloseTimeout
			}
		}
	})
	return s.closeErr
}

// serveConn 按监听器协议分发到对应会话实现。
func (s *Server) serveConn(conn net.Conn, kind protocol) {
	switch kind {
	case protocolIMAP:
		s.serveIMAP(conn)
	case protocolPOP3:
		s.servePOP3(conn)
	default:
		s.serveSMTP(conn)
	}
}

// wrapTLS 在已接受的连接上完成隐式 TLS 握手（IMAP/POP3）。握手失败返回错误，由
// 调用方关闭连接；握手使用读取超时作为上限，避免慢速握手长期占用连接额度。
func (s *Server) wrapTLS(conn net.Conn, conf *tls.Config) (net.Conn, error) {
	tlsConn := tls.Server(conn, conf)
	_ = tlsConn.SetDeadline(time.Now().Add(s.opts.ReadTimeout))
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// serveSMTP 处理单个 SMTP 连接。
func (s *Server) serveSMTP(conn net.Conn) {
	ss := &session{
		srv:        s,
		conn:       conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriter(conn),
		remote:     conn.RemoteAddr().String(),
		sessionID:  s.sessionSeq.Add(1),
		sessionEnd: time.Now().Add(s.opts.SessionTimeout),
	}
	ss.emit(SessionEventConnected, "", "")
	ss.greet()
	ss.loop()
	ss.emit(SessionEventClosed, "", "")
}

// Messages 返回匹配查询的消息快照（按接收顺序）。返回的消息与内部仓库共用
// Data 底层数组，调用方应视为只读。
func (s *Server) Messages(q Query) []Message {
	return s.store.query(q)
}

// MessageCount 返回当前内存中保留的消息数。
func (s *Server) MessageCount() int {
	return s.store.count()
}

// Take 取出（移除并返回）匹配查询的消息，释放的内存容量可被后续消息使用。
func (s *Server) Take(q Query) []Message {
	return s.store.take(q)
}

// Clear 清空全部消息并返回被清空的数量。
func (s *Server) Clear() int {
	return s.store.clear()
}

// Wait 阻塞直到出现至少一条满足查询的消息、ctx 结束或读取失败。
// 它适合测试在发送邮件后等待服务端完成接收，避免固定 sleep。
func (s *Server) Wait(ctx context.Context, q Query) ([]Message, error) {
	ticker := time.NewTicker(waitPollInterval)
	defer ticker.Stop()
	for {
		if msgs := s.store.query(q); len(msgs) > 0 {
			return msgs, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
