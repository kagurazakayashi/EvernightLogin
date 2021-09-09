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

// Server 是本地测试 SMTP 服务器。
//
// 生命周期：New 只校验配置，Start 才监听端口并开始接受连接；Close 停止接受新
// 连接、强制关闭仍活动的连接并等待会话退出（端口在 Listen 关闭后释放）。Close
// 是幂等的，可在 Start 之前调用。
type Server struct {
	opts    Options
	tlsConf *tls.Config
	store   *store

	mu       sync.Mutex
	ln       net.Listener
	started  bool
	closed   bool
	conns    map[net.Conn]struct{}
	sem      chan struct{}
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
		s.tlsConf = &tls.Config{
			Certificates: []tls.Certificate{normalized.TLS.Certificate},
			MinVersion:   tls.VersionTLS12,
		}
	}
	return s, nil
}

// Start 开始监听并接受连接。重复调用返回 ErrAlreadyStarted；已经 Close 过的
// 服务器不能再启动（返回 ErrClosed），需要新的 Server 实例。
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
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// 复核实际绑定地址：即使配置校验通过，也只允许回环地址（除非调用方显式
	// 选择 AllowNonLoopback）。这封堵空主机名等写法被 net.Listen 解释为全部
	// 接口的绕过路径。
	if err := ensureLoopbackListener(ln, s.opts.AllowNonLoopback); err != nil {
		_ = ln.Close()
		s.mu.Unlock()
		return err
	}
	s.ln = ln
	s.started = true
	s.acceptWG.Add(1)
	s.mu.Unlock()

	go s.acceptLoop(ln)
	return nil
}

// Addr 返回实际监听地址；未启动时返回 nil。监听端口为 0 时这里给出操作系统
// 分配的真实端口，测试应据此连接。
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
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

// acceptLoop 接受连接：并发额度耗尽时以 421 拒绝新连接，其余交给会话 goroutine。
func (s *Server) acceptLoop(ln net.Listener) {
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
		case s.sem <- struct{}{}:
		default:
			// 并发连接数已达上限：立即以 421 拒绝并关闭，不做排队，
			// 避免测试时被未读取的连接拖住。
			_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = conn.Write([]byte("421 4.3.2 Too many connections, try again later\r\n"))
			_ = conn.Close()
			continue
		}
		if !s.track(conn) {
			<-s.sem
			_ = conn.Close()
			return
		}
		s.sessWG.Add(1)
		go func() {
			defer s.sessWG.Done()
			defer func() {
				s.untrack(conn)
				<-s.sem
				_ = conn.Close()
			}()
			s.serve(conn)
		}()
	}
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

// Close 停止服务并释放端口。仍在会话中的连接会被强制关闭；本方法等待会话
// goroutine 退出，最多等待 closeTimeout，超时返回 ErrCloseTimeout。
func (s *Server) Close() error {
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.closedCh)
		ln := s.ln
		conns := make([]net.Conn, 0, len(s.conns))
		for c := range s.conns {
			conns = append(conns, c)
		}
		s.mu.Unlock()

		if ln != nil {
			if err := ln.Close(); err != nil {
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

// serve 处理单个连接。
func (s *Server) serve(conn net.Conn) {
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
