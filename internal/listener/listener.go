// Package listener 实现独立 HTTP 监听的生命周期：在多个 IPv4/IPv6 地址与端口
// 上绑定，任一地址失败时关闭已打开的全部监听并整体回滚，关停时有期限地优雅
// 停止并释放端口。
//
// 本包不创建 Handler、不校验 Host、不解析转发头：它只负责“监听与关停”这一层
// 资源生命周期，可被根包的 Server 组件包装后交给 Instance 管理，也可由测试直接
// 使用。所有监听地址必须已经通过 internal/netpolicy 校验。
package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/netpolicy"
)

const (
	// DefaultShutdownTimeout 是优雅关闭的默认墙钟上限。
	DefaultShutdownTimeout = 10 * time.Second
	// readHeaderTimeout/readTimeout/idleTimeout 限制慢请求与空闲连接占用。
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 60 * time.Second
	idleTimeout       = 120 * time.Second
	// maxHeaderBytes 是请求头大小上限；请求体大小由 Handler 另行限制。
	maxHeaderBytes = 1 << 20
)

// ErrAlreadyStarted 表示监听器已经成功启动，不能重复启动。
var ErrAlreadyStarted = errors.New("HTTP 监听器已经启动")

// ErrClosed 表示监听器已经关闭或启动失败，不能再次启动。
var ErrClosed = errors.New("HTTP 监听器已经关闭")

// Options 是构造监听器的显式依赖。
type Options struct {
	// Addresses 是已校验的监听地址，必须非空且不重复。
	Addresses []netpolicy.ListenAddress
	// Handler 是请求处理程序；必填。
	Handler http.Handler
	// TLSConfig 非 nil 时所有监听地址提供 HTTPS（单向认证）；证书选择与重载由
	// 注入的 tls.Config.GetCertificate 负责，本包不读取证书文件。nil 表示明文
	// HTTP；非回环明文是否允许由上层 NewServer 的部署策略决定。
	TLSConfig *tls.Config
	// Logger 是运行日志器；nil 时丢弃日志。
	Logger *slog.Logger
	// ShutdownTimeout 是关停的墙钟上限；0 使用 DefaultShutdownTimeout。
	ShutdownTimeout time.Duration
}

// 监听器状态。只允许 new→running→closed 与 new→closed 两条路径。
type state int

const (
	stateNew state = iota
	stateRunning
	stateClosed
)

// Server 是一组监听地址上的 HTTP 服务。方法并发安全：Start/Close 由互斥锁串行
// 化，重复 Close 安全，重复 Start 返回 ErrAlreadyStarted。
type Server struct {
	mu      sync.Mutex
	state   state
	options Options

	httpServer *http.Server
	listeners  []net.Listener
	addrs      []net.Addr
	serveWG    sync.WaitGroup
}

// New 校验并构造监听器，但不绑定任何端口、不创建协程。地址或 Handler 非法时
// 返回错误，避免把配置错误拖到实际启动阶段才发现。
func New(options Options) (*Server, error) {
	if len(options.Addresses) == 0 {
		return nil, fmt.Errorf("至少需要一个监听地址")
	}
	if options.Handler == nil {
		return nil, fmt.Errorf("HTTP 监听器缺少处理程序")
	}
	shutdownTimeout := options.ShutdownTimeout
	if shutdownTimeout == 0 {
		shutdownTimeout = DefaultShutdownTimeout
	}
	if shutdownTimeout < 0 {
		return nil, fmt.Errorf("安全关闭超时不能为负")
	}
	seen := make(map[string]struct{}, len(options.Addresses))
	for _, address := range options.Addresses {
		key := address.Key()
		if _, duplicated := seen[key]; duplicated {
			return nil, fmt.Errorf("监听地址重复: %s", key)
		}
		seen[key] = struct{}{}
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError + 1}))
	}
	options.Logger = logger
	options.ShutdownTimeout = shutdownTimeout
	options.Addresses = append([]netpolicy.ListenAddress(nil), options.Addresses...)
	return &Server{state: stateNew, options: options}, nil
}

// Start 依次绑定全部地址并开始服务。任一地址绑定失败时关闭已经打开的全部监听
// 并返回错误（整体回滚），不留下半启动状态或占用中的端口。
func (s *Server) Start(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case stateRunning:
		return ErrAlreadyStarted
	case stateClosed:
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		s.state = stateClosed
		return fmt.Errorf("HTTP 监听启动已取消: %w", err)
	}

	listeners := make([]net.Listener, 0, len(s.options.Addresses))
	for _, address := range s.options.Addresses {
		listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address.String())
		if err != nil {
			// 整体回滚：关闭本次已经成功打开的监听，避免地址占用泄漏。
			rollbackErrs := closeListeners(listeners)
			s.state = stateClosed
			errs := []error{fmt.Errorf("无法监听 %s: %w", address.String(), err)}
			return errors.Join(append(errs, rollbackErrs...)...)
		}
		listeners = append(listeners, listener)
	}

	handler := s.options.Handler
	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(s.options.Logger.Handler(), slog.LevelWarn),
		TLSConfig:         s.options.TLSConfig,
	}
	useTLS := s.options.TLSConfig != nil
	addrCopies := make([]net.Addr, 0, len(listeners))
	for _, listener := range listeners {
		addrCopies = append(addrCopies, listener.Addr())
	}
	s.httpServer = httpServer
	s.listeners = listeners
	s.addrs = addrCopies
	for _, listener := range listeners {
		s.serveWG.Add(1)
		go func(listener net.Listener) {
			defer s.serveWG.Done()
			var serveErr error
			if useTLS {
				// ServeTLS 在 TLSConfig 未显式声明时追加 HTTP/2 到 NextProtos；
				// 证书由 TLSConfig.GetCertificate 动态选择，不在这里读证书文件。
				serveErr = httpServer.ServeTLS(listener, "", "")
			} else {
				serveErr = httpServer.Serve(listener)
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				// 监听意外结束：记录地址与固定原因码，不记录请求内容。
				s.options.Logger.Error("HTTP 监听意外结束",
					"listen_address", listener.Addr().String())
			}
		}(listener)
	}
	s.state = stateRunning
	s.options.Logger.Info("HTTP 监听已启动", "listener_count", len(listeners), "tls", useTLS)
	return nil
}

// Close 优雅关闭全部监听与连接，并等待监听协程退出。关闭受调用方 ctx 与
// ShutdownTimeout 双重期限约束：期限内未完成时强制关闭连接与监听，并如实返回
// 未完成的原因，不假装已经优雅退出。
func (s *Server) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case stateClosed:
		return nil
	case stateNew:
		s.state = stateClosed
		return nil
	}

	var errs []error
	deadline := time.Now().Add(s.options.ShutdownTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	shutdownCtx, cancel := context.WithDeadline(ctx, deadline)
	shutdownErr := s.httpServer.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		errs = append(errs, fmt.Errorf("优雅关闭 HTTP 监听未在期限内完成: %w", shutdownErr))
		if closeErr := s.httpServer.Close(); closeErr != nil {
			errs = append(errs, fmt.Errorf("强制关闭 HTTP 连接失败: %w", closeErr))
		}
	}
	// Shutdown 正常时已关闭全部监听；这里兜底关闭并忽略“已关闭”错误。
	errs = append(errs, closeListeners(s.listeners)...)

	// Serve 协程应在监听关闭后立刻返回；仍用期限保护，避免无限等待。
	done := make(chan struct{})
	go func() {
		s.serveWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(s.options.ShutdownTimeout):
		errs = append(errs, fmt.Errorf("HTTP 监听协程未在 %s 内退出", s.options.ShutdownTimeout))
	}

	s.httpServer = nil
	s.listeners = nil
	s.addrs = nil
	s.state = stateClosed
	return errors.Join(errs...)
}

// Addrs 返回实际绑定的地址（含系统分配的端口）。必须在 Start 成功后调用；未
// 启动时返回 nil。返回的是副本，调用方修改不影响监听器。
func (s *Server) Addrs() []net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.addrs) == 0 {
		return nil
	}
	addrs := make([]net.Addr, len(s.addrs))
	copy(addrs, s.addrs)
	return addrs
}

// closeListeners 关闭监听列表并聚合非“已关闭”错误。
func closeListeners(listeners []net.Listener) []error {
	var errs []error
	for _, listener := range listeners {
		if listener == nil {
			continue
		}
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("关闭监听失败: %w", err))
		}
	}
	return errs
}
