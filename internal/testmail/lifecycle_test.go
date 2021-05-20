package testmail_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/testmail"
)

// TestPortReleasedAfterClose 验证 Close 之后端口被真实释放：原地址可以重新监听，
// 旧连接被断开。
func TestPortReleasedAfterClose(t *testing.T) {
	srv, err := testmail.New(testmail.Options{})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	addr := srv.Addr().String()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if _, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
		t.Fatalf("关闭后仍能连接 %s，端口未释放", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("关闭后重新监听 %s 失败（端口未释放）: %v", addr, err)
	}
	_ = ln.Close()
}

// TestStartTwiceAndCloseTwice 验证生命周期状态机：重复 Start 报错、重复 Close 幂等。
func TestStartTwiceAndCloseTwice(t *testing.T) {
	srv, err := testmail.New(testmail.Options{})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("首次 Start 失败: %v", err)
	}
	if err := srv.Start(); !errors.Is(err, testmail.ErrAlreadyStarted) {
		t.Fatalf("重复 Start 应返回 ErrAlreadyStarted，实际 %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("首次 Close 失败: %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("重复 Close 应幂等，实际 %v", err)
	}
	if err := srv.Start(); !errors.Is(err, testmail.ErrClosed) {
		t.Fatalf("关闭后 Start 应返回 ErrClosed，实际 %v", err)
	}
}

// TestCloseBeforeStart 验证未启动即可安全关闭。
func TestCloseBeforeStart(t *testing.T) {
	srv, err := testmail.New(testmail.Options{})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if srv.Addr() != nil {
		t.Errorf("未启动时 Addr 应为 nil，实际 %v", srv.Addr())
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("未启动时 Close 应成功，实际 %v", err)
	}
}

// TestCloseDisconnectsActiveSession 验证 Close 强制断开活动连接，未完成的消息不会
// 被保存。
func TestCloseDisconnectsActiveSession(t *testing.T) {
	srv, err := testmail.New(testmail.Options{})
	if err != nil {
		t.Fatalf("New 失败: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start 失败: %v", err)
	}
	c := wrapRaw(t, dialRaw(t, srv))
	c.expect(220)
	c.expectCode(250, "EHLO client.example.test")
	c.expectCode(250, "MAIL FROM:<a@example.test>")
	c.expectCode(250, "RCPT TO:<b@example.test>")
	c.expectCode(354, "DATA")
	// 只发送部分正文，然后关闭服务器。
	if _, err := c.conn.Write([]byte("Subject: partial\r\n\r\nhalf")); err != nil {
		t.Fatalf("写入部分正文失败: %v", err)
	}
	start := time.Now()
	if err := srv.Close(); err != nil {
		t.Fatalf("Close 失败: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Close 耗时过长: %v", elapsed)
	}
	if got := srv.MessageCount(); got != 0 {
		t.Errorf("未完成的消息不应保存，实际 %d 封", got)
	}
}

// TestConcurrentQueryAndClear 验证查询/清空与收信并发执行时保持一致，不 panic。
func TestConcurrentQueryAndClear(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	c := dialServer(t, srv)
	c.expectCode(250, "EHLO client.example.test")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = srv.Messages(testmail.Query{})
				_ = srv.Messages(testmail.Query{To: "nobody@example.test"})
				_ = srv.Take(testmail.Query{Subject: "not-there"})
				_ = srv.MessageCount()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			srv.Clear()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	for i := 0; i < 20; i++ {
		c.sendMail("a@example.test", []string{"b@example.test"}, "Subject: concurrent\n\nbody")
	}
	close(stop)
	wg.Wait()

	if got, want := srv.MessageCount(), len(srv.Messages(testmail.Query{})); got != want {
		t.Fatalf("并发查询/清空后计数不一致: MessageCount=%d Messages=%d", got, want)
	}
}

// TestWaitTimeout 验证 Wait 在 ctx 结束时返回超时错误而不是一直阻塞。
func TestWaitTimeout(t *testing.T) {
	srv := startServer(t, testmail.Options{})
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if _, err := srv.Wait(ctx, testmail.Query{Subject: "never"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait 应返回 DeadlineExceeded，实际 %v", err)
	}
}
