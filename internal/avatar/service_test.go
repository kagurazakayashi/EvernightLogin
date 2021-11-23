package avatar_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/audit"
	auditsqlite "github.com/kagurazakayashi/EvernightLogin/internal/audit/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/avatar"
	avatarsqlite "github.com/kagurazakayashi/EvernightLogin/internal/avatar/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/storage/migrate"
	storagesqlite "github.com/kagurazakayashi/EvernightLogin/internal/storage/sqlite"
	"github.com/kagurazakayashi/EvernightLogin/internal/testutil"
	"github.com/kagurazakayashi/EvernightLogin/migrations"
)

// testStart 是固定的历史时间，仅用于确定性种子数据与审计事件时间。GC 安全窗口
// 相关断言必须基于真实时钟推进（setClockPastGCWindow），不得依赖任何固定的未来
// 时间戳，否则测试会在真实时间追上该时间戳后失效。
var testStart = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

type testEnv struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	storage *storagesqlite.Store
	files   *avatar.LocalStorage
	service *avatar.Service
	audit   *audit.Recorder
	options avatar.Options
	now     time.Time
}

// setClockPastGCWindow 把服务时钟设为“真实当前时间 + GC 安全窗口 + 1 分钟”，
// 确定性地让已写入文件越过安全窗口，而不依赖固定的未来时间戳。
func (e *testEnv) setClockPastGCWindow() {
	e.now = time.Now().Add(avatar.DefaultGCSafetyWindow + time.Minute)
}

// newTestEnv 构造临时 SQLite、临时头像目录与真实审计写入器；网络策略默认使用
// 测试专用回环开关，使网络头像测试只访问本机 httptest 服务。
func newTestEnv(t *testing.T, mutate func(*avatar.Options)) *testEnv {
	t.Helper()
	ctx := context.Background()
	dir := testutil.TempDir(t)
	path := filepath.Join(testutil.TempDir(t), "avatar-test.db")
	storage, err := storagesqlite.Open(ctx, storagesqlite.DefaultOptions(path))
	if err != nil {
		t.Fatalf("打开数据库: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	migrationList, err := migrate.LoadMigrations(migrations.SQLite)
	if err != nil {
		t.Fatalf("加载迁移: %v", err)
	}
	if _, err := storage.Migrate(ctx, migrationList); err != nil {
		t.Fatalf("执行迁移: %v", err)
	}
	auditStore, err := auditsqlite.New(storage)
	if err != nil {
		t.Fatalf("审计存储: %v", err)
	}
	recorder, err := audit.New(auditStore, audit.Options{Now: func() time.Time { return testStart }})
	if err != nil {
		t.Fatalf("审计: %v", err)
	}
	recordStore, err := avatarsqlite.New(storage)
	if err != nil {
		t.Fatalf("头像记录存储: %v", err)
	}
	files, err := avatar.NewLocalStorage(filepath.Join(dir, "avatars"))
	if err != nil {
		t.Fatalf("头像文件存储: %v", err)
	}
	// 服务时钟默认使用真实当前时间；需要越过 GC 安全窗口的用例显式调用
	// setClockPastGCWindow 推进，避免任何固定未来时间戳依赖。
	env := &testEnv{t: t, ctx: ctx, dir: dir, storage: storage, files: files,
		audit: recorder, now: time.Now().UTC()}
	options := avatar.Options{
		Store:   recordStore,
		Storage: files,
		Audit:   recorder,
		Network: avatar.NetworkPolicy{TestOnlyAllowLocalAddresses: true},
		Now:     func() time.Time { return env.now },
		Logger:  slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
	if mutate != nil {
		mutate(&options)
	}
	service, err := avatar.New(options)
	if err != nil {
		t.Fatalf("头像服务: %v", err)
	}
	env.options = options
	env.service = service
	return env
}

// seedUser 插入合成用户并返回稳定 ID。
func (e *testEnv) seedUser(id, username string) {
	e.t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,?,'','',NULL,'zh-CN','Asia/Shanghai','active',0,1,1,?,?)`,
		id, username, username, now, now); err != nil {
		e.t.Fatalf("用户: %v", err)
	}
}

// seedRoot 插入唯一 root 合成账户（is_root=1），用于验证授权器收到的 root 快照。
func (e *testEnv) seedRoot(id string) {
	e.t.Helper()
	now := testStart.UnixMilli()
	if _, err := e.storage.DB().ExecContext(e.ctx, `INSERT INTO users(
id,username,username_normalized,nickname,biography,avatar_ref,language,timezone,status,is_root,
security_version,row_version,created_at_ms,updated_at_ms
) VALUES(?,?,'','','',NULL,'zh-CN','Asia/Shanghai','active',1,1,1,?,?)`,
		id, "root", now, now); err != nil {
		e.t.Fatalf("root 用户: %v", err)
	}
}

func (e *testEnv) userCaller(id string) avatar.Caller {
	e.t.Helper()
	caller, err := avatar.UserCaller(id)
	if err != nil {
		e.t.Fatalf("用户调用者: %v", err)
	}
	return caller
}
func (e *testEnv) systemCaller(id string) avatar.Caller {
	e.t.Helper()
	caller, err := avatar.SystemCaller(id)
	if err != nil {
		e.t.Fatalf("系统调用者: %v", err)
	}
	return caller
}

func (e *testEnv) scalar(query string, args ...any) string {
	e.t.Helper()
	var value string
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("查询 %q: %v", query, err)
	}
	return value
}

func (e *testEnv) count(query string, args ...any) int {
	e.t.Helper()
	var value int
	if err := e.storage.DB().QueryRowContext(e.ctx, query, args...).Scan(&value); err != nil {
		e.t.Fatalf("计数: %v", err)
	}
	return value
}

// storedFiles 返回头像目录下所有普通文件（相对目录）。
func (e *testEnv) storedFiles() []string {
	e.t.Helper()
	root := filepath.Join(e.dir, "avatars")
	keys := make([]string, 0, 4)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		keys = append(keys, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		e.t.Fatalf("遍历头像目录: %v", err)
	}
	return keys
}

func (e *testEnv) successEvents(action string) int {
	e.t.Helper()
	return e.count(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome='success'`, action)
}

func (e *testEnv) failureEvents(action string) int {
	e.t.Helper()
	return e.count(`SELECT COUNT(*) FROM audit_events WHERE action=? AND outcome<>'success'`, action)
}

// auditDetail 返回匹配动作的所有审计详情 JSON 拼接，用于断言不泄露路径/URL。
func (e *testEnv) auditDetail(action string) string {
	e.t.Helper()
	rows, err := e.storage.DB().QueryContext(e.ctx, `SELECT detail_json FROM audit_events WHERE action=?`, action)
	if err != nil {
		e.t.Fatalf("查询审计详情: %v", err)
	}
	defer rows.Close()
	var builder strings.Builder
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			e.t.Fatalf("扫描审计详情: %v", err)
		}
		builder.WriteString(detail)
	}
	return builder.String()
}

// makePNG 生成确定性的合成 PNG。
func makePNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x), G: uint8(y), B: 120, A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := png.Encode(&buffer, img); err != nil {
		t.Fatalf("编码 PNG: %v", err)
	}
	return buffer.Bytes()
}

// makeJPEG 生成确定性的合成 JPEG。
func makeJPEG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 3), G: uint8(y * 2), B: 40, A: 255})
		}
	}
	var buffer bytes.Buffer
	if err := jpeg.Encode(&buffer, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatalf("编码 JPEG: %v", err)
	}
	return buffer.Bytes()
}

// makeGIF 生成单帧合成 GIF。
func makeGIF(t *testing.T, width, height int) []byte {
	t.Helper()
	palette := color.Palette{color.RGBA{0, 0, 0, 255}, color.RGBA{255, 255, 255, 255}}
	img := image.NewPaletted(image.Rect(0, 0, width, height), palette)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			if (x+y)%2 == 0 {
				img.SetColorIndex(x, y, 1)
			}
		}
	}
	var buffer bytes.Buffer
	if err := gif.Encode(&buffer, img, nil); err != nil {
		t.Fatalf("编码 GIF: %v", err)
	}
	return buffer.Bytes()
}

// TestUploadReplaceReadRemove 覆盖正常上传、读取、替换（旧文件清理）与清除。
func TestUploadReplaceReadRemove(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000001"
	env.seedUser(userID, "alice")
	caller := env.userCaller(userID)

	uploaded, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makePNG(t, 64, 48), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-avatar-1",
	})
	if err != nil {
		t.Fatalf("上传头像: %v", err)
	}
	if uploaded.MediaType != avatar.MediaTypePNG || uploaded.Width != 64 || uploaded.Height != 48 {
		t.Fatalf("头像元数据异常: %+v", uploaded)
	}
	if len(uploaded.SHA256) != 64 {
		t.Errorf("内容摘要长度 = %d，期望 64 个十六进制字符", len(uploaded.SHA256))
	}
	if uploaded.RowVersion != 2 {
		t.Errorf("行版本 = %d，期望 2", uploaded.RowVersion)
	}
	if ref := env.scalar(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, userID); ref != uploaded.ID {
		t.Errorf("users.avatar_ref = %q，期望 %q", ref, uploaded.ID)
	}
	if rows := env.count(`SELECT COUNT(*) FROM avatars WHERE user_id=?`, userID); rows != 1 {
		t.Errorf("头像行数 = %d，期望 1", rows)
	}
	files := env.storedFiles()
	if len(files) != 1 {
		t.Fatalf("头像文件数 = %d，期望 1", len(files))
	}
	// 文件名必须由服务端生成：不含用户 ID、原始扩展名逻辑与上传内容。
	if strings.Contains(files[0], userID) || strings.Contains(files[0], "alice") {
		t.Errorf("存储文件名泄露用户信息: %q", files[0])
	}
	if events := env.successEvents("avatar.upload"); events != 1 {
		t.Errorf("上传成功审计数 = %d，期望 1", events)
	}

	content, err := env.service.Read(env.ctx, caller, userID)
	if err != nil {
		t.Fatalf("读取头像: %v", err)
	}
	if content.Avatar.ID != uploaded.ID || len(content.Data) == 0 {
		t.Fatalf("读取内容异常: %+v", content.Avatar)
	}
	header := http.Header{}
	content.SetResponseHeaders(header)
	wantHeaders := map[string]string{
		"Content-Type":           avatar.MediaTypePNG,
		"X-Content-Type-Options": "nosniff",
		"Cache-Control":          "private, max-age=300",
		"Content-Disposition":    `inline; filename="avatar.png"`,
		"ETag":                   `"` + uploaded.SHA256 + `"`,
		"Content-Length":         fmt.Sprint(len(content.Data)),
	}
	for name, want := range wantHeaders {
		if got := header.Get(name); got != want {
			t.Errorf("响应头 %s = %q，期望 %q", name, got, want)
		}
	}
	for name, values := range header {
		joined := strings.Join(values, " ")
		if strings.Contains(joined, env.dir) || strings.Contains(joined, "storage_key") ||
			strings.Contains(joined, filepath.ToSlash(env.dir)) {
			t.Errorf("响应头 %s 泄露本机路径或存储键: %q", name, joined)
		}
	}

	replaced, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makeJPEG(t, 100, 80), ExpectedRowVersion: 2, RequestID: "req-avatar-2",
	})
	if err != nil {
		t.Fatalf("替换头像: %v", err)
	}
	if replaced.MediaType != avatar.MediaTypeJPEG || replaced.ID == uploaded.ID {
		t.Fatalf("替换结果异常: %+v", replaced)
	}
	if replaced.RowVersion != 3 {
		t.Errorf("替换后行版本 = %d，期望 3", replaced.RowVersion)
	}
	if files := env.storedFiles(); len(files) != 1 {
		t.Errorf("替换后头像文件数 = %d，期望 1（旧文件应被清理）", len(files))
	}
	if rows := env.count(`SELECT COUNT(*) FROM avatars`); rows != 1 {
		t.Errorf("替换后头像行数 = %d，期望 1", rows)
	}
	replacedContent, err := env.service.Read(env.ctx, caller, userID)
	if err != nil {
		t.Fatalf("读取替换后的头像: %v", err)
	}
	if replacedContent.Avatar.MediaType != avatar.MediaTypeJPEG {
		t.Errorf("替换后媒体类型 = %q，期望 JPEG", replacedContent.Avatar.MediaType)
	}

	if err := env.service.Remove(env.ctx, caller, avatar.RemoveRequest{
		ExpectedRowVersion: 3, RequestID: "req-avatar-3",
	}); err != nil {
		t.Fatalf("清除头像: %v", err)
	}
	if ref := env.scalar(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, userID); ref != "" {
		t.Errorf("清除后 avatar_ref = %q，期望空", ref)
	}
	if rows := env.count(`SELECT COUNT(*) FROM avatars`); rows != 0 {
		t.Errorf("清除后头像行数 = %d，期望 0", rows)
	}
	if files := env.storedFiles(); len(files) != 0 {
		t.Errorf("清除后头像文件数 = %d，期望 0", len(files))
	}
	if events := env.successEvents("avatar.remove"); events != 1 {
		t.Errorf("清除成功审计数 = %d，期望 1", events)
	}
	if _, found, err := env.service.Current(env.ctx, caller, userID); err != nil || found {
		t.Errorf("清除后 Current = (found=%v, err=%v)，期望未设置", found, err)
	}
	if _, err := env.service.Read(env.ctx, caller, userID); !errors.Is(err, avatar.ErrInvalidRequest) {
		t.Errorf("无头像读取错误 = %v，期望 ErrInvalidRequest", err)
	}
}

// TestRejectInvalidAndActiveContent 覆盖错误格式、SVG、类型伪装、超大/解压膨胀与
// GIF 重编码；失败不得留下文件、记录或引用。
func TestRejectInvalidAndActiveContent(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000002"
	env.seedUser(userID, "bob")
	caller := env.userCaller(userID)
	validPNG := makePNG(t, 32, 32)
	svgContent := []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><script>alert(1)</script></svg>`)
	hugeDims := makePNG(t, 2000, 2000)
	oversized := make([]byte, avatar.MaxUploadBytes+1)

	cases := []struct {
		name     string
		data     []byte
		declared string
		want     error
	}{
		{name: "随机字节伪装PNG", data: bytes.Repeat([]byte{0x89, 0x50, 0x4e, 0x47}, 64), declared: avatar.MediaTypePNG, want: avatar.ErrUnsupportedMedia},
		{name: "SVG声明", data: svgContent, declared: "image/svg+xml", want: avatar.ErrSVGNotAllowed},
		{name: "SVG伪装PNG", data: svgContent, declared: avatar.MediaTypePNG, want: avatar.ErrUnsupportedMedia},
		{name: "PNG声明为SVG", data: validPNG, declared: "image/svg+xml", want: avatar.ErrSVGNotAllowed},
		{name: "PNG声明为JPEG", data: validPNG, declared: avatar.MediaTypeJPEG, want: avatar.ErrContentTypeMismatch},
		{name: "HTML声明", data: []byte("<html><body>hi</body></html>"), declared: "text/html", want: avatar.ErrUnsupportedMedia},
		{name: "字节超限", data: oversized, declared: avatar.MediaTypePNG, want: avatar.ErrImageTooLarge},
		{name: "解压膨胀大尺寸", data: hugeDims, declared: avatar.MediaTypePNG, want: avatar.ErrImageTooLarge},
		{name: "尺寸过小", data: makePNG(t, 4, 4), declared: avatar.MediaTypePNG, want: avatar.ErrInvalidImage},
		{name: "空内容", data: nil, declared: avatar.MediaTypePNG, want: avatar.ErrInvalidImage},
		{name: "截断PNG", data: validPNG[:len(validPNG)/2], declared: avatar.MediaTypePNG, want: avatar.ErrInvalidImage},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
				Data: test.data, DeclaredMediaType: test.declared,
				ExpectedRowVersion: 1, RequestID: "req-invalid",
			}); !errors.Is(err, test.want) {
				t.Fatalf("上传错误 = %v，期望 %v", err, test.want)
			}
		})
	}
	if files := env.storedFiles(); len(files) != 0 {
		t.Errorf("失败上传后头像文件数 = %d，期望 0", len(files))
	}
	if rows := env.count(`SELECT COUNT(*) FROM avatars`); rows != 0 {
		t.Errorf("失败上传后头像行数 = %d，期望 0", rows)
	}
	if ref := env.scalar(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, userID); ref != "" {
		t.Errorf("失败上传后 avatar_ref = %q，期望空", ref)
	}

	// GIF 允许输入但重编码为静态 PNG，不保留动画/扩展块。
	gifAvatar, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makeGIF(t, 48, 32), DeclaredMediaType: avatar.MediaTypeGIF,
		ExpectedRowVersion: 1, RequestID: "req-gif",
	})
	if err != nil {
		t.Fatalf("上传 GIF: %v", err)
	}
	if gifAvatar.MediaType != avatar.MediaTypePNG {
		t.Errorf("GIF 重编码媒体类型 = %q，期望 image/png", gifAvatar.MediaType)
	}
	if gifAvatar.Width != 48 || gifAvatar.Height != 32 {
		t.Errorf("GIF 尺寸 = %dx%d，期望 48x32", gifAvatar.Width, gifAvatar.Height)
	}
	processed, err := avatar.ProcessImage(makeGIF(t, 16, 16), "")
	if err != nil {
		t.Fatalf("直接处理 GIF: %v", err)
	}
	if processed.InputFormat() != "gif" || processed.MediaType != avatar.MediaTypePNG {
		t.Errorf("GIF 处理结果 = 输入 %q / 输出 %q", processed.InputFormat(), processed.MediaType)
	}
}

// TestStoragePathAndKeySafety 覆盖存储键格式、路径穿越与非法路径拒绝。
func TestStoragePathAndKeySafety(t *testing.T) {
	dir := testutil.TempDir(t)
	files, err := avatar.NewLocalStorage(dir)
	if err != nil {
		t.Fatalf("构造存储: %v", err)
	}
	ctx := context.Background()
	key, err := files.Save(ctx, makePNG(t, 16, 16), "png")
	if err != nil {
		t.Fatalf("保存文件: %v", err)
	}
	if !strings.HasPrefix(key, key[:2]+"/") || !strings.HasSuffix(key, ".png") || len(key) != 39 {
		t.Errorf("存储键格式 = %q", key)
	}
	data, err := files.Open(ctx, key)
	if err != nil {
		t.Fatalf("读取存储键: %v", err)
	}
	if len(data) == 0 {
		t.Error("读取内容为空")
	}
	if second, err := files.Save(ctx, makePNG(t, 16, 16), "png"); err != nil || second == key {
		t.Errorf("第二次保存键 = %q, err = %v，期望唯一键", second, err)
	}
	for _, badKey := range []string{
		"", "../evil.png", "ab/../../evil.png", "/etc/passwd", "C:/windows/win.ini",
		"AB/0123456789abcdef0123456789abcdef.png", "ab/short.png",
		"ab/0123456789abcdef0123456789abcdef.svg",
		"ab/0123456789abcdef0123456789abcdef.png/../../x.png",
	} {
		if _, err := files.Open(ctx, badKey); err == nil {
			t.Errorf("非法存储键 %q 未被拒绝", badKey)
		}
	}
	// 目录外文件不能通过受控键访问。
	if err := os.WriteFile(filepath.Join(filepath.Dir(dir), "outside.png"), []byte("x"), 0o600); err != nil {
		t.Fatalf("写入目录外文件: %v", err)
	}
	if _, err := files.Open(ctx, "../outside.png"); err == nil {
		t.Error("目录外文件通过路径穿越被读取")
	}
	// 目录不可用：路径是普通文件、目录为空、符号链接目录。
	if _, err := avatar.NewLocalStorage(""); !errors.Is(err, avatar.ErrOptionsInvalid) {
		t.Errorf("空目录错误 = %v，期望 ErrOptionsInvalid", err)
	}
	filePath := filepath.Join(testutil.TempDir(t), "not-a-dir")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatalf("写入普通文件: %v", err)
	}
	if _, err := avatar.NewLocalStorage(filePath); !errors.Is(err, avatar.ErrOptionsInvalid) {
		t.Errorf("普通文件目录错误 = %v，期望 ErrOptionsInvalid", err)
	}
	if _, err := files.Save(ctx, []byte("data"), "svg"); !errors.Is(err, avatar.ErrOptionsInvalid) {
		t.Errorf("非法扩展名错误 = %v，期望 ErrOptionsInvalid", err)
	}
	// 存储目录内的符号链接不能被 Open 跟随读取（Windows 无权限创建时跳过）。
	outside := filepath.Join(testutil.TempDir(t), "outside-target.png")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("写入链接目标: %v", err)
	}
	shardDir := filepath.Join(dir, "ab")
	if err := os.MkdirAll(shardDir, 0o700); err != nil {
		t.Fatalf("创建分片目录: %v", err)
	}
	linkKey := "ab/" + strings.Repeat("2", 32) + ".png"
	linkPath := filepath.Join(shardDir, strings.Repeat("2", 32)+".png")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Logf("当前环境无法创建符号链接，跳过链接跟随用例: %v", err)
	} else {
		if _, err := files.Open(ctx, linkKey); !errors.Is(err, avatar.ErrStorageCorrupt) {
			t.Errorf("符号链接读取错误 = %v，期望 ErrStorageCorrupt（不跟随链接）", err)
		}
		list, err := files.ListFiles(ctx)
		if err != nil {
			t.Fatalf("列出文件: %v", err)
		}
		for _, entry := range list {
			if entry.Key == linkKey {
				t.Errorf("ListFiles 不应返回符号链接 %q", linkKey)
			}
		}
	}
}

// TestAuthorizationAndTenantIsolation 覆盖越权读写、跨用户与非公网以外信息泄露。
func TestAuthorizationAndTenantIsolation(t *testing.T) {
	env := newTestEnv(t, nil)
	const aliceID = "usr_00000000000000000000000000000003"
	const bobID = "usr_00000000000000000000000000000004"
	const missingID = "usr_00000000000000000000000000000005"
	env.seedUser(aliceID, "alice2")
	env.seedUser(bobID, "bob2")
	alice := env.userCaller(aliceID)
	bob := env.userCaller(bobID)
	if _, err := env.service.Upload(env.ctx, alice, avatar.UploadRequest{
		Data: makePNG(t, 20, 20), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-auth-1",
	}); err != nil {
		t.Fatalf("本人上传: %v", err)
	}
	if _, err := env.service.Read(env.ctx, bob, aliceID); !errors.Is(err, avatar.ErrAccessDenied) {
		t.Errorf("他人读取错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, err := env.service.Upload(env.ctx, bob, avatar.UploadRequest{
		TargetUserID: aliceID, Data: makePNG(t, 20, 20),
		ExpectedRowVersion: 2, RequestID: "req-auth-2",
	}); !errors.Is(err, avatar.ErrAccessDenied) {
		t.Errorf("他人写入错误 = %v，期望 ErrAccessDenied", err)
	}
	if _, _, err := env.service.Current(env.ctx, bob, missingID); !errors.Is(err, avatar.ErrAccessDenied) {
		t.Errorf("越权读取不存在用户错误 = %v，期望 ErrAccessDenied（不泄露存在性）", err)
	}
	if _, _, err := env.service.Current(env.ctx, bob, "bad-id"); !errors.Is(err, avatar.ErrInvalidRequest) {
		t.Errorf("非法目标 ID 错误 = %v，期望 ErrInvalidRequest", err)
	}
	if _, _, err := env.service.Current(env.ctx, env.systemCaller("svc"), ""); !errors.Is(err, avatar.ErrInvalidRequest) {
		t.Errorf("系统调用者空目标错误 = %v，期望 ErrInvalidRequest", err)
	}
	// 受信系统通道可代管指定用户。
	if _, err := env.service.Upload(env.ctx, env.systemCaller("svc"), avatar.UploadRequest{
		TargetUserID: bobID, Data: makePNG(t, 24, 24), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-auth-3",
	}); err != nil {
		t.Errorf("系统代管上传: %v", err)
	}
	// root 目标与 Authorizer 决策：注入的授权器会收到 IsRoot 快照并拒绝 root 头像修改。
	const rootID = "usr_00000000000000000000000000000006"
	var rootMu sync.Mutex
	rootCalls := 0
	sawRootSnapshot := false
	authorizerEnv := newTestEnv(t, func(options *avatar.Options) {
		options.Authorizer = avatar.AuthorizerFunc(func(ctx context.Context, caller avatar.Caller, target avatar.Target, write bool) error {
			if target.UserID != rootID {
				return nil
			}
			rootMu.Lock()
			defer rootMu.Unlock()
			rootCalls++
			if target.IsRoot {
				sawRootSnapshot = true
				return avatar.ErrAccessDenied
			}
			return nil
		})
	})
	authorizerEnv.seedUser(aliceID, "alice3")
	authorizerEnv.seedUser(bobID, "bob3")
	authorizerEnv.seedRoot(rootID)
	if _, err := authorizerEnv.service.Upload(authorizerEnv.ctx, authorizerEnv.userCaller(aliceID), avatar.UploadRequest{
		Data: makePNG(t, 20, 20), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-auth-4",
	}); err != nil {
		t.Fatalf("授权器环境上传: %v", err)
	}
	if _, _, err := authorizerEnv.service.Current(authorizerEnv.ctx, authorizerEnv.userCaller(bobID), aliceID); err != nil {
		t.Errorf("注入授权器后跨用户读取: %v", err)
	}
	if _, err := authorizerEnv.service.Upload(authorizerEnv.ctx, authorizerEnv.systemCaller("svc"), avatar.UploadRequest{
		TargetUserID: rootID, Data: makePNG(t, 20, 20), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-auth-5",
	}); !errors.Is(err, avatar.ErrAccessDenied) {
		t.Errorf("授权器拒绝 root 目标错误 = %v，期望 ErrAccessDenied", err)
	}
	rootMu.Lock()
	if !sawRootSnapshot || rootCalls < 2 {
		t.Errorf("Authorizer 未收到读取后的 root 快照（调用 %d 次，root 快照 %v）", rootCalls, sawRootSnapshot)
	}
	rootMu.Unlock()
}

// failingSaveStorage 让 Save 失败，用于验证文件存储故障不改变数据库状态。
type failingSaveStorage struct {
	avatar.Storage
}

func (f failingSaveStorage) Save(ctx context.Context, data []byte, extension string) (string, error) {
	return "", fmt.Errorf("%w: 测试注入", avatar.ErrStorageUnavailable)
}

// failingReplaceStore 让事务内替换失败，用于验证新文件补偿删除。
type failingReplaceStore struct {
	avatar.Store
}

func (f failingReplaceStore) ReplaceTx(ctx context.Context, tx audit.Tx, record avatar.ReplaceRecord) (avatar.AvatarRecord, bool, error) {
	return avatar.AvatarRecord{}, false, fmt.Errorf("%w: 测试注入", avatar.ErrStoreUnavailable)
}

// failingAudit 让关键审计写入失败。
type failingAudit struct {
	avatar.AuditRecorder
}

func (f failingAudit) ExecuteCritical(ctx context.Context, request audit.CriticalRequest, change audit.Change) error {
	return fmt.Errorf("%w: 测试注入", audit.ErrAuditUnavailable)
}

// flakyRemoveStorage 在指定期间让 Remove 失败，用于验证旧文件清理失败的补偿。
type flakyRemoveStorage struct {
	avatar.Storage
	mu   sync.Mutex
	fail bool
}

func (f *flakyRemoveStorage) lock()   { f.mu.Lock() }
func (f *flakyRemoveStorage) unlock() { f.mu.Unlock() }

func (f *flakyRemoveStorage) Remove(ctx context.Context, key string) error {
	f.mu.Lock()
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return fmt.Errorf("%w: 测试注入", avatar.ErrStorageUnavailable)
	}
	return f.Storage.Remove(ctx, key)
}

// TestFailureCompensationAndVersionConflict 覆盖存储失败、事务失败、审计失败与版本冲突。
func TestFailureCompensationAndVersionConflict(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000007"
	env.seedUser(userID, "carol")
	caller := env.userCaller(userID)

	if _, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 99, RequestID: "req-conflict",
	}); !errors.Is(err, avatar.ErrVersionConflict) {
		t.Fatalf("错误版本上传 = %v，期望 ErrVersionConflict", err)
	}
	if files := env.storedFiles(); len(files) != 0 {
		t.Errorf("版本冲突后文件数 = %d，期望 0", len(files))
	}

	// 文件存储失败：数据库不变。
	failingFileEnv := newTestEnv(t, func(options *avatar.Options) {
		options.Storage = failingSaveStorage{Storage: options.Storage}
	})
	failingFileEnv.seedUser(userID, "carol")
	if _, err := failingFileEnv.service.Upload(failingFileEnv.ctx, failingFileEnv.userCaller(userID), avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-storage-fail",
	}); !errors.Is(err, avatar.ErrStorageUnavailable) {
		t.Fatalf("文件存储失败上传 = %v，期望 ErrStorageUnavailable", err)
	}
	if ref := failingFileEnv.scalar(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, userID); ref != "" {
		t.Errorf("文件存储失败后 avatar_ref = %q，期望空", ref)
	}

	// 事务替换失败：刚写入的新文件被补偿删除。
	failingStoreEnv := newTestEnv(t, func(options *avatar.Options) {
		options.Store = failingReplaceStore{Store: options.Store}
	})
	failingStoreEnv.seedUser(userID, "carol")
	if _, err := failingStoreEnv.service.Upload(failingStoreEnv.ctx, failingStoreEnv.userCaller(userID), avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-store-fail",
	}); !errors.Is(err, avatar.ErrStoreUnavailable) {
		t.Fatalf("事务失败上传 = %v，期望 ErrStoreUnavailable", err)
	}
	if files := failingStoreEnv.storedFiles(); len(files) != 0 {
		t.Errorf("事务失败后文件数 = %d，期望 0（补偿删除）", len(files))
	}

	// 审计失败必须 fail-closed 且补偿删除新文件。
	failingAuditEnv := newTestEnv(t, func(options *avatar.Options) {
		options.Audit = failingAudit{AuditRecorder: options.Audit}
	})
	failingAuditEnv.seedUser(userID, "carol")
	if _, err := failingAuditEnv.service.Upload(failingAuditEnv.ctx, failingAuditEnv.userCaller(userID), avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-audit-fail",
	}); !errors.Is(err, avatar.ErrAuditUnavailable) {
		t.Fatalf("审计失败上传 = %v，期望 ErrAuditUnavailable", err)
	}
	if files := failingAuditEnv.storedFiles(); len(files) != 0 {
		t.Errorf("审计失败后文件数 = %d，期望 0（补偿删除）", len(files))
	}
	if ref := failingAuditEnv.scalar(`SELECT COALESCE(avatar_ref,'') FROM users WHERE id=?`, userID); ref != "" {
		t.Errorf("审计失败后 avatar_ref = %q，期望空", ref)
	}
}

// TestOldFileCleanupCompensation 覆盖替换时旧文件删除失败，之后由 CollectGarbage 清理。
func TestOldFileCleanupCompensation(t *testing.T) {
	flaky := &flakyRemoveStorage{}
	env := newTestEnv(t, func(options *avatar.Options) {
		flaky.Storage = options.Storage
		options.Storage = flaky
	})
	const userID = "usr_00000000000000000000000000000008"
	env.seedUser(userID, "dave")
	caller := env.userCaller(userID)
	if _, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-gc-1",
	}); err != nil {
		t.Fatalf("首次上传: %v", err)
	}
	flaky.lock()
	flaky.fail = true
	flaky.unlock()
	if _, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makeJPEG(t, 40, 40), ExpectedRowVersion: 2, RequestID: "req-gc-2",
	}); err != nil {
		t.Fatalf("旧文件删除失败不应导致替换失败: %v", err)
	}
	if files := env.storedFiles(); len(files) != 2 {
		t.Fatalf("旧文件删除失败后文件数 = %d，期望 2（等待 GC）", len(files))
	}
	// 基于真实时钟把服务时钟推进到安全窗口之后，孤儿文件才允许被清理。
	env.setClockPastGCWindow()
	if _, err := env.service.CollectGarbage(env.ctx); !errors.Is(err, avatar.ErrStorageUnavailable) {
		t.Fatalf("删除失败时 GC 错误 = %v，期望 ErrStorageUnavailable", err)
	}
	flaky.lock()
	flaky.fail = false
	flaky.unlock()
	removed, err := env.service.CollectGarbage(env.ctx)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if removed != 1 {
		t.Errorf("GC 删除数 = %d，期望 1", removed)
	}
	if files := env.storedFiles(); len(files) != 1 {
		t.Errorf("GC 后文件数 = %d，期望 1", len(files))
	}
	if _, err := env.service.Read(env.ctx, caller, userID); err != nil {
		t.Errorf("GC 后读取当前头像: %v", err)
	}
	// GC 不触碰目录内非受控文件。
	foreign := filepath.Join(env.dir, "avatars", "keep.txt")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatalf("写入非受控文件: %v", err)
	}
	if _, err := env.service.CollectGarbage(env.ctx); err != nil {
		t.Fatalf("二次 GC: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("GC 误删非受控文件: %v", err)
	}
}

// TestTamperedFileFailsClosed 覆盖文件被替换/篡改时读取 fail-closed。
func TestTamperedFileFailsClosed(t *testing.T) {
	env := newTestEnv(t, nil)
	const userID = "usr_00000000000000000000000000000009"
	env.seedUser(userID, "erin")
	caller := env.userCaller(userID)
	if _, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-tamper",
	}); err != nil {
		t.Fatalf("上传: %v", err)
	}
	files := env.storedFiles()
	if len(files) != 1 {
		t.Fatalf("文件数 = %d", len(files))
	}
	tampered := filepath.Join(env.dir, "avatars", filepath.FromSlash(files[0]))
	if err := os.WriteFile(tampered, []byte("tampered"), 0o600); err != nil {
		t.Fatalf("篡改文件: %v", err)
	}
	if _, err := env.service.Read(env.ctx, caller, userID); !errors.Is(err, avatar.ErrStorageCorrupt) {
		t.Errorf("篡改后读取错误 = %v，期望 ErrStorageCorrupt", err)
	}
}

// TestGarbageCollectSafetyWindow 覆盖 GC 安全窗口：新写入但数据库引用尚未提交的文件
// 不会被当作孤儿删除，窗口过期后才清理；配置非法窗口被拒绝。
func TestGarbageCollectSafetyWindow(t *testing.T) {
	env := newTestEnv(t, nil)
	// 默认服务时钟必须来自真实当前时间（允许少量调度延迟），不允许固定未来时间戳。
	if age := time.Since(env.now); age < -time.Minute || age > time.Minute {
		t.Fatalf("测试环境服务时钟与真实时间相差 %s，GC 安全窗口用例不应依赖超前时钟", age)
	}
	const userID = "usr_00000000000000000000000000000014"
	env.seedUser(userID, "henry")
	caller := env.userCaller(userID)
	if _, err := env.service.Upload(env.ctx, caller, avatar.UploadRequest{
		Data: makePNG(t, 32, 32), DeclaredMediaType: avatar.MediaTypePNG,
		ExpectedRowVersion: 1, RequestID: "req-gc-window-1",
	}); err != nil {
		t.Fatalf("上传: %v", err)
	}
	// 以真实当前时间为 GC 参考（文件 mtime 由文件系统真实时钟产生）：模拟
	// “新文件已落盘、引用事务尚未提交”的窗口，不依赖任何固定未来时间戳。
	env.now = time.Now().UTC()
	if _, err := env.files.Save(env.ctx, makePNG(t, 16, 16), "png"); err != nil {
		t.Fatalf("写入模拟在途文件: %v", err)
	}
	removed, err := env.service.CollectGarbage(env.ctx)
	if err != nil {
		t.Fatalf("窗口内 GC: %v", err)
	}
	if removed != 0 {
		t.Errorf("窗口内 GC 删除数 = %d，期望 0（保护可能尚未提交的新文件）", removed)
	}
	if files := env.storedFiles(); len(files) != 2 {
		t.Errorf("窗口内 GC 后文件数 = %d，期望 2", len(files))
	}
	// 时间越过安全窗口后，未被引用的文件才被清理；当前头像文件仍保留。
	env.setClockPastGCWindow()
	removed, err = env.service.CollectGarbage(env.ctx)
	if err != nil {
		t.Fatalf("窗口后 GC: %v", err)
	}
	if removed != 1 {
		t.Errorf("窗口后 GC 删除数 = %d，期望 1", removed)
	}
	if files := env.storedFiles(); len(files) != 1 {
		t.Errorf("窗口后 GC 文件数 = %d，期望 1", len(files))
	}
	if _, err := env.service.Read(env.ctx, caller, userID); err != nil {
		t.Errorf("GC 后读取当前头像: %v", err)
	}
	// 非法安全窗口配置拒绝构造服务（下限 30 秒，上限 24 小时）。
	for _, window := range []time.Duration{500 * time.Millisecond, 5 * time.Second, 48 * time.Hour} {
		options := env.options
		options.GCSafetyWindow = window
		if _, err := avatar.New(options); !errors.Is(err, avatar.ErrOptionsInvalid) {
			t.Errorf("GC 窗口 %s 错误 = %v，期望 ErrOptionsInvalid", window, err)
		}
	}
}
