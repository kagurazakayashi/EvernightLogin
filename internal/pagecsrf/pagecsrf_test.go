package pagecsrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/internal/secrets"
)

func newTestProvider(t *testing.T) *Provider {
	t.Helper()
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	ring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	provider, err := New(Options{Keyring: ring, TTL: 10 * time.Minute,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	return provider
}

func TestIssueValidateRoundTrip(t *testing.T) {
	provider := newTestProvider(t)
	token, cookie, err := provider.IssueFormToken(context.Background(), nil, "auth.login")
	if err != nil || cookie == nil || cookie.HttpOnly == false || cookie.Secure == false {
		t.Fatalf("签发: %v cookie=%+v", err, cookie)
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/login", nil)
	request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	if err := provider.Validate(context.Background(), request, "/login",
		map[string]string{"/login": "auth.login"}, token); err != nil {
		t.Fatalf("校验: %v", err)
	}
}

func TestValidateRejectsTamperPurposeAndCookie(t *testing.T) {
	provider := newTestProvider(t)
	token, cookie, err := provider.IssueFormToken(context.Background(), nil, "auth.login")
	if err != nil {
		t.Fatalf("签发: %v", err)
	}
	makeRequest := func(value string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, "http://example.test/login", nil)
		request.AddCookie(&http.Cookie{Name: CookieName, Value: value})
		return request
	}
	cases := map[string]struct {
		request *http.Request
		path    string
		token   string
	}{
		"用途错配":      {makeRequest(cookie.Value), "/register", token},
		"Cookie 不符": {makeRequest("other"), "/login", token},
		"令牌篡改":      {makeRequest(cookie.Value), "/login", token[:len(token)-2] + "00"},
		"缺少 Cookie": {httptest.NewRequest(http.MethodPost, "http://example.test/login", nil),
			"/login", token},
	}
	for name, testCase := range cases {
		purposes := map[string]string{"/login": "auth.login", "/register": "auth.register"}
		if err := provider.Validate(context.Background(), testCase.request, testCase.path,
			purposes, testCase.token); err == nil {
			t.Errorf("%s: 应拒绝", name)
		}
	}
}

func TestValidateRejectsExpiredToken(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	ring, err := secrets.GenerateKeyring("k1", now)
	if err != nil {
		t.Fatalf("密钥环: %v", err)
	}
	provider, err := New(Options{Keyring: ring, TTL: 2 * time.Minute,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("构造: %v", err)
	}
	token, cookie, err := provider.IssueFormToken(context.Background(), nil, "auth.login")
	if err != nil {
		t.Fatalf("签发: %v", err)
	}
	later := now.Add(5 * time.Minute)
	provider.now = func() time.Time { return later }
	request := httptest.NewRequest(http.MethodPost, "http://example.test/login", nil)
	request.AddCookie(&http.Cookie{Name: CookieName, Value: cookie.Value})
	if err := provider.Validate(context.Background(), request, "/login",
		map[string]string{"/login": "auth.login"}, token); err == nil {
		t.Fatal("过期令牌应拒绝")
	}
}
