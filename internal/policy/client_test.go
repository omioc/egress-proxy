package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"egress-proxy/config"
	"egress-proxy/internal/policymodel"
)

func compiledFixture() policymodel.Compiled {
	return policymodel.Compiled{
		Mode:       policymodel.ModeEnforce,
		Generation: 3,
		Targets: []policymodel.CompiledTarget{
			{Host: "a.example.com", Port: 443, ProxyPort: 20001, AllowSources: []string{"10.244.5.7/32"}},
		},
	}
}

func TestHTTPClientFetch(t *testing.T) {
	var gotNode, gotToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/compiled" {
			t.Errorf("意外路径 %s", r.URL.Path)
		}
		gotNode = r.URL.Query().Get("node")
		gotToken = r.Header.Get("X-EGP-Token")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(compiledFixture())
	}))
	defer srv.Close()

	cache := filepath.Join(t.TempDir(), "policy.json")
	c := NewHTTPClient(Options{
		BaseURL:   srv.URL,
		NodeName:  "node-a",
		Token:     "secret",
		CachePath: cache,
	})

	compiled, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch 失败: %v", err)
	}
	if gotNode != "node-a" {
		t.Fatalf("node 查询参数未传递: %q", gotNode)
	}
	if gotToken != "secret" {
		t.Fatalf("令牌头未传递: %q", gotToken)
	}
	if compiled.Mode != policymodel.ModeEnforce || compiled.Generation != 3 {
		t.Fatalf("解析结果不对: %+v", compiled)
	}
	if len(compiled.Targets) != 1 || compiled.Targets[0].AllowSources[0] != "10.244.5.7/32" {
		t.Fatalf("目标解析不对: %+v", compiled.Targets)
	}

	// 缓存应已落盘
	raw, err := os.ReadFile(cache)
	if err != nil {
		t.Fatalf("缓存未写入: %v", err)
	}
	var cached policymodel.Compiled
	if err := json.Unmarshal(raw, &cached); err != nil {
		t.Fatalf("缓存内容非法: %v", err)
	}
	if cached.Generation != 3 {
		t.Fatalf("缓存内容不对: %+v", cached)
	}
}

func TestHTTPClientFallsBackToLastKnown(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(compiledFixture())
	}))
	defer srv.Close()

	c := NewHTTPClient(Options{BaseURL: srv.URL})
	if _, err := c.Fetch(context.Background()); err != nil {
		t.Fatalf("首次 Fetch 失败: %v", err)
	}

	fail = true
	compiled, err := c.Fetch(context.Background())
	if err == nil {
		t.Fatal("控制器异常时应返回错误（便于上报与告警）")
	}
	if compiled == nil {
		t.Fatal("应沿用上一次成功的结果（fail-stale）")
	}
	if compiled.Generation != 3 {
		t.Fatalf("沿用结果不对: %+v", compiled)
	}
}

func TestHTTPClientFirstFailureReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewHTTPClient(Options{BaseURL: srv.URL})
	compiled, err := c.Fetch(context.Background())
	if err == nil {
		t.Fatal("应返回错误")
	}
	if compiled != nil {
		t.Fatalf("首次失败时不应有结果，实际 %+v", compiled)
	}
}

func TestHTTPClientRejectsInvalidMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"mode":"bogus","targets":[]}`))
	}))
	defer srv.Close()

	c := NewHTTPClient(Options{BaseURL: srv.URL})
	if _, err := c.Fetch(context.Background()); err == nil {
		t.Fatal("非法 mode 应报错")
	}
}

func TestHTTPClientLoadsCache(t *testing.T) {
	dir := t.TempDir()
	cache := filepath.Join(dir, "policy.json")
	raw, _ := json.Marshal(compiledFixture())
	if err := os.WriteFile(cache, raw, 0o644); err != nil {
		t.Fatalf("写入缓存失败: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewHTTPClient(Options{BaseURL: srv.URL, CachePath: cache})
	compiled, err := c.Fetch(context.Background())
	if err == nil {
		t.Fatal("控制器不可用时应返回错误")
	}
	if compiled == nil || compiled.Generation != 3 {
		t.Fatalf("应从磁盘缓存恢复策略，实际 %+v", compiled)
	}
}

func TestStaticSource(t *testing.T) {
	targets := []config.Target{
		{Host: "a.example.com", Port: 443, ProxyPort: 20001},
		{Host: "10.20.30.40", Port: 5432, ProxyPort: 20002},
	}
	s := NewStaticSource(targets)
	compiled, err := s.Fetch(context.Background())
	if err != nil {
		t.Fatalf("静态来源不应报错: %v", err)
	}
	if compiled.Mode != policymodel.ModeDisabled {
		t.Fatalf("静态来源应为 disabled 模式，实际 %q", compiled.Mode)
	}
	if len(compiled.Targets) != 2 {
		t.Fatalf("目标数不对: %+v", compiled.Targets)
	}
	for _, tgt := range compiled.Targets {
		if len(tgt.AllowSources) != 0 {
			t.Fatalf("静态来源不应有允许源: %+v", tgt)
		}
	}
	if err := s.Report(context.Background(), Status{Node: "x"}); err != nil {
		t.Fatalf("静态来源 Report 应为空操作: %v", err)
	}
	if s.Describe() == "" {
		t.Fatal("Describe 不应为空")
	}
}

func TestParsePortList(t *testing.T) {
	got, err := ParsePortList("20001, 20002")
	if err != nil || len(got) != 2 || got[1] != 20002 {
		t.Fatalf("解析结果不对: %v %v", got, err)
	}
	if _, err := ParsePortList("0"); err == nil {
		t.Fatal("端口 0 应报错")
	}
	if _, err := ParsePortList("abc"); err == nil {
		t.Fatal("非数字应报错")
	}
}

func TestFormatSources(t *testing.T) {
	if got := FormatSources(nil); got == "" {
		t.Fatal("空列表也应有可读描述")
	}
	if got := FormatSources([]string{"10.0.0.1/32"}); got != "10.0.0.1/32" {
		t.Fatalf("单值格式化不对: %q", got)
	}
	many := []string{"1", "2", "3", "4", "5", "6", "7"}
	if got := FormatSources(many); got == "" {
		t.Fatal("多值格式化不应为空")
	}
}

func TestHostOf(t *testing.T) {
	if got := HostOf("10.20.30.40:5432"); got != "10.20.30.40" {
		t.Fatalf("HostOf = %q", got)
	}
	if got := HostOf("plain"); got != "plain" {
		t.Fatalf("非法输入应原样返回: %q", got)
	}
}
