package config

import (
	"strings"
	"testing"
)

// 四元组管控启用后，targets 完全由控制器下发，配置文件里可以为空
// 这是曾经导致 forwarder/agent 卡在「等待配置文件」的回归点
func TestEmptyTargetsAllowed(t *testing.T) {
	yaml := `
proxy:
  address: "10.238.29.6"
targets: []
options:
  policyUrl: http://egress-proxy-controller.egress-proxy.svc:18082
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("空 targets 应被允许，实际报错: %v", err)
	}
	if len(cfg.Targets) != 0 {
		t.Fatalf("targets 应为空，实际 %+v", cfg.Targets)
	}
	if cfg.Options.PolicyURL != "http://egress-proxy-controller.egress-proxy.svc:18082" {
		t.Fatalf("policyUrl 未解析: %q", cfg.Options.PolicyURL)
	}
	if cfg.Options.PolicyInterval.D().String() != "2s" {
		t.Fatalf("policyInterval 默认值应为 2s，实际 %s", cfg.Options.PolicyInterval)
	}
}

func TestEmptyTargetsWithoutPolicyURLAlsoAllowed(t *testing.T) {
	yaml := `
proxy:
  address: "10.238.29.6"
`
	cfg, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("省略 targets 也应被允许，实际报错: %v", err)
	}
	if len(cfg.Targets) != 0 {
		t.Fatalf("targets 应为空，实际 %+v", cfg.Targets)
	}
	if cfg.Options.PolicyURL != "" {
		t.Fatalf("未配置 policyUrl 时应为空，实际 %q", cfg.Options.PolicyURL)
	}
}

func TestPolicyURLOptions(t *testing.T) {
	base := `
proxy:
  address: "10.238.29.6"
targets: []
options:
  policyUrl: %s
`
	ok := []string{
		"http://egress-proxy-controller.egress-proxy.svc:18082",
		"https://controller.example.com",
	}
	for _, u := range ok {
		if _, err := Parse([]byte(strings.Replace(base, "%s", u, 1))); err != nil {
			t.Fatalf("policyUrl %q 应合法，实际报错: %v", u, err)
		}
	}

	bad := map[string]string{
		"ftp://controller":   "http",
		"egress-proxy:18082": "http",
		"http://":            "主机名",
	}
	for u, want := range bad {
		_, err := Parse([]byte(strings.Replace(base, "%s", u, 1)))
		if err == nil {
			t.Fatalf("policyUrl %q 应非法", u)
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("policyUrl %q 的错误 %q 未包含 %q", u, err.Error(), want)
		}
	}
}

func TestPolicyIntervalTooSmall(t *testing.T) {
	yaml := `
proxy:
  address: "10.238.29.6"
targets: []
options:
  policyInterval: 100ms
`
	if _, err := Parse([]byte(yaml)); err == nil {
		t.Fatal("policyInterval 小于 MinInterval 应报错")
	}
}
