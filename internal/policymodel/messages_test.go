package policymodel

import (
	"regexp"
	"strings"
	"testing"

	"egress-proxy/internal/i18n"
)

// cjkRe 用于断言英文路径不残留任何中文字符
var cjkRe = regexp.MustCompile(`\p{Han}`)

// brokenPolicy 返回一个同时违反多条规则的策略（只触发 policymodel 自己的校验文案，
// 避免把 config 包的 host/port 文案混进断言）
func brokenPolicy() *Policy {
	return &Policy{
		Mode: "on",
		Payloads: []Payload{
			// 名称非法 + 没有命名空间也没有 matchLabels
			{Name: "Order_Svc"},
			{Name: "dup", Namespaces: []string{"prod-shop"}, MatchLabels: map[string]string{"app": "dup"}},
			// 与上一个同名
			{Name: "dup", Namespaces: []string{"prod-shop"}, MatchLabels: map[string]string{"app": "dup"}},
		},
		Targets: []Target{
			{Host: "a.example.com", Port: 443, ProxyPort: 20001},
			// proxyPort 与上一个重复
			{Host: "b.example.com", Port: 443, ProxyPort: 20001},
		},
		Grants: []Grant{
			{Payload: "dup", Target: "a.example.com:443"},
			// payload 与 target 都不存在
			{Payload: "ghost", Target: "missing.example.com:443"},
		},
	}
}

// TestValidateLangEnglish 证明英文路径不输出中文，且中文路径与 Validate() 逐字一致
func TestValidateLangEnglish(t *testing.T) {
	p := brokenPolicy()

	enErr := p.ValidateLang(i18n.EN)
	if enErr == nil {
		t.Fatal("期望英文校验失败，实际通过")
	}
	if loc := cjkRe.FindString(enErr.Error()); loc != "" {
		t.Fatalf("英文校验结果不应包含中文，实际出现 %q:\n%s", loc, enErr.Error())
	}
	for _, want := range []string{
		"configuration validation failed:",
		`mode "on" is invalid, must be one of disabled / observe / enforce`,
		`payloads[0]: name "Order_Svc" is invalid, must match `,
		`duplicates payloads[1]`,
		"namespaces and matchLabels cannot both be empty",
		`proxyPort 20001 duplicates a.example.com:443; proxyPort must be globally unique`,
		`payload "ghost" does not exist`,
		`target "missing.example.com:443" does not exist (must be written as host:port)`,
	} {
		if !strings.Contains(enErr.Error(), want) {
			t.Fatalf("英文校验结果缺少 %q:\n%s", want, enErr.Error())
		}
	}

	zhErr := p.ValidateLang(i18n.ZH)
	if zhErr == nil {
		t.Fatal("期望中文校验失败，实际通过")
	}
	if got, want := zhErr.Error(), p.Validate().Error(); got != want {
		t.Fatalf("ValidateLang(zh) 应与 Validate() 完全一致\n got: %s\nwant: %s", got, want)
	}
}

// TestWarningsLangEnglish 证明 Warnings 的英文路径同样是纯英文，且中文路径不变
func TestWarningsLangEnglish(t *testing.T) {
	p := &Policy{
		Mode: ModeEnforce,
		Payloads: []Payload{
			// 没有 matchLabels、也没有命名空间
			{Name: "open-svc"},
		},
		Targets: []Target{
			{Host: "a.example.com", Port: 443, ProxyPort: 20001},
		},
	}

	en := p.WarningsLang(i18n.EN)
	joined := strings.Join(en, "|")
	if len(en) != 3 {
		t.Fatalf("期望 3 条英文提醒（缺 matchLabels / 缺命名空间 / 目标无授权），实际 %d 条: %v", len(en), en)
	}
	if loc := cjkRe.FindString(joined); loc != "" {
		t.Fatalf("英文提醒不应包含中文，实际出现 %q: %v", loc, en)
	}
	for _, want := range []string{"has no matchLabels set", "does not restrict namespaces", "has no grant"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("英文提醒缺少 %q: %v", want, en)
		}
	}

	if got, want := strings.Join(p.WarningsLang(i18n.ZH), "|"), strings.Join(p.Warnings(), "|"); got != want {
		t.Fatalf("WarningsLang(zh) 应与 Warnings() 完全一致\n got: %s\nwant: %s", got, want)
	}
	if _, err := NormalizeSourceLang(i18n.EN, "fd00::1"); err == nil || cjkRe.MatchString(err.Error()) {
		t.Fatalf("英文源地址错误应为纯英文，实际 %v", err)
	}
}
