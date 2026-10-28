package policymodel

import (
	"strings"
	"testing"
)

func validPolicy() *Policy {
	return &Policy{
		Mode: ModeEnforce,
		Payloads: []Payload{
			{
				Name:        "order-svc",
				Namespaces:  []string{"prod-shop"},
				MatchLabels: map[string]string{"app": "order-svc"},
			},
		},
		Targets: []Target{
			{Host: "a.example.com", Port: 443, ProxyPort: 20001},
			{Host: "10.20.30.40", Port: 5432, ProxyPort: 20002},
		},
		Grants: []Grant{
			{Payload: "order-svc", Target: "a.example.com:443"},
		},
	}
}

func TestPolicyValidateOK(t *testing.T) {
	p := validPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("期望校验通过，实际报错: %v", err)
	}
}

func TestPolicyValidateErrors(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Policy)
		want   string
	}{
		{"非法模式", func(p *Policy) { p.Mode = "on" }, "mode"},
		{"payload 名非法", func(p *Policy) { p.Payloads[0].Name = "Order_Svc" }, "名称"},
		{"payload 重复", func(p *Policy) { p.Payloads = append(p.Payloads, p.Payloads[0]) }, "重复"},
		{"payload 空选择器", func(p *Policy) { p.Payloads[0].Namespaces = nil; p.Payloads[0].MatchLabels = nil }, "不能同时为空"},
		{"命名空间非法", func(p *Policy) { p.Payloads[0].Namespaces = []string{"Prod_Shop"} }, "命名空间"},
		{"工作负载类型非法", func(p *Policy) { p.Payloads[0].Workload = &WorkloadRef{Kind: "ReplicaSet", Name: "x"} }, "workload.kind"},
		{"工作负载未解析", func(p *Policy) {
			p.Payloads[0].Workload = &WorkloadRef{Kind: "Deployment", Name: "x"}
			p.Payloads[0].MatchLabels = nil
		}, "解析成标签选择器"},
		{"工作负载缺命名空间", func(p *Policy) {
			p.Payloads[0].Workload = &WorkloadRef{Kind: "Deployment", Name: "x"}
			p.Payloads[0].Namespaces = nil
		}, "1 个命名空间"},
		{"host 非法", func(p *Policy) { p.Targets[0].Host = "a b" }, "host"},
		{"端口越界", func(p *Policy) { p.Targets[0].Port = 70000 }, "port"},
		{"proxyPort 重复", func(p *Policy) { p.Targets[1].ProxyPort = p.Targets[0].ProxyPort }, "proxyPort"},
		{"host+port 重复", func(p *Policy) { p.Targets[1].Host = p.Targets[0].Host; p.Targets[1].Port = p.Targets[0].Port }, "重复"},
		{"授权引用不存在的 payload", func(p *Policy) { p.Grants[0].Payload = "ghost" }, "不存在"},
		{"授权引用不存在的 target", func(p *Policy) { p.Grants[0].Target = "b.example.com:443" }, "不存在"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := validPolicy()
			tc.mutate(p)
			err := p.Validate()
			if err == nil {
				t.Fatalf("期望校验失败，实际通过")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误信息 %q 未包含 %q", err.Error(), tc.want)
			}
		})
	}
}

func TestPolicyNormalize(t *testing.T) {
	p := &Policy{
		Payloads: []Payload{
			{Name: " b ", Namespaces: []string{" ns1 ", "ns1", ""}, MatchLabels: map[string]string{" app ": " v "}},
			{Name: "a", Namespaces: []string{"ns2"}},
			{Name: "b", Namespaces: []string{"dup"}},
			{Name: "  ", Namespaces: []string{"x"}},
		},
		Targets: []Target{
			{Host: " b.example.com ", Port: 443, ProxyPort: 20002},
			{Host: "a.example.com", Port: 443, ProxyPort: 20001},
			{Host: "a.example.com", Port: 443, ProxyPort: 20003},
		},
		Grants: []Grant{
			{Payload: "b", Target: "b.example.com:443"},
			{Payload: "a", Target: "a.example.com:443"},
			{Payload: "a", Target: "a.example.com:443"},
		},
	}
	p.Normalize()

	if p.Mode != ModeDisabled {
		t.Fatalf("空 mode 应默认为 disabled，实际 %q", p.Mode)
	}
	if len(p.Payloads) != 2 || p.Payloads[0].Name != "a" || p.Payloads[1].Name != "b" {
		t.Fatalf("payload 去重排序结果不对: %+v", p.Payloads)
	}
	if got := p.Payloads[1].Namespaces; len(got) != 1 || got[0] != "ns1" {
		t.Fatalf("命名空间规范化结果不对: %v", got)
	}
	if p.Payloads[1].MatchLabels["app"] != "v" {
		t.Fatalf("标签键值未 trim: %v", p.Payloads[1].MatchLabels)
	}
	if len(p.Targets) != 2 || p.Targets[0].Host != "a.example.com" || p.Targets[1].Host != "b.example.com" {
		t.Fatalf("target 去重排序结果不对: %+v", p.Targets)
	}
	if len(p.Grants) != 2 {
		t.Fatalf("grant 去重失败: %+v", p.Grants)
	}
}

func TestCompileDefaultDeny(t *testing.T) {
	idx := NewIndex([]Pod{
		{Namespace: "prod-shop", Name: "order-0", NodeName: "node-a", IP: "10.244.5.7", Labels: map[string]string{"app": "order-svc"}},
		{Namespace: "prod-shop", Name: "other-0", NodeName: "node-a", IP: "10.244.5.8", Labels: map[string]string{"app": "other"}},
		{Namespace: "prod-bi", Name: "order-1", NodeName: "node-b", IP: "10.244.6.9", Labels: map[string]string{"app": "order-svc"}},
	})

	p := validPolicy()
	// payload 覆盖两个命名空间，因此 prod-shop 与 prod-bi 的 Pod 都应命中
	p.Payloads[0].Namespaces = []string{"prod-shop", "prod-bi"}
	compiled := Compile(p, idx, "")

	if compiled.Mode != ModeEnforce {
		t.Fatalf("mode 未透传: %q", compiled.Mode)
	}
	if len(compiled.Targets) != 2 {
		t.Fatalf("目标数不对: %+v", compiled.Targets)
	}

	// 有授权的目标：两个 Pod IP
	a443, ok := compiled.TargetByKey("a.example.com:443")
	if !ok {
		t.Fatal("缺少 a.example.com:443")
	}
	want := []string{"10.244.5.7/32", "10.244.6.9/32"}
	if strings.Join(a443.AllowSources, ",") != strings.Join(want, ",") {
		t.Fatalf("允许源不一致\n got: %v\nwant: %v", a443.AllowSources, want)
	}

	// 没有授权的目标：允许源必须为空（默认拒绝）
	db, ok := compiled.TargetByKey("10.20.30.40:5432")
	if !ok {
		t.Fatal("缺少 10.20.30.40:5432")
	}
	if len(db.AllowSources) != 0 {
		t.Fatalf("未授权目标不应有任何源地址，实际 %v", db.AllowSources)
	}
}

func TestCompileNodeFilter(t *testing.T) {
	idx := NewIndex([]Pod{
		{Namespace: "prod-shop", Name: "order-0", NodeName: "node-a", IP: "10.244.5.7", Labels: map[string]string{"app": "order-svc"}},
		{Namespace: "prod-shop", Name: "order-1", NodeName: "node-b", IP: "10.244.6.9", Labels: map[string]string{"app": "order-svc"}},
	})
	p := validPolicy()

	compiled := Compile(p, idx, "node-a")
	target, _ := compiled.TargetByKey("a.example.com:443")
	if len(target.AllowSources) != 1 || target.AllowSources[0] != "10.244.5.7/32" {
		t.Fatalf("按节点过滤失败: %v", target.AllowSources)
	}

	compiled = Compile(p, idx, "node-c")
	target, _ = compiled.TargetByKey("a.example.com:443")
	if len(target.AllowSources) != 0 {
		t.Fatalf("该节点没有成员时应为空，实际 %v", target.AllowSources)
	}
}

func TestIndexDropsPodsWithoutIP(t *testing.T) {
	idx := NewIndex([]Pod{
		{Namespace: "ns", Name: "pending", NodeName: "node-a", IP: ""},
		{Namespace: "ns", Name: "none", NodeName: "node-a", IP: "None"},
		{Namespace: "ns", Name: "ok", NodeName: "node-a", IP: "10.244.1.1"},
	})
	if idx.Len() != 1 {
		t.Fatalf("应只保留有 IP 的 Pod，实际 %d", idx.Len())
	}
}

func TestSortSources(t *testing.T) {
	got := SortSources([]string{
		"10.244.6.9", "10.238.29.0/24", "10.244.5.7/32", "10.244.6.9", "bad",
	})
	want := "10.244.5.7/32,10.244.6.9/32,10.238.29.0/24"
	if strings.Join(got, ",") != want {
		t.Fatalf("排序去重结果不对\n got: %v\nwant: %s", got, want)
	}
}

func TestNormalizeSource(t *testing.T) {
	ok := map[string]string{
		"10.244.5.7":      "10.244.5.7/32",
		"10.244.5.7/32":   "10.244.5.7/32",
		"10.238.29.0/24":  "10.238.29.0/24",
		" 10.244.5.7/032": "10.244.5.7/32",
	}
	for in, want := range ok {
		got, err := NormalizeSource(in)
		if err != nil {
			t.Fatalf("%q 期望合法，实际报错 %v", in, err)
		}
		if got != want {
			t.Fatalf("%q 规范化结果 %q != %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "fd00::1", "10.0.0.0/64"} {
		if _, err := NormalizeSource(bad); err == nil {
			t.Fatalf("%q 期望非法，实际通过", bad)
		}
	}
}

func TestToggleGrant(t *testing.T) {
	p := validPolicy()
	if !p.Allows("order-svc", "a.example.com:443") {
		t.Fatal("初始应已授权")
	}
	if !p.ToggleGrant("order-svc", "10.20.30.40:5432", true) {
		t.Fatal("新增授权应返回 true")
	}
	if !p.Allows("order-svc", "10.20.30.40:5432") {
		t.Fatal("新增授权未生效")
	}
	if p.ToggleGrant("order-svc", "10.20.30.40:5432", true) {
		t.Fatal("重复新增应返回 false")
	}
	if !p.ToggleGrant("order-svc", "a.example.com:443", false) {
		t.Fatal("删除授权应返回 true")
	}
	if p.Allows("order-svc", "a.example.com:443") {
		t.Fatal("授权未被删除")
	}
	if p.ToggleGrant("ghost", "a.example.com:443", true) {
		t.Fatal("不存在的 payload 不应变更成功")
	}
}

func TestWarnings(t *testing.T) {
	p := validPolicy()
	p.Payloads[0].MatchLabels = nil
	p.Payloads[0].Namespaces = []string{"prod-shop"}
	p.Grants = nil

	warnings := p.Warnings()
	joined := strings.Join(warnings, "|")
	if !strings.Contains(joined, "matchLabels") {
		t.Fatalf("应提示未设置 matchLabels: %v", warnings)
	}
	if !strings.Contains(joined, "没有任何授权") {
		t.Fatalf("应提示目标没有授权: %v", warnings)
	}
}

func TestPayloadResolveWorkload(t *testing.T) {
	list := []Workload{
		{Kind: "Deployment", Namespace: "prod-shop", Name: "order-svc", Selector: map[string]string{"app": "order-svc"}, Ready: "2/2"},
		{Kind: "StatefulSet", Namespace: "prod-shop", Name: "order-svc", Selector: map[string]string{"app": "order-sts"}},
	}
	base := Payload{Name: "order", Namespaces: []string{"prod-shop"}, Workload: &WorkloadRef{Kind: "Deployment", Name: "order-svc"}}
	got, err := base.Resolve(list)
	if err != nil {
		t.Fatalf("期望解析成功，实际报错: %v", err)
	}
	if got.MatchLabels["app"] != "order-svc" {
		t.Fatalf("解析出的标签不对: %v", got.MatchLabels)
	}
	if base.MatchLabels != nil {
		t.Fatal("Resolve 不应修改原 payload")
	}
	if err := (&Policy{Mode: ModeDisabled, Payloads: []Payload{got}}).Validate(); err != nil {
		t.Fatalf("解析后的 payload 应通过校验: %v", err)
	}

	missing := Payload{Name: "ghost", Namespaces: []string{"prod-shop"}, Workload: &WorkloadRef{Kind: "Deployment", Name: "nope"}}
	if _, err := missing.Resolve(list); err == nil {
		t.Fatal("工作负载不存在时应报错")
	}

	// 标签模式已经给出 matchLabels 时不再解析
	labelMode := Payload{Name: "lab", Namespaces: []string{"prod-shop"}, MatchLabels: map[string]string{"app": "x"}}
	out, err := labelMode.Resolve(list)
	if err != nil || out.MatchLabels["app"] != "x" {
		t.Fatalf("标签模式应原样返回: %v %v", out.MatchLabels, err)
	}
}
