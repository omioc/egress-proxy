package iptables

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

// fakeRunner 按「命令|参数」返回脚本化输出，并记录所有调用
type fakeRunner struct {
	responses map[string]string
	calls     []string
	restores  []string
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{responses: make(map[string]string)}
}

func (f *fakeRunner) set(cmd string, args []string, out string) {
	f.responses[cmd+"|"+strings.Join(args, " ")] = out
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name + "|" + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if out, ok := f.responses[key]; ok {
		return out, nil
	}
	return "", nil
}

func (f *fakeRunner) RunWithInput(_ context.Context, input, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+"|"+strings.Join(args, " "))
	f.restores = append(f.restores, input)
	return "", nil
}

func (f *fakeRunner) hasCall(substr string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, substr) {
			return true
		}
	}
	return false
}

func (f *fakeRunner) indexOf(substr string) int {
	for i, c := range f.calls {
		if strings.Contains(c, substr) {
			return i
		}
	}
	return -1
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testPlan() Plan {
	const sub = "EGRESS-PROXY-T-abc123"
	return Plan{
		Chains: []Chain{
			{
				Table: TableNat,
				Name:  "EGRESS-PROXY",
				Rules: []Rule{
					{DstPrefix: "10.238.29.6/32", Action: ActionReturn, Comment: "egress-proxy 代理节点自身"},
					{DstPrefix: "127.0.0.0/8", Action: ActionReturn, Comment: "egress-proxy 回环"},
					{
						DstPrefix:  "10.20.30.40/32",
						Protocol:   "tcp",
						Port:       443,
						Action:     ActionJump,
						JumpTarget: sub,
					},
				},
			},
			{
				Table: TableNat,
				Name:  sub,
				Rules: []Rule{
					{
						SrcPrefix:     "10.244.5.7/32",
						Protocol:      "tcp",
						Action:        ActionDNAT,
						ToDestination: "10.238.29.6:20001",
					},
				},
			},
		},
		Jumps: []Jump{{Table: TableNat, Parent: "PREROUTING", Child: "EGRESS-PROXY", Position: 1}},
	}
}

// savedNat 返回与 testPlan 等价的 iptables -S 输出（模拟内核回显，含 -m tcp）
func savedNat() string {
	return strings.Join([]string{
		"-N EGRESS-PROXY",
		"-N EGRESS-PROXY-T-abc123",
		`-A EGRESS-PROXY -d 10.238.29.6/32 -m comment --comment "egress-proxy 代理节点自身" -j RETURN`,
		`-A EGRESS-PROXY -d 127.0.0.0/8 -m comment --comment "egress-proxy 回环" -j RETURN`,
		`-A EGRESS-PROXY -d 10.20.30.40/32 -p tcp -m tcp --dport 443 -m comment --comment "egress-proxy" -j EGRESS-PROXY-T-abc123`,
		`-A EGRESS-PROXY-T-abc123 -s 10.244.5.7/32 -p tcp -m tcp -m comment --comment "egress-proxy" -j DNAT --to-destination 10.238.29.6:20001`,
	}, "\n")
}

func TestRuleArgsAndCanonical(t *testing.T) {
	r := Rule{
		SrcPrefix:     "10.244.5.7/32",
		DstPrefix:     "10.20.30.40/32",
		Protocol:      "tcp",
		Port:          443,
		Action:        ActionDNAT,
		ToDestination: "10.238.29.6:20001",
	}
	args := strings.Join(r.args(), " ")
	for _, want := range []string{"-s 10.244.5.7/32", "-d 10.20.30.40/32", "-p tcp", "--dport 443", "-j DNAT", "--to-destination 10.238.29.6:20001"} {
		if !strings.Contains(args, want) {
			t.Fatalf("参数 %q 缺少 %q", args, want)
		}
	}
	canonical := r.canonical()
	for _, want := range []string{"src=10.244.5.7/32", "dst=10.20.30.40/32", "proto=tcp", "dport=443", "dnat=10.238.29.6:20001", "action=DNAT"} {
		if !strings.Contains(canonical, want) {
			t.Fatalf("规范化 %q 缺少 %q", canonical, want)
		}
	}

	reject := Rule{Action: ActionReject}
	if got := strings.Join(reject.args(), " "); !strings.Contains(got, "--reject-with tcp-reset") {
		t.Fatalf("REJECT 必须显式指定 tcp-reset（否则内核会补默认值导致反复漂移）: %s", got)
	}

	logRule := Rule{Action: ActionLog, LogPrefix: "egp-would-deny "}
	if got := strings.Join(logRule.args(), " "); !strings.Contains(got, "--log-prefix egp-would-deny") {
		t.Fatalf("LOG 参数不对: %s", got)
	}
}

func TestParseRule(t *testing.T) {
	cases := []struct {
		line string
		want string
		ok   bool
	}{
		{
			line: `-d 10.238.29.6/32 -m comment --comment "x" -j RETURN`,
			want: "dst=10.238.29.6/32 action=RETURN",
			ok:   true,
		},
		{
			line: `-s 10.244.5.7/32 -p tcp -m tcp --dport 443 -j DNAT --to-destination 10.238.29.6:20001`,
			want: "src=10.244.5.7/32 proto=tcp dport=443 dnat=10.238.29.6:20001 action=DNAT",
			ok:   true,
		},
		{
			line: `-j REJECT --reject-with tcp-reset`,
			want: "reject=tcp-reset action=REJECT",
			ok:   true,
		},
		{
			line: `-j LOG --log-prefix "egp-would-deny "`,
			want: "log=egp-would-deny action=LOG",
			ok:   true,
		},
		{
			line: `-p tcp -m tcp --dport 443 -j EGRESS-PROXY-T-abc123`,
			want: "proto=tcp dport=443 jump=EGRESS-PROXY-T-abc123 action=JUMP",
			ok:   true,
		},
		{line: `-m set --match-set foo src -j RETURN`, want: "", ok: false},
		{line: `! -s 10.0.0.1/32 -j RETURN`, want: "", ok: false},
	}
	for _, tc := range cases {
		got, ok := parseRule(tc.line)
		if ok != tc.ok {
			t.Fatalf("%q 可解析性期望 %v，实际 %v", tc.line, tc.ok, ok)
		}
		if ok && got != tc.want {
			t.Fatalf("%q 解析结果\n got: %s\nwant: %s", tc.line, got, tc.want)
		}
	}
}

func TestPlanValidate(t *testing.T) {
	cases := []struct {
		name string
		plan Plan
		want string
	}{
		{
			name: "跳转到不存在的链",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: "C1", Rules: []Rule{{Action: ActionJump, JumpTarget: "NOPE"}}}}},
			want: "跳转目标",
		},
		{
			name: "非法的表",
			plan: Plan{Chains: []Chain{{Table: "mangle", Name: "C1"}}},
			want: "不支持",
		},
		{
			name: "内建链名",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: "PREROUTING"}}},
			want: "内建链",
		},
		{
			name: "链名过长",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: strings.Repeat("X", 29)}}},
			want: "上限",
		},
		{
			name: "DNAT 缺目标",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: "C1", Rules: []Rule{{Action: ActionDNAT}}}}},
			want: "--to-destination",
		},
		{
			// 曾经的线上故障：DNAT 带端口但没 -p tcp，iptables 直接退出码 2
			name: "DNAT 带端口但没协议",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: "C1", Rules: []Rule{
				{Action: ActionDNAT, ToDestination: "10.238.29.6:20001"},
			}}}},
			want: "需要 -p tcp",
		},
		{
			// 同理：tcp-reset 要求规则本身匹配 tcp
			name: "REJECT tcp-reset 但没协议",
			plan: Plan{Chains: []Chain{{Table: TableFilter, Name: "C1", Rules: []Rule{
				{Action: ActionReject, RejectWith: "tcp-reset"},
			}}}},
			want: "tcp-reset",
		},
		{
			name: "有端口没协议",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: "C1", Rules: []Rule{{Port: 443, Action: ActionReturn}}}}},
			want: "Protocol",
		},
		{
			name: "非法源地址",
			plan: Plan{Chains: []Chain{{Table: TableNat, Name: "C1", Rules: []Rule{{SrcPrefix: "nope", Action: ActionReturn}}}}},
			want: "src",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.plan.Validate()
			if err == nil {
				t.Fatalf("期望校验失败")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误 %q 未包含 %q", err.Error(), tc.want)
			}
		})
	}
	if err := testPlan().Validate(); err != nil {
		t.Fatalf("合法计划不应报错: %v", err)
	}
}

func TestApplyFirstTimeWritesEverything(t *testing.T) {
	r := newFakeRunner()
	m := NewWithRunner(r, "iptables", "EGRESS-PROXY", testLogger())

	changed, err := m.Apply(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if !changed {
		t.Fatal("首次应用应返回 changed=true")
	}
	if len(r.restores) != 1 {
		t.Fatalf("应只有一次 iptables-restore，实际 %d", len(r.restores))
	}
	fragment := r.restores[0]
	for _, want := range []string{
		"*nat",
		":EGRESS-PROXY - [0:0]",
		":EGRESS-PROXY-T-abc123 - [0:0]",
		"-A EGRESS-PROXY -d 10.238.29.6/32",
		"-A EGRESS-PROXY-T-abc123 -s 10.244.5.7/32",
		"-j DNAT --to-destination 10.238.29.6:20001",
		"COMMIT",
	} {
		if !strings.Contains(fragment, want) {
			t.Fatalf("restore 片段缺少 %q\n%s", want, fragment)
		}
	}
	for _, want := range []string{"-t nat -N EGRESS-PROXY", "-t nat -F EGRESS-PROXY", "-t nat -I PREROUTING 1"} {
		if !r.hasCall(want) {
			t.Fatalf("缺少命令 %q，实际调用：%v", want, r.calls)
		}
	}
}

func TestApplyIsIdempotentWhenStateMatches(t *testing.T) {
	r := newFakeRunner()
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S"}, savedNat())
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S", "PREROUTING"},
		"-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-A PREROUTING -m comment --comment \"egress-proxy\" -j EGRESS-PROXY")

	m := NewWithRunner(r, "iptables", "EGRESS-PROXY", testLogger())
	changed, err := m.Apply(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if changed {
		t.Fatal("内核状态与期望一致时不应发生写操作")
	}
	if len(r.restores) != 0 {
		t.Fatalf("不应调用 iptables-restore，实际 %d 次", len(r.restores))
	}
	for _, c := range r.calls {
		if strings.Contains(c, " -N ") || strings.Contains(c, " -F ") || strings.Contains(c, " -I ") || strings.Contains(c, " -A ") {
			t.Fatalf("不应有写操作，实际调用 %q", c)
		}
	}
}

func TestApplyRebuildsWhenDrift(t *testing.T) {
	r := newFakeRunner()
	// 现状：链存在但内容少一条 → 应被判定为漂移并重建
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S"},
		"-N EGRESS-PROXY\n-A EGRESS-PROXY -d 127.0.0.0/8 -m comment --comment \"x\" -j RETURN")
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S", "PREROUTING"},
		"-A PREROUTING -m comment --comment \"egress-proxy\" -j EGRESS-PROXY")

	m := NewWithRunner(r, "iptables", "EGRESS-PROXY", testLogger())
	changed, err := m.Apply(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if !changed {
		t.Fatal("规则漂移时应返回 changed=true")
	}
	if len(r.restores) != 1 {
		t.Fatalf("应重写一次规则，实际 %d", len(r.restores))
	}
}

func TestApplyRecreatesJumpWhenNotFirst(t *testing.T) {
	r := newFakeRunner()
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S"}, savedNat())
	// 跳转存在但不在首位（前面还有 Calico 之类规则）→ 应删除后重新插到首位
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S", "PREROUTING"},
		"-A PREROUTING -m comment --comment \"cali\" -j cali-PREROUTING\n"+
			"-A PREROUTING -m comment --comment \"egress-proxy\" -j EGRESS-PROXY")

	m := NewWithRunner(r, "iptables", "EGRESS-PROXY", testLogger())
	changed, err := m.Apply(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if !changed {
		t.Fatal("跳转位置不对时应返回 changed=true")
	}
	if !r.hasCall("-D PREROUTING") {
		t.Fatalf("应删除错位的跳转，实际调用：%v", r.calls)
	}
	if !r.hasCall("-I PREROUTING 1") {
		t.Fatalf("应重新插入到首位，实际调用：%v", r.calls)
	}
}

func TestApplyRemovesStaleManagedChains(t *testing.T) {
	r := newFakeRunner()
	// 现状里有一个已不在计划中的托管链
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S"},
		savedNat()+"\n-N EGRESS-PROXY-T-oldold")
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S", "PREROUTING"},
		"-A PREROUTING -m comment --comment \"egress-proxy\" -j EGRESS-PROXY")

	m := NewWithRunner(r, "iptables", "EGRESS-PROXY", testLogger())
	changed, err := m.Apply(context.Background(), testPlan())
	if err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	if !changed {
		t.Fatal("存在多余托管链时应返回 changed=true")
	}
	if !r.hasCall("-t nat -X EGRESS-PROXY-T-oldold") {
		t.Fatalf("应删除多余托管链，实际调用：%v", r.calls)
	}
}

func TestCleanupOrder(t *testing.T) {
	r := newFakeRunner()
	r.set("iptables", []string{"-w", "5", "-t", "nat", "-S"},
		"-N EGRESS-PROXY\n-N EGRESS-PROXY-T-abc123\n"+
			"-A PREROUTING -m comment --comment \"egress-proxy\" -j EGRESS-PROXY\n"+
			"-A EGRESS-PROXY -d 10.20.30.40/32 -p tcp -m tcp --dport 443 -j EGRESS-PROXY-T-abc123")

	m := NewWithRunner(r, "iptables", "EGRESS-PROXY", testLogger())
	if err := m.Cleanup(context.Background()); err != nil {
		t.Fatalf("Cleanup 失败: %v", err)
	}

	del := r.indexOf("-D PREROUTING")
	flush := r.indexOf("-t nat -F EGRESS-PROXY")
	delChain := r.indexOf("-t nat -X EGRESS-PROXY")
	if del < 0 {
		t.Fatalf("应先删除内建链上的跳转，实际调用：%v", r.calls)
	}
	if flush < 0 || delChain < 0 {
		t.Fatalf("应清空并删除托管链，实际调用：%v", r.calls)
	}
	if !(del < delChain) {
		t.Fatalf("必须先删跳转再删链（顺序实际 %d vs %d）", del, delChain)
	}
	if !strings.Contains(strings.Join(r.calls, "\n"), "-X EGRESS-PROXY-T-abc123") {
		t.Fatalf("派生链也应被删除，实际调用：%v", r.calls)
	}
}

func TestManaged(t *testing.T) {
	m := NewWithRunner(newFakeRunner(), "iptables", "EGRESS-PROXY", testLogger())
	cases := map[string]bool{
		"EGRESS-PROXY":          true,
		"EGRESS-PROXY-DENY":     true,
		"EGRESS-PROXY-T-abc123": true,
		"EGRESS-PROXY-OTHER":    true,
		"EGRESS-PROXYX":         false,
		"KUBE-SERVICES":         false,
		"PREROUTING":            false,
	}
	for name, want := range cases {
		if got := m.Managed(name); got != want {
			t.Fatalf("Managed(%q) = %v，期望 %v", name, got, want)
		}
	}
}
