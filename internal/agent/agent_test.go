package agent

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"egress-proxy/config"
	"egress-proxy/internal/iptables"
	"egress-proxy/internal/policy"
	"egress-proxy/internal/policymodel"
	"egress-proxy/internal/resolver"
)

const testConfig = `
proxy:
  address: "10.238.29.6"
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
`

// fakeManager 记录收到的规则计划
type fakeManager struct {
	plans   []iptables.Plan
	applyN  int
	cleaned bool
	err     error
}

func (f *fakeManager) Apply(_ context.Context, plan iptables.Plan) (bool, error) {
	f.plans = append(f.plans, plan)
	f.applyN++
	if f.err != nil {
		return false, f.err
	}
	return true, nil
}

func (f *fakeManager) Cleanup(context.Context) error {
	f.cleaned = true
	return nil
}

func (f *fakeManager) Chain() string  { return "EGRESS-PROXY" }
func (f *fakeManager) Binary() string { return "iptables" }

// fakeSource 是可控的 policy.Source
type fakeSource struct {
	compiled *policymodel.Compiled
	err      error
	reports  []policy.Status
}

func (f *fakeSource) Fetch(context.Context) (*policymodel.Compiled, error) {
	return f.compiled, f.err
}
func (f *fakeSource) Describe() string { return "fake-controller" }
func (f *fakeSource) Report(_ context.Context, status policy.Status) error {
	f.reports = append(f.reports, status)
	return nil
}

func compileFor(t *testing.T, mode policymodel.Mode, sources []string) *policymodel.Compiled {
	t.Helper()
	return &policymodel.Compiled{
		Mode:       mode,
		Generation: 7,
		Targets: []policymodel.CompiledTarget{
			{Host: "a.example.com", Port: 443, ProxyPort: 20001, AllowSources: sources},
		},
	}
}

func lookupFake(_ context.Context, host string) ([]net.IP, error) {
	if host == "a.example.com" {
		return []net.IP{net.ParseIP("10.20.30.40")}, nil
	}
	return nil, errors.New("not found")
}

// newTestAgent 构造一个已加载配置与策略的 Agent（不启动 Run 循环）
func newTestAgent(t *testing.T, source policy.Source) (*Agent, *fakeManager) {
	t.Helper()
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatalf("测试配置非法: %v", err)
	}
	mgr := &fakeManager{}
	a := New(Options{
		ConfigPath: "unused",
		HostIP:     net.ParseIP("10.238.29.9"),
		NodeName:   "node-a",
		Lookup:     lookupFake,
		NewManager: func(binary, chain string) RuleManager { return mgr },
		Source:     source,
	})
	a.mgr = mgr
	a.cfg = cfg
	a.res = resolver.New(resolver.Options{Lookup: lookupFake, MaxIPsPerHost: 8})
	a.nextPolicyAt = time.Now()
	return a, mgr
}

func TestPlanEnforceRestrictsSource(t *testing.T) {
	src := &fakeSource{compiled: compileFor(t, policymodel.ModeEnforce, []string{"10.244.5.7/32"})}
	a, _ := newTestAgent(t, src)

	if !a.refreshPolicy(context.Background()) {
		t.Fatal("首次拉取策略应返回变化")
	}
	// 模拟一次域名解析（Run 循环里由 resolveInterval 触发）
	a.res.Refresh(context.Background(), domainHosts(a.compiled))
	plan, err := a.Plan()
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}

	var natSub, denySub *iptables.Chain
	for i := range plan.Chains {
		c := &plan.Chains[i]
		if strings.HasPrefix(c.Name, "EGRESS-PROXY-T-") && c.Table == iptables.TableNat {
			natSub = c
		}
		if strings.HasPrefix(c.Name, "EGRESS-PROXY-DENY-T-") {
			denySub = c
		}
	}
	if natSub == nil {
		t.Fatalf("缺少 nat 子链: %+v", plan.Chains)
	}
	if len(natSub.Rules) != 1 || natSub.Rules[0].SrcPrefix != "10.244.5.7/32" {
		t.Fatalf("enforce 模式子链应只放授权源: %+v", natSub.Rules)
	}
	if natSub.Rules[0].ToDestination != "10.238.29.6:20001" {
		t.Fatalf("DNAT 目标不对: %+v", natSub.Rules[0])
	}
	if denySub == nil || len(denySub.Rules) == 0 {
		t.Fatalf("enforce 模式必须有拒绝子链: %+v", plan.Chains)
	}
	last := denySub.Rules[len(denySub.Rules)-1]
	if last.Action != iptables.ActionReject {
		t.Fatalf("拒绝子链末条应为 REJECT: %+v", last)
	}

	// 域名应被解析成 /32 目标规则
	found := false
	for _, r := range plan.Chains {
		if r.Name != "EGRESS-PROXY" || r.Table != iptables.TableNat {
			continue
		}
		for _, rule := range r.Rules {
			if rule.DstPrefix == "10.20.30.40/32" && rule.Port == 443 {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("主链应包含解析后的目标 IP 跳转")
	}
}

func TestPlanEmptySourcesDeniesAll(t *testing.T) {
	src := &fakeSource{compiled: compileFor(t, policymodel.ModeEnforce, nil)}
	a, _ := newTestAgent(t, src)
	a.refreshPolicy(context.Background())

	plan, err := a.Plan()
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	for _, c := range plan.Chains {
		if strings.HasPrefix(c.Name, "EGRESS-PROXY-T-") && c.Table == iptables.TableNat {
			if len(c.Rules) != 0 {
				t.Fatalf("没有授权源时子链必须为空（默认拒绝）: %+v", c.Rules)
			}
		}
	}
}

func TestRefreshPolicyFallsBackToLegacyWhenControllerDown(t *testing.T) {
	src := &fakeSource{err: errors.New("connection refused")}
	a, _ := newTestAgent(t, src)

	// 控制器不可用且无缓存时应退化为配置文件的 targets（disabled 模式）
	if err := a.applyConfig(context.Background(), a.cfg); err != nil {
		t.Fatalf("applyConfig 失败: %v", err)
	}
	if a.mode() != policymodel.ModeDisabled {
		t.Fatalf("应退化为 disabled，实际 %q", a.mode())
	}
	plan, err := a.Plan()
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	for _, c := range plan.Chains {
		if c.Table == iptables.TableFilter {
			t.Fatalf("disabled 模式不应有 filter 链: %+v", c)
		}
	}
}

func TestReconcileRecordsFailure(t *testing.T) {
	src := &fakeSource{compiled: compileFor(t, policymodel.ModeEnforce, []string{"10.244.5.7/32"})}
	a, mgr := newTestAgent(t, src)
	a.refreshPolicy(context.Background())

	mgr.err = errors.New("iptables 不可用")
	if err := a.Reconcile(context.Background()); err == nil {
		t.Fatal("期望 Reconcile 返回错误")
	}
	if a.Applied() {
		t.Fatal("失败时 Applied() 应为 false")
	}
	if !strings.Contains(a.LastError(), "iptables 不可用") {
		t.Fatalf("LastError 未记录错误: %q", a.LastError())
	}
	if len(src.reports) == 0 {
		t.Fatal("应向控制器上报状态")
	}
	last := src.reports[len(src.reports)-1]
	if last.Applied {
		t.Fatalf("上报状态应为未应用: %+v", last)
	}
	if last.Generation != 7 || last.Node != "node-a" {
		t.Fatalf("上报内容不对: %+v", last)
	}

	mgr.err = nil
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatalf("恢复后应成功: %v", err)
	}
	if !a.Applied() || a.LastError() != "" {
		t.Fatalf("成功后状态未复位: applied=%v err=%q", a.Applied(), a.LastError())
	}
}

func TestCompiledEqual(t *testing.T) {
	base := compileFor(t, policymodel.ModeEnforce, []string{"10.244.5.7/32"})
	same := compileFor(t, policymodel.ModeEnforce, []string{"10.244.5.7/32"})
	if !compiledEqual(base, same) {
		t.Fatal("相同内容应判定为相等")
	}
	otherMode := compileFor(t, policymodel.ModeObserve, []string{"10.244.5.7/32"})
	if compiledEqual(base, otherMode) {
		t.Fatal("mode 不同应判定为不等")
	}
	otherSource := compileFor(t, policymodel.ModeEnforce, []string{"10.244.5.8/32"})
	if compiledEqual(base, otherSource) {
		t.Fatal("允许源不同应判定为不等")
	}
	if !compiledEqual(nil, nil) {
		t.Fatal("nil 与 nil 应相等")
	}
	if compiledEqual(nil, base) {
		t.Fatal("nil 与非 nil 不应相等")
	}
}

func TestDomainHosts(t *testing.T) {
	compiled := &policymodel.Compiled{Targets: []policymodel.CompiledTarget{
		{Host: "a.example.com", Port: 443},
		{Host: "a.example.com", Port: 8443},
		{Host: "10.20.30.40", Port: 5432},
		{Host: "", Port: 1},
	}}
	got := domainHosts(compiled)
	if len(got) != 1 || got[0] != "a.example.com" {
		t.Fatalf("域名列表不对: %v", got)
	}
	if domainHosts(nil) != nil {
		t.Fatal("nil 输入应返回 nil")
	}
}

func TestIsProxyNode(t *testing.T) {
	cfg, err := config.Parse([]byte(testConfig))
	if err != nil {
		t.Fatalf("配置非法: %v", err)
	}
	proxyNode := New(Options{ConfigPath: "x", HostIP: net.ParseIP("10.238.29.6")})
	if !proxyNode.IsProxyNode(cfg) {
		t.Fatal("HOST_IP 等于 proxy.address 时应判定为代理节点")
	}
	worker := New(Options{ConfigPath: "x", HostIP: net.ParseIP("10.238.29.9")})
	if worker.IsProxyNode(cfg) {
		t.Fatal("普通工作节点不应判定为代理节点")
	}
}

func TestEnvNodeName(t *testing.T) {
	t.Setenv("NODE_NAME", " node-a ")
	if got := EnvNodeName(); got != "node-a" {
		t.Fatalf("EnvNodeName 未 trim: %q", got)
	}
	t.Setenv("NODE_NAME", "")
	if got := EnvNodeName(); got != "" {
		t.Fatalf("空环境变量应返回空串: %q", got)
	}
}
