package rules

import (
	"net"
	"strings"
	"testing"

	"egress-proxy/internal/iptables"
	"egress-proxy/internal/policymodel"
)

func opts(mode policymodel.Mode) Options {
	return Options{
		ProxyIP:       net.ParseIP("10.238.29.6"),
		ChainName:     "EGRESS-PROXY",
		ExcludeCIDRs:  []string{"10.96.0.0/12"},
		Mode:          mode,
		Comment:       "egress-proxy",
		IncludeOutput: true,
	}
}

func target() ResolvedTarget {
	return ResolvedTarget{
		Host:         "a.example.com",
		Port:         443,
		ProxyPort:    20001,
		IPs:          []net.IP{net.ParseIP("10.20.30.40"), net.ParseIP("10.20.30.41")},
		AllowSources: []string{"10.244.5.7", "10.238.29.0/24"},
	}
}

// chain 从计划里取指定表+名字的链
func chain(plan iptables.Plan, table, name string) (iptables.Chain, bool) {
	for _, c := range plan.Chains {
		if c.Table == table && c.Name == name {
			return c, true
		}
	}
	return iptables.Chain{}, false
}

// TestDNATAndRejectRulesCarryProtocol 守住线上真实踩过的坑：
// iptables 的 `--to-destination IP:port` 与 `--reject-with tcp-reset` 都要求规则
// 自身带协议匹配，缺少 `-p tcp` 时 iptables 直接退出码 2，规则完全写不进去
func TestDNATAndRejectRulesCarryProtocol(t *testing.T) {
	modes := []policymodel.Mode{policymodel.ModeEnforce, policymodel.ModeObserve, policymodel.ModeDisabled}
	for _, mode := range modes {
		plan, err := BuildPlan(opts(mode), []ResolvedTarget{target()})
		if err != nil {
			t.Fatalf("mode=%s 生成计划失败: %v", mode, err)
		}
		for _, c := range plan.Chains {
			for _, r := range c.Rules {
				if r.Action == iptables.ActionDNAT && r.Protocol != "tcp" {
					t.Fatalf("mode=%s 链 %s：DNAT 规则缺少 -p tcp: %+v", mode, c.Name, r)
				}
				if r.Action == iptables.ActionReject && r.Protocol != "tcp" {
					t.Fatalf("mode=%s 链 %s：REJECT 规则缺少 -p tcp: %+v", mode, c.Name, r)
				}
			}
		}
	}
}

func TestBuildPlanEnforce(t *testing.T) {
	plan, err := BuildPlan(opts(policymodel.ModeEnforce), []ResolvedTarget{target()})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}

	natMain, ok := chain(plan, iptables.TableNat, "EGRESS-PROXY")
	if !ok {
		t.Fatal("缺少 nat 主链")
	}
	// 前三条固定是代理节点、回环、排除网段
	if len(natMain.Rules) != 3+2 {
		t.Fatalf("nat 主链规则数不对: %d", len(natMain.Rules))
	}
	if natMain.Rules[0].DstPrefix != "10.238.29.6/32" || natMain.Rules[0].Action != iptables.ActionReturn {
		t.Fatalf("首条规则应为代理节点的 RETURN: %+v", natMain.Rules[0])
	}
	if natMain.Rules[2].DstPrefix != "10.96.0.0/12" {
		t.Fatalf("第三条应为排除网段: %+v", natMain.Rules[2])
	}
	if natMain.Rules[3].Action != iptables.ActionJump || !strings.HasPrefix(natMain.Rules[3].JumpTarget, "EGRESS-PROXY-T-") {
		t.Fatalf("第四条应为目标跳转: %+v", natMain.Rules[3])
	}

	natSubName := target().NatChain("EGRESS-PROXY")
	natSub, ok := chain(plan, iptables.TableNat, natSubName)
	if !ok {
		t.Fatalf("缺少子链 %s", natSubName)
	}
	if len(natSub.Rules) != 2 {
		t.Fatalf("每个授权源一条 DNAT，期望 2 条，实际 %d", len(natSub.Rules))
	}
	for _, r := range natSub.Rules {
		if r.Action != iptables.ActionDNAT || r.ToDestination != "10.238.29.6:20001" {
			t.Fatalf("DNAT 规则不对: %+v", r)
		}
		// 没有 -p tcp 时 iptables 会拒绝 --to-destination 带端口的 DNAT（退出码 2），
		// 这是线上真实踩过的坑，必须有断言守住
		if r.Protocol != "tcp" {
			t.Fatalf("DNAT 规则必须带 -p tcp: %+v", r)
		}
	}
	if natSub.Rules[0].SrcPrefix != "10.244.5.7/32" {
		t.Fatalf("源地址未规范化: %+v", natSub.Rules[0])
	}

	denyMain, ok := chain(plan, iptables.TableFilter, "EGRESS-PROXY-DENY")
	if !ok {
		t.Fatal("缺少拒绝主链")
	}
	if denyMain.Rules[0].SrcPrefix != "10.238.29.6/32" || denyMain.Rules[0].Action != iptables.ActionReturn {
		t.Fatalf("拒绝链首条应为代理节点出站的 RETURN: %+v", denyMain.Rules[0])
	}

	denySubName := target().DenyChain("EGRESS-PROXY")
	denySub, ok := chain(plan, iptables.TableFilter, denySubName)
	if !ok {
		t.Fatalf("缺少拒绝子链 %s", denySubName)
	}
	last := denySub.Rules[len(denySub.Rules)-1]
	if last.Action != iptables.ActionReject || last.RejectWith != "tcp-reset" {
		t.Fatalf("末条应为 REJECT tcp-reset: %+v", last)
	}
	if len(denySub.Rules) != 3 {
		t.Fatalf("拒绝子链应为 2 条白名单 RETURN + 1 条兜底 REJECT，实际 %d", len(denySub.Rules))
	}

	// 跳转：nat PREROUTING/OUTPUT + filter FORWARD/OUTPUT，且都要置顶
	if len(plan.Jumps) != 4 {
		t.Fatalf("跳转数应为 4，实际 %d: %+v", len(plan.Jumps), plan.Jumps)
	}
	for _, j := range plan.Jumps {
		if j.Position != 1 {
			t.Fatalf("跳转必须置顶（避免被 CNI 规则抢先）: %+v", j)
		}
	}
}

func TestBuildPlanEmptySourcesIsFailClosed(t *testing.T) {
	tgt := target()
	tgt.AllowSources = nil

	plan, err := BuildPlan(opts(policymodel.ModeEnforce), []ResolvedTarget{tgt})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	natSub, ok := chain(plan, iptables.TableNat, tgt.NatChain("EGRESS-PROXY"))
	if !ok {
		t.Fatal("子链必须存在（空子链 = 谁都不许）")
	}
	if len(natSub.Rules) != 0 {
		t.Fatalf("没有授权源时子链必须为空，实际 %+v", natSub.Rules)
	}
	denySub, ok := chain(plan, iptables.TableFilter, tgt.DenyChain("EGRESS-PROXY"))
	if !ok {
		t.Fatal("缺少拒绝子链")
	}
	if len(denySub.Rules) != 1 || denySub.Rules[0].Action != iptables.ActionReject {
		t.Fatalf("没有授权源时应直接 REJECT 所有人: %+v", denySub.Rules)
	}
}

func TestBuildPlanObserveUsesLog(t *testing.T) {
	plan, err := BuildPlan(opts(policymodel.ModeObserve), []ResolvedTarget{target()})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	// 观察模式：nat 不做源匹配（保持旧行为），拒绝链只记日志
	natSub, _ := chain(plan, iptables.TableNat, target().NatChain("EGRESS-PROXY"))
	if len(natSub.Rules) != 1 || natSub.Rules[0].SrcPrefix != "" {
		t.Fatalf("观察模式不应按源匹配: %+v", natSub.Rules)
	}
	denySub, _ := chain(plan, iptables.TableFilter, target().DenyChain("EGRESS-PROXY"))
	last := denySub.Rules[len(denySub.Rules)-1]
	if last.Action != iptables.ActionLog {
		t.Fatalf("观察模式末条应为 LOG: %+v", last)
	}
	if !strings.HasPrefix(last.LogPrefix, "egp-would-deny") {
		t.Fatalf("LOG 前缀不对: %q", last.LogPrefix)
	}
}

func TestBuildPlanDisabledHasNoDenyChain(t *testing.T) {
	plan, err := BuildPlan(opts(policymodel.ModeDisabled), []ResolvedTarget{target()})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	if _, ok := chain(plan, iptables.TableFilter, "EGRESS-PROXY-DENY"); ok {
		t.Fatal("disabled 模式不应创建拒绝链")
	}
	for _, j := range plan.Jumps {
		if j.Table == iptables.TableFilter {
			t.Fatalf("disabled 模式不应有 filter 跳转: %+v", j)
		}
	}
	natSub, _ := chain(plan, iptables.TableNat, target().NatChain("EGRESS-PROXY"))
	if len(natSub.Rules) != 1 || natSub.Rules[0].SrcPrefix != "" {
		t.Fatalf("disabled 模式应为无源匹配的 DNAT: %+v", natSub.Rules)
	}
}

func TestBuildPlanIncludeOutputFalse(t *testing.T) {
	o := opts(policymodel.ModeEnforce)
	o.IncludeOutput = false
	plan, err := BuildPlan(o, []ResolvedTarget{target()})
	if err != nil {
		t.Fatalf("生成计划失败: %v", err)
	}
	for _, j := range plan.Jumps {
		if j.Parent == "OUTPUT" {
			t.Fatalf("代理节点不应挂 OUTPUT 跳转: %+v", j)
		}
	}
}

func TestBuildPlanChainNameTooLong(t *testing.T) {
	o := opts(policymodel.ModeEnforce)
	o.ChainName = "EGRESS-PROXY-VERY-LONG"
	if _, err := BuildPlan(o, nil); err == nil {
		t.Fatal("过长的链名应报错")
	}
}

func TestBuildPlanRejectsInvalidProxyIP(t *testing.T) {
	o := opts(policymodel.ModeEnforce)
	o.ProxyIP = net.ParseIP("fd00::1")
	if _, err := BuildPlan(o, nil); err == nil {
		t.Fatal("IPv6 代理地址应报错")
	}
}

func TestChainNamesFitLimit(t *testing.T) {
	tgt := target()
	for _, name := range []string{
		tgt.NatChain("EGRESS-PROXY"),
		tgt.DenyChain("EGRESS-PROXY"),
		"EGRESS-PROXY-DENY",
	} {
		if len(name) > iptables.MaxChainNameLen {
			t.Fatalf("链名 %q 长度 %d 超过上限 %d", name, len(name), iptables.MaxChainNameLen)
		}
	}
	if MaxBaseChainLen() != 14 {
		t.Fatalf("MaxBaseChainLen 期望 14，实际 %d", MaxBaseChainLen())
	}
}
