// Package policymodel 定义「四元组」出网流量管控策略：
// payload（负载身份）+ 目标域名/IP + 目标端口 + 代理端口
//
// 策略的唯一事实来源是控制器（egress-proxy-controller 的 WebUI / REST API）
// 各节点的 redirect-agent 通过 /api/v1/compiled 拉取「按节点过滤并展开」后的
// 结果（Compiled），再翻译成 iptables 规则
//
// 不变量（保证「未配置即拒绝」是结构性的，而不是额外分支）：
//   - 没有授权的 (payload, target) 配对，就不会有任何源地址进入 allowSources；
//   - 规则层表现为「每个 target 一条子链，子链为空 → 不 DNAT → 落到拒绝链」，
//     因此空集合天然等于「谁都不许」；
//   - 策略变更只改变 allowSources 的内容，不改变规则结构（不会引起规则抖动）
package policymodel

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"

	egconfig "egress-proxy/config"
	"egress-proxy/internal/i18n"
)

// Mode 是策略执行模式
type Mode string

const (
	// ModeDisabled 直通：所有 Pod 的命中流量都被代理，不做源地址匹配，也不拒绝
	// 用于「关闭四元组管控」的兼容状态（等价于改造前的行为）
	ModeDisabled Mode = "disabled"
	// ModeObserve 观察：仍然全部代理，但把「按策略本应被拒」的连接记日志而不阻断
	ModeObserve Mode = "observe"
	// ModeEnforce 强制：只有被授权的源地址走代理，其余对目标直连的尝试被显式拒绝
	ModeEnforce Mode = "enforce"
)

// Valid 判断模式是否合法
func (m Mode) Valid() bool {
	switch m {
	case ModeDisabled, ModeObserve, ModeEnforce:
		return true
	}
	return false
}

// String 实现 fmt.Stringer
func (m Mode) String() string { return string(m) }

// WorkloadKind 是支持「按工作负载名」选取的 Kubernetes 工作负载类型
type WorkloadKind string

const (
	// WorkloadDeployment 对应 apps/v1 Deployment
	WorkloadDeployment WorkloadKind = "Deployment"
	// WorkloadStatefulSet 对应 apps/v1 StatefulSet
	WorkloadStatefulSet WorkloadKind = "StatefulSet"
	// WorkloadDaemonSet 对应 apps/v1 DaemonSet
	WorkloadDaemonSet WorkloadKind = "DaemonSet"
)

// Valid 判断工作负载类型是否受支持
func (k WorkloadKind) Valid() bool {
	switch k {
	case WorkloadDeployment, WorkloadStatefulSet, WorkloadDaemonSet:
		return true
	}
	return false
}

// WorkloadRef 是「按工作负载名」建立的负载引用
//
// 它只描述选取方式：控制器用只读权限把工作负载的 spec.selector.matchLabels
// 解析出来写回 Payload.MatchLabels，因此策略文件里始终能看到该负载最终选中的标签
type WorkloadRef struct {
	Kind string `json:"kind" yaml:"kind"`
	Name string `json:"name" yaml:"name"`
}

// Payload 是一个负载定义，即四元组的第一元
//
// 两种选取方式（最终都归结为「命名空间 + 一组标签」）：
//   - 按工作负载名：Workload 非空，由控制器解析成 MatchLabels；
//   - 按标签选择器：直接给出 MatchLabels
//
// 匹配规则：Pod 的命名空间命中 Namespaces（为空表示所有命名空间），
// 且 Pod 标签包含 MatchLabels 中的全部键值
type Payload struct {
	Name        string            `json:"name" yaml:"name"`
	Namespaces  []string          `json:"namespaces,omitempty" yaml:"namespaces,omitempty"`
	Workload    *WorkloadRef      `json:"workload,omitempty" yaml:"workload,omitempty"`
	MatchLabels map[string]string `json:"matchLabels,omitempty" yaml:"matchLabels,omitempty"`
}

// Clone 返回深拷贝
func (p Payload) Clone() Payload {
	out := p
	out.Namespaces = append([]string(nil), p.Namespaces...)
	if p.Workload != nil {
		w := *p.Workload
		out.Workload = &w
	}
	if p.MatchLabels != nil {
		out.MatchLabels = make(map[string]string, len(p.MatchLabels))
		for k, v := range p.MatchLabels {
			out.MatchLabels[k] = v
		}
	}
	return out
}

// Matches 判断给定 Pod 是否属于该负载
func (p Payload) Matches(pod Pod) bool {
	if len(p.Namespaces) > 0 {
		ok := false
		for _, ns := range p.Namespaces {
			if ns == pod.Namespace {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	for k, v := range p.MatchLabels {
		if got, ok := pod.Labels[k]; !ok || got != v {
			return false
		}
	}
	return true
}

// Target 是一个外部目标，四元组的第二、三、四元
type Target struct {
	Host      string `json:"host" yaml:"host"`
	Port      int    `json:"port" yaml:"port"`
	ProxyPort int    `json:"proxyPort" yaml:"proxyPort"`
}

// Key 返回 host:port，作为 target 在策略内的唯一标识
func (t Target) Key() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Addr 返回原始目标的 host:port（供 forwarder 拨号）
func (t Target) Addr() string { return t.Key() }

// Grant 把 payload 与 target 关联起来，凑齐四元组
type Grant struct {
	Payload string `json:"payload" yaml:"payload"`
	Target  string `json:"target" yaml:"target"`
}

// Policy 是完整策略
type Policy struct {
	Mode     Mode      `json:"mode" yaml:"mode"`
	Payloads []Payload `json:"payloads" yaml:"payloads"`
	Targets  []Target  `json:"targets" yaml:"targets"`
	Grants   []Grant   `json:"grants" yaml:"grants"`
}

// Clone 返回深拷贝
func (p *Policy) Clone() *Policy {
	if p == nil {
		return &Policy{Mode: ModeDisabled}
	}
	out := &Policy{
		Mode:     p.Mode,
		Payloads: make([]Payload, 0, len(p.Payloads)),
		Targets:  append([]Target(nil), p.Targets...),
		Grants:   append([]Grant(nil), p.Grants...),
	}
	for _, pl := range p.Payloads {
		out.Payloads = append(out.Payloads, pl.Clone())
	}
	return out
}

var (
	payloadNameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	nsLabelRe      = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	workloadNameRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	labelKeyRe     = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
)

// Normalize 就地整理策略：去空白、补默认、排序、去重
// 它不做合法性判断（那是 Validate 的职责），但保证后续比较与生成规则是稳定的
func (p *Policy) Normalize() {
	if p.Mode == "" {
		p.Mode = ModeDisabled
	}

	payloads := make([]Payload, 0, len(p.Payloads))
	seenPayload := make(map[string]struct{}, len(p.Payloads))
	for _, pl := range p.Payloads {
		pl.Name = strings.TrimSpace(pl.Name)
		if pl.Name == "" {
			continue
		}
		if _, dup := seenPayload[pl.Name]; dup {
			continue
		}
		seenPayload[pl.Name] = struct{}{}

		pl.Namespaces = normalizeStringList(pl.Namespaces)
		if pl.Workload != nil {
			w := WorkloadRef{
				Kind: strings.TrimSpace(pl.Workload.Kind),
				Name: strings.TrimSpace(pl.Workload.Name),
			}
			if w.Kind == "" || w.Name == "" {
				pl.Workload = nil
			} else {
				pl.Workload = &w
			}
		}
		if len(pl.MatchLabels) == 0 {
			pl.MatchLabels = nil
		} else {
			labels := make(map[string]string, len(pl.MatchLabels))
			for k, v := range pl.MatchLabels {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				labels[k] = strings.TrimSpace(v)
			}
			if len(labels) == 0 {
				labels = nil
			}
			pl.MatchLabels = labels
		}
		payloads = append(payloads, pl)
	}
	sort.Slice(payloads, func(i, j int) bool { return payloads[i].Name < payloads[j].Name })
	p.Payloads = payloads

	targets := make([]Target, 0, len(p.Targets))
	seenTarget := make(map[string]struct{}, len(p.Targets))
	for _, t := range p.Targets {
		t.Host = strings.TrimSpace(t.Host)
		if t.Host == "" {
			continue
		}
		key := t.Key()
		if _, dup := seenTarget[key]; dup {
			continue
		}
		seenTarget[key] = struct{}{}
		targets = append(targets, t)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Host != targets[j].Host {
			return targets[i].Host < targets[j].Host
		}
		return targets[i].Port < targets[j].Port
	})
	p.Targets = targets

	grants := make([]Grant, 0, len(p.Grants))
	seenGrant := make(map[string]struct{}, len(p.Grants))
	for _, g := range p.Grants {
		g.Payload = strings.TrimSpace(g.Payload)
		g.Target = strings.TrimSpace(g.Target)
		if g.Payload == "" || g.Target == "" {
			continue
		}
		key := g.Payload + "\x00" + g.Target
		if _, dup := seenGrant[key]; dup {
			continue
		}
		seenGrant[key] = struct{}{}
		grants = append(grants, g)
	}
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].Target != grants[j].Target {
			return grants[i].Target < grants[j].Target
		}
		return grants[i].Payload < grants[j].Payload
	})
	p.Grants = grants
}

func normalizeStringList(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// Validate 返回全部校验错误；完全合法时返回 nil
// 结果固定为中文；需要指定语言时用 ValidateLang
func (p *Policy) Validate() error {
	return p.ValidateLang(i18n.ZH)
}

// ValidateLang 按语言返回全部校验错误；完全合法时返回 nil
func (p *Policy) ValidateLang(l i18n.Lang) error {
	var errs []string
	add := func(m i18n.Msg, args ...interface{}) {
		errs = append(errs, m.S(l, args...))
	}

	if !p.Mode.Valid() {
		add(msgModeInvalid, string(p.Mode))
	}

	seenPayload := make(map[string]int, len(p.Payloads))
	for i, pl := range p.Payloads {
		where := fmt.Sprintf("payloads[%d]", i)
		if !payloadNameRe.MatchString(pl.Name) {
			add(msgPayloadNameInvalid, where, pl.Name, payloadNameRe.String())
		} else if prev, dup := seenPayload[pl.Name]; dup {
			add(msgPayloadNameDuplicate, where, pl.Name, prev)
		} else {
			seenPayload[pl.Name] = i
		}
		if pl.Workload != nil {
			if !WorkloadKind(pl.Workload.Kind).Valid() {
				add(msgWorkloadKindInvalid, where, pl.Name, pl.Workload.Kind)
			}
			if !workloadNameRe.MatchString(pl.Workload.Name) || len(pl.Workload.Name) > 253 {
				add(msgWorkloadNameInvalid, where, pl.Name, pl.Workload.Name)
			}
			if len(pl.Namespaces) != 1 {
				add(msgWorkloadNamespaceCount, where, pl.Name, len(pl.Namespaces))
			}
			if len(pl.MatchLabels) == 0 {
				add(msgWorkloadSelectorUnresolved,
					where, pl.Name, pl.Workload.Kind, pl.Workload.Name)
			}
		} else if len(pl.Namespaces) == 0 && len(pl.MatchLabels) == 0 {
			add(msgPayloadSelectorEmpty, where, pl.Name)
		}
		for j, ns := range pl.Namespaces {
			if !nsLabelRe.MatchString(ns) || len(ns) > 63 {
				add(msgNamespaceInvalid, where, pl.Name, j, ns)
			}
		}
		for k, v := range pl.MatchLabels {
			if !labelKeyRe.MatchString(k) || len(k) > 63 {
				add(msgMatchLabelKeyInvalid, where, pl.Name, k)
			}
			if v != "" && (!labelKeyRe.MatchString(v) || len(v) > 63) {
				add(msgMatchLabelValueInvalid, where, pl.Name, k, v)
			}
		}
	}

	seenTarget := make(map[string]int, len(p.Targets))
	seenProxyPort := make(map[int]string, len(p.Targets))
	for i, t := range p.Targets {
		where := fmt.Sprintf("targets[%d]", i)
		if err := egconfig.ValidateHostLang(l, t.Host); err != nil {
			add(msgHostInvalid, where, t.Host, err)
		}
		if err := egconfig.ValidatePortLang(l, t.Port); err != nil {
			add(msgTargetPortInvalid, where, t.Host, err)
		}
		if err := egconfig.ValidatePortLang(l, t.ProxyPort); err != nil {
			add(msgTargetProxyPortInvalid, where, t.Host, err)
		}
		if t.Host != "" && t.Port > 0 {
			key := t.Key()
			if prev, dup := seenTarget[key]; dup {
				add(msgTargetDuplicate, where, key, prev)
			} else {
				seenTarget[key] = i
			}
		}
		if t.ProxyPort > 0 {
			if prev, dup := seenProxyPort[t.ProxyPort]; dup {
				add(msgProxyPortDuplicate, where, t.ProxyPort, prev)
			} else {
				seenProxyPort[t.ProxyPort] = t.Key()
			}
		}
	}

	seenGrant := make(map[string]int, len(p.Grants))
	for i, g := range p.Grants {
		where := fmt.Sprintf("grants[%d]", i)
		if _, ok := seenPayload[g.Payload]; !ok {
			add(msgGrantPayloadMissing, where, g.Payload)
		}
		if _, ok := seenTarget[g.Target]; !ok {
			add(msgGrantTargetMissing, where, g.Target)
		}
		key := g.Payload + "\x00" + g.Target
		if prev, dup := seenGrant[key]; dup {
			add(msgGrantDuplicate, where, g.Payload, g.Target, prev)
		} else {
			seenGrant[key] = i
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return msgValidateFailed.E(l, strings.Join(errs, "\n  - "))
}

// Warnings 返回「合法但值得提醒」的事项，用于 WebUI 展示
// 结果固定为中文；需要指定语言时用 WarningsLang
func (p *Policy) Warnings() []string {
	return p.WarningsLang(i18n.ZH)
}

// WarningsLang 按语言返回「合法但值得提醒」的事项，用于 WebUI 展示
func (p *Policy) WarningsLang(l i18n.Lang) []string {
	var out []string
	for _, pl := range p.Payloads {
		if len(pl.MatchLabels) == 0 {
			out = append(out, msgWarnPayloadNoMatchLabels.S(l, pl.Name))
		}
		if len(pl.Namespaces) == 0 {
			out = append(out, msgWarnPayloadNoNamespaces.S(l, pl.Name))
		}
	}

	if p.Mode == ModeEnforce || p.Mode == ModeObserve {
		granted := make(map[string]struct{}, len(p.Grants))
		for _, g := range p.Grants {
			granted[g.Target] = struct{}{}
		}
		for _, t := range p.Targets {
			if _, ok := granted[t.Key()]; !ok {
				out = append(out, msgWarnTargetNoGrants.S(l, t.Key()))
			}
		}
	}
	return out
}

// PayloadByName 返回指定名字的负载定义
func (p *Policy) PayloadByName(name string) (Payload, bool) {
	for _, pl := range p.Payloads {
		if pl.Name == name {
			return pl, true
		}
	}
	return Payload{}, false
}

// TargetByKey 返回指定 host:port 的目标定义
func (p *Policy) TargetByKey(key string) (Target, bool) {
	for _, t := range p.Targets {
		if t.Key() == key {
			return t, true
		}
	}
	return Target{}, false
}

// Allows 判断 (payload, target) 是否已授权
func (p *Policy) Allows(payload, targetKey string) bool {
	for _, g := range p.Grants {
		if g.Payload == payload && g.Target == targetKey {
			return true
		}
	}
	return false
}

// ToggleGrant 增删一条授权，返回是否发生变化
func (p *Policy) ToggleGrant(payload, targetKey string, allowed bool) bool {
	if _, ok := p.PayloadByName(payload); !ok {
		return false
	}
	if _, ok := p.TargetByKey(targetKey); !ok {
		return false
	}

	idx := -1
	for i, g := range p.Grants {
		if g.Payload == payload && g.Target == targetKey {
			idx = i
			break
		}
	}
	switch {
	case allowed && idx < 0:
		p.Grants = append(p.Grants, Grant{Payload: payload, Target: targetKey})
		p.Normalize()
		return true
	case !allowed && idx >= 0:
		p.Grants = append(p.Grants[:idx], p.Grants[idx+1:]...)
		return true
	}
	return false
}

// PayloadNames 返回按名称排序的 payload 名列表
func (p *Policy) PayloadNames() []string {
	out := make([]string, 0, len(p.Payloads))
	for _, pl := range p.Payloads {
		out = append(out, pl.Name)
	}
	sort.Strings(out)
	return out
}

// Pod 是策略解析所需的 Pod 视图（由控制器从 API Server 读取）
type Pod struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	NodeName  string            `json:"node"`
	IP        string            `json:"ip"`
	Labels    map[string]string `json:"-"`
}

// Member 是一个命中某个 payload 的 Pod 实例
type Member struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Node      string `json:"node"`
	IP        string `json:"ip"`
}

// Index 是 Pod 索引，支持按 payload 解析成员
type Index struct {
	pods []Pod
}

// NewIndex 构建索引，自动丢弃没有可用 IPv4 的 Pod
func NewIndex(pods []Pod) *Index {
	kept := make([]Pod, 0, len(pods))
	for _, pod := range pods {
		ip := strings.TrimSpace(pod.IP)
		if ip == "" || ip == "None" || net.ParseIP(ip) == nil {
			continue
		}
		pod.IP = ip
		kept = append(kept, pod)
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].Namespace != kept[j].Namespace {
			return kept[i].Namespace < kept[j].Namespace
		}
		return kept[i].Name < kept[j].Name
	})
	return &Index{pods: kept}
}

// Len 返回索引内的 Pod 数
func (idx *Index) Len() int {
	if idx == nil {
		return 0
	}
	return len(idx.pods)
}

// Members 返回命中 payload 的 Pod 成员；node 非空时只保留该节点上的 Pod
func (idx *Index) Members(p Payload, node string) []Member {
	if idx == nil {
		return nil
	}
	out := make([]Member, 0, 4)
	for _, pod := range idx.pods {
		if node != "" && pod.NodeName != node {
			continue
		}
		if !p.Matches(pod) {
			continue
		}
		out = append(out, Member{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			Node:      pod.NodeName,
			IP:        pod.IP,
		})
	}
	return out
}

// MembersMap 返回「payload 名 → 成员列表」，用于 WebUI 展示
func (idx *Index) MembersMap(p *Policy) map[string][]Member {
	out := make(map[string][]Member, len(p.Payloads))
	for _, pl := range p.Payloads {
		members := idx.Members(pl, "")
		if members == nil {
			members = []Member{}
		}
		out[pl.Name] = members
	}
	return out
}

// CompiledTarget 是某个目标最终生效的源地址集合
type CompiledTarget struct {
	Host      string `json:"host"`
	Port      int    `json:"port"`
	ProxyPort int    `json:"proxyPort"`
	// AllowSources 是被授权访问该目标的源地址（IPv4 或 CIDR），已排序去重
	// 为空表示「谁都不许」
	AllowSources []string `json:"allowSources"`
}

// Compiled 是下发给节点 / 转发器的编译结果
type Compiled struct {
	Mode       Mode             `json:"mode"`
	Generation int64            `json:"generation"`
	Targets    []CompiledTarget `json:"targets"`
}

// TargetByKey 返回指定目标的编译结果
func (c *Compiled) TargetByKey(key string) (CompiledTarget, bool) {
	for _, t := range c.Targets {
		if t.Key() == key {
			return t, true
		}
	}
	return CompiledTarget{}, false
}

// Key 返回 host:port
func (t CompiledTarget) Key() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Compile 把策略解析成「每个目标的允许源集合」
// node 非空时只统计该节点上的 Pod（节点侧 agent 用）；为空时统计全集群（WebUI 预览用）
func Compile(p *Policy, idx *Index, node string) *Compiled {
	if p == nil {
		return &Compiled{Mode: ModeDisabled}
	}
	out := &Compiled{Mode: p.Mode, Targets: make([]CompiledTarget, 0, len(p.Targets))}
	for _, t := range p.Targets {
		key := t.Key()
		var sources []string
		for _, g := range p.Grants {
			if g.Target != key {
				continue
			}
			pl, ok := p.PayloadByName(g.Payload)
			if !ok {
				continue
			}
			for _, m := range idx.Members(pl, node) {
				sources = append(sources, m.IP)
			}
		}
		out.Targets = append(out.Targets, CompiledTarget{
			Host:         t.Host,
			Port:         t.Port,
			ProxyPort:    t.ProxyPort,
			AllowSources: SortSources(sources),
		})
	}
	return out
}

// SourcesMap 返回「targetKey → 允许源列表」，供 WebUI 展示
func SourcesMap(c *Compiled) map[string][]string {
	out := make(map[string][]string, len(c.Targets))
	for _, t := range c.Targets {
		sources := t.AllowSources
		if sources == nil {
			sources = []string{}
		}
		out[t.Key()] = sources
	}
	return out
}

// NormalizeSource 校验并规范化一个源地址：单 IP 补成 /32，CIDR 取规范形式
// 错误文案固定为中文；需要指定语言时用 NormalizeSourceLang
func NormalizeSource(s string) (string, error) {
	return NormalizeSourceLang(i18n.ZH, s)
}

// NormalizeSourceLang 按语言返回源地址规范化结果与错误
func NormalizeSourceLang(l i18n.Lang, s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", msgSourceEmpty.E(l)
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return "", msgSourceNotIPOrCIDR.E(l)
		}
		if ip.To4() == nil {
			return "", msgSourceIPv4Only.E(l)
		}
		return ip.To4().String() + "/32", nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return "", msgSourceNotCIDR.E(l)
	}
	if ipnet.IP.To4() == nil {
		return "", msgSourceIPv4CIDROnly.E(l)
	}
	return ipnet.String(), nil
}

// SortSources 对源地址列表做规范化、去重与稳定排序（IP 在前、CIDR 在后，各自按数值序）
func SortSources(in []string) []string {
	type entry struct {
		text  string
		ip    net.IP
		isNet bool
	}
	entries := make([]entry, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		normalized, err := NormalizeSource(raw)
		if err != nil {
			// 非法项直接跳过：策略校验阶段已拦截，这里只做兜底
			continue
		}
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		ip, _, _ := net.ParseCIDR(normalized)
		entries = append(entries, entry{
			text:  normalized,
			ip:    ip.To4(),
			isNet: !strings.HasSuffix(normalized, "/32"),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].isNet != entries[j].isNet {
			return !entries[i].isNet
		}
		return bytesLess(entries[i].ip, entries[j].ip)
	})
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.text)
	}
	return out
}

func bytesLess(a, b net.IP) bool {
	for k := 0; k < len(a) && k < len(b); k++ {
		if a[k] != b[k] {
			return a[k] < b[k]
		}
	}
	return false
}

// Workload 是一个可被「按名选取」的 Kubernetes 工作负载
// 由控制器从 apps/v1 读取，用于 WebUI 下拉与标签解析，本身不参与规则生成
type Workload struct {
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Selector  map[string]string `json:"selector,omitempty"`
	// Ready 是就绪副本描述（如 "2/2"），仅供 WebUI 展示
	Ready string `json:"ready,omitempty"`
}

// Key 返回 kind/namespace/name，作为工作负载的唯一标识
func (w Workload) Key() string {
	return w.Kind + "/" + w.Namespace + "/" + w.Name
}

// Resolve 把「按工作负载名」的负载解析成具体的标签选择器
//
// 已经是标签模式（MatchLabels 非空）或没有 Workload 引用时原样返回
// 解析失败必须返回错误：静默退化成「空选择器」会把负载变成匹配命名空间内全部 Pod
// 错误文案固定为中文；需要指定语言时用 ResolveLang
func (p Payload) Resolve(list []Workload) (Payload, error) {
	return p.ResolveLang(i18n.ZH, list)
}

// ResolveLang 按语言返回「按工作负载名」解析出的标签选择器
func (p Payload) ResolveLang(l i18n.Lang, list []Workload) (Payload, error) {
	if p.Workload == nil || len(p.MatchLabels) > 0 {
		return p, nil
	}
	ns := ""
	if len(p.Namespaces) > 0 {
		ns = p.Namespaces[0]
	}
	want := WorkloadRef{Kind: strings.TrimSpace(p.Workload.Kind), Name: strings.TrimSpace(p.Workload.Name)}
	for _, w := range list {
		if w.Kind != want.Kind || w.Name != want.Name {
			continue
		}
		if ns != "" && w.Namespace != ns {
			continue
		}
		if len(w.Selector) == 0 {
			return p, msgResolveWorkloadNoSelector.E(l, w.Namespace, w.Name)
		}
		out := p.Clone()
		out.MatchLabels = make(map[string]string, len(w.Selector))
		for k, v := range w.Selector {
			out.MatchLabels[k] = v
		}
		return out, nil
	}
	return p, msgResolveWorkloadNotFound.E(l, want.Kind, ns, want.Name)
}
