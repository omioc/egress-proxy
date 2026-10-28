// Package iptables 管理 egress-proxy 自己创建的 iptables 链
//
// 设计要点：
//   - 只增删自己管理的链：<chainName> 及其派生链（<chainName>-T-<hash>、
//     <chainName>-DENY、<chainName>-DENY-T-<hash>），绝不清空或覆盖其他链，
//     也不影响 kube-proxy / Calico 的规则
//   - 每次同步先与内核现状比较（规范化后逐链比对），完全一致时一个写操作都不做，
//     避免策略轮询引起规则抖动
//   - 规则通过 iptables-restore --noflush 一次性批量写入，幂等；失败回退为逐条追加
//   - 跳转规则单独维护：先检查是否存在且位置正确，再决定插入还是重建
//   - 清理顺序固定：先摘掉内建链上的跳转 → 清空各托管链 → 删链（主链优先），
//     顺序错了 -X 会因链仍被引用而失败
package iptables

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"egress-proxy/config"
	"egress-proxy/internal/i18n"
)

// 支持的 iptables 表
const (
	TableNat    = "nat"
	TableFilter = "filter"
)

// DefaultComment 是写在自己规则上的注释前缀，便于识别与排障
const DefaultComment = "egress-proxy"

// DefaultWaitSeconds 是 xtables 锁等待秒数（与 kube-proxy 并发操作时避免报错）
const DefaultWaitSeconds = 5

// ChainName is kept for compatibility with existing callers.
//
// Deprecated: 请使用 config.DefaultChainName
const ChainName = config.DefaultChainName

// MaxChainNameLen 是 iptables 链名长度上限
const MaxChainNameLen = 28

// Action 是规则的动作
type Action string

const (
	ActionReturn Action = "RETURN"
	ActionDNAT   Action = "DNAT"
	ActionReject Action = "REJECT"
	ActionLog    Action = "LOG"
	ActionJump   Action = "JUMP"
)

// builtinChains 是 iptables 内建链，不允许创建同名链
var builtinChains = map[string]struct{}{
	"PREROUTING":  {},
	"INPUT":       {},
	"FORWARD":     {},
	"OUTPUT":      {},
	"POSTROUTING": {},
}

// Rule 是链内的一条规则；零值字段表示不参与匹配
type Rule struct {
	// SrcPrefix 是源地址／网段匹配（例如 10.244.5.7/32 或 10.238.29.0/24）
	SrcPrefix string
	// DstPrefix 是目标地址／网段匹配
	DstPrefix string
	// Protocol 非空时生成 -p 匹配（当前只用 tcp）
	Protocol string
	// Port 非零时生成 --dport 匹配，要求 Protocol 非空
	Port int
	// Action 是动作
	Action Action
	// ToDestination 是 DNAT 目标（proxyIP:proxyPort）
	ToDestination string
	// JumpTarget 是 JUMP 目标链名
	JumpTarget string
	// LogPrefix 是 LOG 动作的前缀
	LogPrefix string
	// RejectWith 是 REJECT 的 --reject-with 参数，默认 tcp-reset
	RejectWith string
	// Comment 是规则注释（仅用于排障，不参与比较）
	Comment string
}

func (r Rule) rejectWith() string {
	if r.RejectWith != "" {
		return r.RejectWith
	}
	return "tcp-reset"
}

// args 返回不带 "-A <chain>" 的规则参数，顺序尽量贴近 iptables-save 风格
func (r Rule) args() []string {
	args := make([]string, 0, 16)
	if r.SrcPrefix != "" {
		args = append(args, "-s", r.SrcPrefix)
	}
	if r.DstPrefix != "" {
		args = append(args, "-d", r.DstPrefix)
	}
	if r.Protocol != "" {
		args = append(args, "-p", r.Protocol)
		if r.Port > 0 {
			args = append(args, "--dport", strconv.Itoa(r.Port))
		}
	}
	if r.Comment != "" {
		args = append(args, "-m", "comment", "--comment", sanitizeComment(r.Comment))
	}
	switch r.Action {
	case ActionDNAT:
		args = append(args, "-j", "DNAT", "--to-destination", r.ToDestination)
	case ActionJump:
		args = append(args, "-j", r.JumpTarget)
	case ActionReject:
		args = append(args, "-j", "REJECT", "--reject-with", r.rejectWith())
	case ActionLog:
		args = append(args, "-j", "LOG", "--log-prefix", sanitizeLogPrefix(r.LogPrefix))
	case ActionReturn:
		args = append(args, "-j", "RETURN")
	default:
		args = append(args, "-j", string(r.Action))
	}
	return args
}

// canonical 返回用于漂移比较的规范化字符串（不含注释）
func (r Rule) canonical() string {
	parts := make([]string, 0, 8)
	if r.SrcPrefix != "" {
		parts = append(parts, "src="+normalizePrefix(r.SrcPrefix))
	}
	if r.DstPrefix != "" {
		parts = append(parts, "dst="+normalizePrefix(r.DstPrefix))
	}
	if r.Protocol != "" {
		parts = append(parts, "proto="+r.Protocol)
	}
	if r.Port > 0 {
		parts = append(parts, "dport="+strconv.Itoa(r.Port))
	}
	switch r.Action {
	case ActionDNAT:
		parts = append(parts, "dnat="+normalizeHostPort(r.ToDestination))
	case ActionJump:
		parts = append(parts, "jump="+r.JumpTarget)
	case ActionReject:
		parts = append(parts, "reject="+r.rejectWith())
	case ActionLog:
		parts = append(parts, "log="+strings.TrimSpace(r.LogPrefix))
	}
	parts = append(parts, "action="+string(r.Action))
	return strings.Join(parts, " ")
}

// Chain 是一条期望存在的链及其内容
type Chain struct {
	Table string
	Name  string
	Rules []Rule
}

// Jump 是把子链挂到内建链上的跳转规则
type Jump struct {
	Table  string
	Parent string
	Child  string
	// Position 为 1 表示插入到父链首位（必须抢在 CNI 的规则之前），0 表示追加
	Position int
}

// Plan 是一次完整同步的期望状态
type Plan struct {
	Chains []Chain
	Jumps  []Jump
}

// Tables 返回 Plan 涉及的、去重排序后的表名
func (p Plan) Tables() []string {
	seen := make(map[string]struct{}, 2)
	for _, c := range p.Chains {
		seen[c.Table] = struct{}{}
	}
	for _, j := range p.Jumps {
		seen[j.Table] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Validate 校验 Plan 的结构合法性
//
// 返回一条双语错误：Error() 给中文，i18n.Bilingual / S(i18n.EN) 给英文。
// 中英两套文案在同一轮循环里同时收集，保证两种语言的行数与顺序一致。
func (p Plan) Validate() error {
	var zhErrs, enErrs []string
	add := func(m i18n.Msg, args ...any) {
		zhErrs = append(zhErrs, m.S(i18n.ZH, args...))
		enErrs = append(enErrs, m.S(i18n.EN, args...))
	}
	// addCause 用于模板里内嵌原因（%v）的行：原因本身也是双语的，中英各取一份
	addCause := func(m i18n.Msg, cause error, args ...any) {
		causeZH, causeEN := i18n.Bilingual(cause)
		if causeEN == "" {
			causeEN = causeZH
		}
		zhErrs = append(zhErrs, m.S(i18n.ZH, append(append([]any{}, args...), causeZH)...))
		enErrs = append(enErrs, m.S(i18n.EN, append(append([]any{}, args...), causeEN)...))
	}

	known := make(map[string]struct{}, len(p.Chains))
	for i, c := range p.Chains {
		where := fmt.Sprintf("chains[%d]", i)
		if c.Table != TableNat && c.Table != TableFilter {
			add(msgPlanTableUnsupported, where, c.Table)
		}
		if err := validateChainName(c.Name); err != nil {
			addCause(msgPlanChainNameInvalid, err, where, c.Name)
		}
		key := c.Table + "/" + c.Name
		if _, dup := known[key]; dup {
			add(msgPlanChainDuplicate, where, key)
		}
		known[key] = struct{}{}
	}
	for i, c := range p.Chains {
		for k, r := range c.Rules {
			where := fmt.Sprintf("chains[%d](%s).rules[%d]", i, c.Name, k)
			if r.Action == ActionJump {
				if _, ok := known[c.Table+"/"+r.JumpTarget]; !ok {
					add(msgPlanJumpTargetMissing, where, r.JumpTarget)
				}
			}
			if r.Action == ActionDNAT && r.ToDestination == "" {
				add(msgPlanDNATMissingDest, where)
			}
			if r.Action == ActionDNAT && r.ToDestination != "" && r.Protocol == "" {
				// iptables 规定：--to-destination 带端口时必须先匹配协议，
				// 否则报 "Need TCP, UDP, SCTP or DCCP with port specification" 并退出码 2
				if _, port, err := net.SplitHostPort(r.ToDestination); err == nil && port != "" {
					add(msgPlanDNATPortNeedsProtocol, where, r.ToDestination)
				}
			}
			if r.Action == ActionReject && r.rejectWith() == "tcp-reset" && r.Protocol != "tcp" {
				add(msgPlanRejectResetNeedsTCP, where, r.Protocol)
			}
			if r.Port > 0 && r.Protocol == "" {
				add(msgPlanPortNeedsProtocol, where)
			}
			if r.Port < 0 || r.Port > 65535 {
				add(msgPlanPortOutOfRange, where, r.Port)
			}
			if r.SrcPrefix != "" {
				if _, err := normalizeCIDROrIP(r.SrcPrefix); err != nil {
					addCause(msgPlanSrcInvalid, err, where, r.SrcPrefix)
				}
			}
			if r.DstPrefix != "" {
				if _, err := normalizeCIDROrIP(r.DstPrefix); err != nil {
					addCause(msgPlanDstInvalid, err, where, r.DstPrefix)
				}
			}
		}
	}
	for i, j := range p.Jumps {
		where := fmt.Sprintf("jumps[%d]", i)
		if j.Table != TableNat && j.Table != TableFilter {
			add(msgPlanJumpTableUnsupported, where, j.Table)
		}
		if _, ok := builtinChains[j.Parent]; !ok {
			add(msgPlanParentNotBuiltin, where, j.Parent)
		}
		if _, ok := known[j.Table+"/"+j.Child]; !ok {
			add(msgPlanChildMissing, where, j.Child)
		}
		if j.Position < 0 || j.Position > 1 {
			add(msgPlanPositionInvalid, where, j.Position)
		}
	}
	if len(zhErrs) == 0 {
		return nil
	}
	return i18n.NewCoded(i18n.Msg{
		ZH: msgPlanInvalid.S(i18n.ZH) + "\n  - " + strings.Join(zhErrs, "\n  - "),
		EN: msgPlanInvalid.S(i18n.EN) + "\n  - " + strings.Join(enErrs, "\n  - "),
	})
}

func validateChainName(name string) error {
	if name == "" {
		return i18n.NewCoded(msgChainNameEmpty)
	}
	if len(name) > MaxChainNameLen {
		return i18n.NewCoded(msgChainNameTooLong, len(name), MaxChainNameLen)
	}
	if _, ok := builtinChains[name]; ok {
		return i18n.NewCoded(msgChainNameBuiltin)
	}
	if strings.HasPrefix(name, "-") {
		return i18n.NewCoded(msgChainNameLeadingDash)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return i18n.NewCoded(msgChainNameInvalidChar, string(r))
		}
	}
	return nil
}

// Runner 抽象命令执行，便于测试
type Runner interface {
	// Run 执行命令并返回 stdout+stderr
	Run(ctx context.Context, name string, args ...string) (string, error)
	// RunWithInput 执行命令并把 input 写入其标准输入
	RunWithInput(ctx context.Context, input string, name string, args ...string) (string, error)
}

// ExecRunner 是使用真实进程的 Runner 实现
type ExecRunner struct{}

// Run 执行命令
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// RunWithInput 执行命令并写入标准输入
func (ExecRunner) RunWithInput(ctx context.Context, input string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// Manager 负责托管链的创建、内容同步、跳转维护与清理
type Manager struct {
	binary        string
	restoreBinary string
	chain         string
	comment       string
	waitSeconds   string
	runner        Runner
	log           *slog.Logger
}

// New 创建使用真实命令执行的 Manager
func New(binary, chain string, logger *slog.Logger) *Manager {
	return NewWithRunner(ExecRunner{}, binary, chain, logger)
}

// NewWithRunner 创建可注入 Runner 的 Manager（测试用）
func NewWithRunner(runner Runner, binary, chain string, logger *slog.Logger) *Manager {
	if binary == "" {
		binary = config.DefaultIptablesBinary
	}
	if chain == "" {
		chain = config.DefaultChainName
	}
	if logger == nil {
		logger = slog.Default()
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	return &Manager{
		binary:        binary,
		restoreBinary: deriveBinary(binary, "iptables-restore"),
		chain:         chain,
		comment:       DefaultComment,
		waitSeconds:   strconv.Itoa(DefaultWaitSeconds),
		runner:        runner,
		log:           logger,
	}
}

// Chain 返回主链名
func (m *Manager) Chain() string { return m.chain }

// Binary 返回使用的 iptables 可执行文件名
func (m *Manager) Binary() string { return m.binary }

// Managed 判断某个链名是否由本组件管理
func (m *Manager) Managed(name string) bool {
	return name == m.chain || strings.HasPrefix(name, m.chain+"-")
}

// deriveBinary 由 "iptables"/"iptables-legacy" 推导出对应的 restore 命令名
func deriveBinary(binary, base string) string {
	if strings.HasSuffix(binary, "-legacy") {
		return base + "-legacy"
	}
	if strings.HasSuffix(binary, "-nft") {
		return base + "-nft"
	}
	return base
}

// snapshot 是某张表当前状态的解析结果
type snapshot struct {
	chains []string            // 已存在的链（-N 行）
	rules  map[string][]string // 链名 → 规范化规则（顺序保持）
	raw    map[string][]string // 链名 → 原始规则参数文本（用于精确 -D）
}

func newSnapshot() snapshot {
	return snapshot{
		rules: make(map[string][]string),
		raw:   make(map[string][]string),
	}
}

func (s snapshot) hasChain(name string) bool {
	for _, c := range s.chains {
		if c == name {
			return true
		}
	}
	return false
}

func (s snapshot) equalChain(name string, want []Rule) bool {
	got := s.rules[name]
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i].canonical() {
			return false
		}
	}
	return true
}

// Apply 让内核状态与 plan 一致，返回是否发生了写操作
func (m *Manager) Apply(ctx context.Context, plan Plan) (bool, error) {
	if err := plan.Validate(); err != nil {
		return false, err
	}

	tables := plan.Tables()
	snaps := make(map[string]snapshot, len(tables))
	for _, t := range tables {
		snap, err := m.snapshot(ctx, t)
		if err != nil {
			return false, err
		}
		snaps[t] = snap
	}

	desired := make(map[string]map[string][]Rule, len(tables))
	for _, c := range plan.Chains {
		if desired[c.Table] == nil {
			desired[c.Table] = make(map[string][]Rule, len(plan.Chains))
		}
		desired[c.Table][c.Name] = c.Rules
	}

	drift := false
	for _, t := range tables {
		snap := snaps[t]
		for name, rules := range desired[t] {
			if !snap.hasChain(name) || !snap.equalChain(name, rules) {
				drift = true
			}
		}
		for _, name := range snap.chains {
			if !m.Managed(name) {
				continue
			}
			if _, ok := desired[t][name]; !ok {
				drift = true
			}
		}
	}
	jumpStates, err := m.inspectJumps(ctx, plan.Jumps)
	if err != nil {
		return false, err
	}
	for _, ok := range jumpStates {
		if !ok {
			drift = true
		}
	}
	if !drift {
		return false, nil
	}

	for _, t := range tables {
		if err := m.writeChains(ctx, t, desired[t], snaps[t]); err != nil {
			return true, err
		}
	}
	for _, t := range tables {
		if err := m.dropStaleChains(ctx, t, snaps[t], desired[t]); err != nil {
			m.log.Warn(i18n.Text("删除多余托管链失败"), "table", t, "err", err)
		}
	}
	if err := m.applyJumps(ctx, plan.Jumps); err != nil {
		return true, err
	}
	return true, nil
}

// snapshot 读取某张表的链与规则
func (m *Manager) snapshot(ctx context.Context, table string) (snapshot, error) {
	out, err := m.run(ctx, "-t", table, "-S")
	snap := newSnapshot()
	if err != nil {
		// 表不存在时 iptables 会报错，视为空快照
		m.log.Debug(i18n.Text("读取 iptables 状态失败，按空快照处理"), "table", table, "err", err)
		return snap, nil
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "-N "):
			snap.chains = append(snap.chains, strings.TrimSpace(strings.TrimPrefix(line, "-N ")))
		case strings.HasPrefix(line, "-A "):
			rest := strings.TrimPrefix(line, "-A ")
			chain, body := splitChainAndBody(rest)
			if chain == "" {
				continue
			}
			snap.raw[chain] = append(snap.raw[chain], body)
			if canonical, ok := parseRule(body); ok {
				snap.rules[chain] = append(snap.rules[chain], canonical)
			} else {
				snap.rules[chain] = append(snap.rules[chain], "RAW "+body)
			}
		}
	}
	return snap, nil
}

func splitChainAndBody(s string) (string, string) {
	idx := strings.IndexAny(s, " \t")
	if idx < 0 {
		return s, ""
	}
	return s[:idx], strings.TrimSpace(s[idx+1:])
}

// writeChains 确保链存在、清空并写入期望规则
func (m *Manager) writeChains(ctx context.Context, table string, want map[string][]Rule, snap snapshot) error {
	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if snap.hasChain(name) {
			continue
		}
		if _, err := m.run(ctx, "-t", table, "-N", name); err != nil {
			if _, checkErr := m.run(ctx, "-t", table, "-S", name); checkErr != nil {
				return i18n.NewCoded(msgCreateChainFailed, table, name, err)
			}
		}
	}
	for _, name := range names {
		if _, err := m.run(ctx, "-t", table, "-F", name); err != nil {
			return i18n.NewCoded(msgFlushChainFailed, table, name, err)
		}
	}

	fragment := restoreFragment(table, names, want)
	if out, err := m.runWithInput(ctx, fragment, m.restoreBinary, "--noflush", "-w", m.waitSeconds); err != nil {
		m.log.Warn(i18n.Text("iptables-restore 失败，回退为逐条添加规则"),
			"table", table, "err", err, "output", strings.TrimSpace(out))
		for _, name := range names {
			for _, rule := range want[name] {
				args := append([]string{"-t", table, "-A", name}, rule.args()...)
				if _, addErr := m.run(ctx, args...); addErr != nil {
					return i18n.NewCoded(msgAddRuleFailed, table, name, addErr)
				}
			}
		}
	}
	return nil
}

// RenderRestore 把某个表的链与规则渲染成 iptables-restore 可读入的文本
//
// 用途：排障时把「期望规则」打印出来，用 `iptables-restore --test` 验证合法性，
// 不必真的写内核；例如：
//
//	iptables-restore --test < /tmp/nat.rules
func RenderRestore(table string, chains []Chain) string {
	names := make([]string, 0, len(chains))
	want := make(map[string][]Rule, len(chains))
	for _, c := range chains {
		if c.Table != table {
			continue
		}
		names = append(names, c.Name)
		want[c.Name] = c.Rules
	}
	sort.Strings(names)
	return restoreFragment(table, names, want)
}

func restoreFragment(table string, names []string, want map[string][]Rule) string {
	var b strings.Builder
	b.WriteString("*" + table + "\n")
	for _, name := range names {
		b.WriteString(":" + name + " - [0:0]\n")
	}
	for _, name := range names {
		for _, rule := range want[name] {
			b.WriteString("-A " + name)
			for _, arg := range rule.args() {
				b.WriteString(" ")
				b.WriteString(quoteIfNeeded(arg))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// dropStaleChains 删除不再需要的托管链（先摘跳转，再删链）
func (m *Manager) dropStaleChains(ctx context.Context, table string, snap snapshot, want map[string][]Rule) error {
	var stale []string
	for _, name := range snap.chains {
		if !m.Managed(name) {
			continue
		}
		if _, ok := want[name]; ok {
			continue
		}
		stale = append(stale, name)
	}
	if len(stale) == 0 {
		return nil
	}
	sortChainsForDeletion(stale)

	// 先删掉其他链（含内建链）里指向这些链的跳转，否则 -X 必然失败
	for _, name := range stale {
		m.removeJumpsTo(ctx, table, snap, name)
	}
	for _, name := range stale {
		if _, err := m.run(ctx, "-t", table, "-F", name); err != nil {
			m.log.Debug(i18n.Text("清空遗留链失败"), "table", table, "chain", name, "err", err)
		}
	}
	var errs []error
	for _, name := range stale {
		if _, err := m.run(ctx, "-t", table, "-X", name); err != nil {
			if _, checkErr := m.run(ctx, "-t", table, "-S", name); checkErr == nil {
				errs = append(errs, i18n.NewCoded(msgDeleteChainFailed, table, name, err))
			}
		}
	}
	for _, name := range stale {
		m.log.Info(i18n.Text("已删除不再需要的链"), "table", table, "chain", name)
	}
	return errors.Join(errs...)
}

// sortChainsForDeletion 让主链排在派生链之前（主链引用派生链）
func sortChainsForDeletion(names []string) {
	sort.SliceStable(names, func(i, j int) bool {
		if len(names[i]) != len(names[j]) {
			return len(names[i]) < len(names[j])
		}
		return names[i] < names[j]
	})
}

// removeJumpsTo 删除所有链中指向 target 的跳转规则
func (m *Manager) removeJumpsTo(ctx context.Context, table string, snap snapshot, target string) {
	for chain, raws := range snap.raw {
		for _, raw := range raws {
			tokens := splitArgs(raw)
			if jumpOf(tokens) != target {
				continue
			}
			args := append([]string{"-t", table, "-D", chain}, tokens...)
			if _, err := m.run(ctx, args...); err != nil {
				m.log.Debug(i18n.Text("删除跳转失败"), "table", table, "parent", chain, "child", target, "err", err)
			}
		}
	}
}

// jumpOf 从规则参数中取出 -j 的目标
func jumpOf(tokens []string) string {
	for i := 0; i < len(tokens); i++ {
		if tokens[i] == "-j" || tokens[i] == "--jump" {
			if i+1 < len(tokens) {
				return tokens[i+1]
			}
			return ""
		}
	}
	return ""
}

// inspectJumps 检查跳转是否存在且位置正确
func (m *Manager) inspectJumps(ctx context.Context, jumps []Jump) ([]bool, error) {
	out := make([]bool, len(jumps))
	for i, j := range jumps {
		raws, err := m.parentRules(ctx, j.Table, j.Parent)
		if err != nil {
			return nil, err
		}
		found, index := -1, -1
		for k, raw := range raws {
			if jumpOf(splitArgs(raw)) == j.Child {
				found = k
				break
			}
		}
		index = found
		switch {
		case index < 0:
			out[i] = false
		case j.Position == 1 && index != 0:
			out[i] = false
		default:
			out[i] = true
		}
	}
	return out, nil
}

// parentRules 返回内建链当前的规则参数文本列表
func (m *Manager) parentRules(ctx context.Context, table, parent string) ([]string, error) {
	out, err := m.run(ctx, "-t", table, "-S", parent)
	if err != nil {
		return nil, nil // 父链不存在时按空处理
	}
	var raws []string
	prefix := "-A " + parent + " "
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		raws = append(raws, strings.TrimSpace(strings.TrimPrefix(line, prefix)))
	}
	return raws, nil
}

// applyJumps 让跳转规则存在且位置正确
func (m *Manager) applyJumps(ctx context.Context, jumps []Jump) error {
	for _, j := range jumps {
		states, err := m.inspectJumps(ctx, []Jump{j})
		if err != nil {
			return err
		}
		if states[0] {
			continue
		}
		// 先清理已存在的同目标跳转，避免重复
		raws, err := m.parentRules(ctx, j.Table, j.Parent)
		if err != nil {
			return err
		}
		for _, raw := range raws {
			if jumpOf(splitArgs(raw)) != j.Child {
				continue
			}
			args := append([]string{"-t", j.Table, "-D", j.Parent}, splitArgs(raw)...)
			if _, err := m.run(ctx, args...); err != nil {
				m.log.Debug(i18n.Text("删除旧跳转失败"), "table", j.Table, "parent", j.Parent, "err", err)
			}
		}

		args := []string{"-t", j.Table}
		if j.Position == 1 {
			args = append(args, "-I", j.Parent, "1")
		} else {
			args = append(args, "-A", j.Parent)
		}
		args = append(args, "-m", "comment", "--comment", m.comment, "-j", j.Child)
		if _, err := m.run(ctx, args...); err != nil {
			return i18n.NewCoded(msgAddJumpFailed, j.Table, j.Parent, j.Child, err)
		}
		m.log.Info(i18n.Text("已添加跳转规则"), "table", j.Table, "parent", j.Parent, "chain", j.Child)
	}
	return nil
}

// Cleanup 删除自己创建的全部链与跳转（幂等，失败只记录不阻断）
func (m *Manager) Cleanup(ctx context.Context) error {
	var errs []error
	for _, table := range []string{TableNat, TableFilter} {
		snap, err := m.snapshot(ctx, table)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var managed []string
		for _, name := range snap.chains {
			if m.Managed(name) {
				managed = append(managed, name)
			}
		}
		if len(managed) == 0 {
			continue
		}
		sortChainsForDeletion(managed)

		for _, name := range managed {
			m.removeJumpsTo(ctx, table, snap, name)
		}
		for _, name := range managed {
			if _, err := m.run(ctx, "-t", table, "-F", name); err != nil {
				m.log.Debug(i18n.Text("清空链失败"), "table", table, "chain", name, "err", err)
			}
		}
		for _, name := range managed {
			if _, err := m.run(ctx, "-t", table, "-X", name); err != nil {
				if _, checkErr := m.run(ctx, "-t", table, "-S", name); checkErr == nil {
					errs = append(errs, i18n.NewCoded(msgDeleteChainFailed, table, name, err))
					continue
				}
			}
			m.log.Info(i18n.Text("已删除链"), "table", table, "chain", name)
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) run(ctx context.Context, args ...string) (string, error) {
	return m.runner.Run(ctx, m.binary, append([]string{"-w", m.waitSeconds}, args...)...)
}

func (m *Manager) runWithInput(ctx context.Context, input, name string, args ...string) (string, error) {
	return m.runner.RunWithInput(ctx, input, name, args...)
}

// parseRule 把 iptables-save 输出的规则参数解析成与 Rule.canonical 同构的字符串
// 无法识别的内容返回 ok=false（会被视为漂移并重建）
func parseRule(argLine string) (string, bool) {
	tokens := splitArgs(argLine)
	var (
		src, dst, proto, dport, action, toDest, rejectWith, logPrefix string
		jumpTarget                                                    string
	)
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		next := func() (string, bool) {
			if i+1 >= len(tokens) {
				return "", false
			}
			i++
			return tokens[i], true
		}
		switch tok {
		case "-s", "--source":
			v, ok := next()
			if !ok {
				return "", false
			}
			src = normalizePrefix(v)
		case "-d", "--destination":
			v, ok := next()
			if !ok {
				return "", false
			}
			dst = normalizePrefix(v)
		case "-p", "--protocol":
			v, ok := next()
			if !ok {
				return "", false
			}
			proto = v
		case "--dport", "--destination-port":
			v, ok := next()
			if !ok {
				return "", false
			}
			dport = normalizePort(v)
		case "-j", "--jump":
			v, ok := next()
			if !ok {
				return "", false
			}
			action = v
		case "--to-destination", "--to":
			v, ok := next()
			if !ok {
				return "", false
			}
			toDest = normalizeHostPort(v)
		case "--reject-with":
			v, ok := next()
			if !ok {
				return "", false
			}
			rejectWith = v
		case "--log-prefix":
			v, ok := next()
			if !ok {
				return "", false
			}
			logPrefix = strings.TrimSpace(v)
		case "-m", "--match":
			// 模块名忽略（iptables-save 会显式输出 -m tcp / -m comment / -m multiport 等）
			if _, ok := next(); !ok {
				return "", false
			}
		case "--comment":
			if _, ok := next(); !ok {
				return "", false
			}
		case "!":
			// 本项目不生成取反匹配，出现即视为不认识的规则
			return "", false
		default:
			if strings.HasPrefix(tok, "-") {
				return "", false
			}
		}
	}
	if action == "" {
		return "", false
	}

	parts := make([]string, 0, 8)
	if src != "" {
		parts = append(parts, "src="+src)
	}
	if dst != "" {
		parts = append(parts, "dst="+dst)
	}
	if proto != "" {
		parts = append(parts, "proto="+proto)
	}
	if dport != "" {
		parts = append(parts, "dport="+dport)
	}
	switch Action(action) {
	case ActionDNAT:
		if toDest == "" {
			return "", false
		}
		parts = append(parts, "dnat="+toDest, "action=DNAT")
	case ActionReject:
		if rejectWith == "" {
			rejectWith = "tcp-reset"
		}
		parts = append(parts, "reject="+rejectWith, "action=REJECT")
	case ActionLog:
		parts = append(parts, "log="+logPrefix, "action=LOG")
	case ActionReturn:
		parts = append(parts, "action=RETURN")
	default:
		// 其余 -j 目标一律按跳转处理（托管链名）
		if strings.HasPrefix(action, "-") {
			return "", false
		}
		jumpTarget = action
		parts = append(parts, "jump="+jumpTarget, "action=JUMP")
	}
	return strings.Join(parts, " "), true
}

// splitArgs 按空格拆分，保留双引号内的内容（并去掉引号）
func splitArgs(s string) []string {
	var (
		out     []string
		current strings.Builder
		quoted  bool
		started bool
	)
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
			started = true
		case r == ' ' && !quoted:
			if started {
				out = append(out, current.String())
				current.Reset()
				started = false
			}
		default:
			current.WriteRune(r)
			started = true
		}
	}
	if started {
		out = append(out, current.String())
	}
	return out
}

// normalizePrefix 把 "10.0.0.1" 或 "10.0.0.1/32" 统一为 "10.0.0.1/32"、
// 把 "10.0.0.0/8" 统一为规范化网段；无法解析时原样返回（从而永远不等于期望值）
func normalizePrefix(s string) string {
	if !strings.Contains(s, "/") {
		s += "/32"
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return s
	}
	return ipnet.String()
}

// normalizeCIDROrIP 校验并规范化地址/网段，返回 (前缀, error)
func normalizeCIDROrIP(s string) (string, error) {
	normalized := normalizePrefix(strings.TrimSpace(s))
	if _, _, err := net.ParseCIDR(normalized); err != nil {
		return "", i18n.NewCoded(msgInvalidIPv4OrCIDR)
	}
	return normalized, nil
}

// normalizePort 把 "443:443" 之类的单端口范围统一为 "443"
func normalizePort(s string) string {
	if idx := strings.Index(s, ":"); idx > 0 {
		first, second := s[:idx], s[idx+1:]
		if first == second {
			return first
		}
	}
	return s
}

// normalizeHostPort 规范化 "10.238.29.6:20001" 形式的目标
func normalizeHostPort(s string) string {
	if strings.Count(s, ":") > 1 {
		return s // 端口范围（a:b）或多冒号形式，原样保留
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return s
	}
	return net.JoinHostPort(ip.To4().String(), port)
}

// quoteIfNeeded 在参数含空格时加引号，保证 iptables-restore 能正确解析
func quoteIfNeeded(arg string) string {
	if strings.ContainsAny(arg, " \t\"") {
		return `"` + strings.ReplaceAll(arg, `"`, `_`) + `"`
	}
	return arg
}

// sanitizeComment 过滤注释中会破坏 iptables-restore 输入解析的字符（双引号、反斜杠、
// 控制字符）；中文等可打印字符保留，便于运维排障
func sanitizeComment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = DefaultComment
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteRune('_')
		case r < 0x20 || r == 0x7f:
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		out = DefaultComment
	}
	// 注释上限 256 字节，这里按 rune 边界截断到 200 字节以内
	if len(out) > 200 {
		runes := []rune(out)
		for len(string(runes)) > 200 && len(runes) > 0 {
			runes = runes[:len(runes)-1]
		}
		out = string(runes)
	}
	return out
}

// sanitizeLogPrefix 过滤 LOG 前缀里的空格与特殊字符（内核要求前缀以空格结尾）
func sanitizeLogPrefix(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = DefaultComment
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteRune('_')
		case r < 0x20 || r == 0x7f:
			b.WriteRune('_')
		default:
			b.WriteRune(r)
		}
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		out = DefaultComment
	}
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
