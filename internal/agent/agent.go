// Package agent 实现 DaemonSet 中的策略落地逻辑：
//
//	控制器（四元组策略）→ 本节点编译结果 → 域名解析 → iptables 规则计划 → 应用到内核
//
// 关键行为：
//   - 静态参数（代理地址、链名、间隔、DNS、排除网段）来自 ConfigMap 挂载的配置文件；
//   - 动态策略（payload / target / proxyPort / 授权关系）来自控制器，按 policyInterval 轮询；
//   - 控制器不可用时沿用上一次成功的结果（fail-stale），启动即失败时回退到「配置文件
//     targets 全量直通」，避免一上来就把集群出网打死；
//   - 规则内容与内核现状一致时不做任何写操作，避免轮询导致规则抖动
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"egress-proxy/config"
	"egress-proxy/internal/filewatch"
	"egress-proxy/internal/i18n"
	"egress-proxy/internal/iptables"
	"egress-proxy/internal/policy"
	"egress-proxy/internal/policymodel"
	"egress-proxy/internal/resolver"
	"egress-proxy/internal/rules"
)

const (
	// tickInterval 是调度精度：所有周期都按它取整判断
	tickInterval = time.Second
	// cleanupTimeout 是退出清理规则的时间上限
	cleanupTimeout = 10 * time.Second
	// configWaitTimeout 是启动时等待配置文件出现的最长时间
	configWaitTimeout = 60 * time.Second
	// reportTimeout 是上报状态给控制器的超时
	reportTimeout = 2 * time.Second
	// DefaultCachePath 是策略缓存的默认落盘位置（容器内 /run 是唯一可写卷）
	DefaultCachePath = "/run/egress-proxy/policy-cache.json"
)

// RuleManager 抽象 iptables 规则管理，便于测试注入
type RuleManager interface {
	Apply(ctx context.Context, plan iptables.Plan) (bool, error)
	Cleanup(ctx context.Context) error
	Chain() string
	Binary() string
}

// Options 配置 Agent
type Options struct {
	// ConfigPath 是 ConfigMap 挂载的配置文件路径
	ConfigPath string
	// HostIP 是本节点 IP（通常来自 Downward API 注入的 HOST_IP），可为 nil
	HostIP net.IP
	// NodeName 是本节点名（Downward API 注入的 NODE_NAME），用于按节点过滤允许源
	NodeName string
	// Logger 可为 nil
	Logger *slog.Logger
	// Lookup 用于测试注入 DNS 解析，nil 时使用系统解析器
	Lookup resolver.LookupFunc
	// NewManager 用于测试注入规则管理器，nil 时使用真实 iptables 命令
	NewManager func(binary, chain string) RuleManager
	// Source 是策略来源；为 nil 时使用配置文件里的 targets（四元组管控未启用）
	Source policy.Source
}

// Agent 维护托管链的内容与跳转
type Agent struct {
	configPath string
	hostIP     net.IP
	nodeName   string
	log        *slog.Logger
	lookup     resolver.LookupFunc
	newManager func(binary, chain string) RuleManager
	source     policy.Source
	sourceURL  string

	cfg      *config.Config
	mgr      RuleManager
	res      *resolver.Resolver
	dnsKey   string
	compiled *policymodel.Compiled

	nextPolicyAt  time.Time
	nextResolveAt time.Time
	nextSyncAt    time.Time

	applied     bool
	lastError   string
	lastErrorEn string
}

// New 创建 Agent
func New(opts Options) *Agent {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	newManager := opts.NewManager
	if newManager == nil {
		newManager = func(binary, chain string) RuleManager {
			return iptables.New(binary, chain, logger)
		}
	}
	// source 可以为 nil：applyConfig 会按 cfg.Options.PolicyURL 决定用控制器还是配置文件
	source := opts.Source
	return &Agent{
		configPath: opts.ConfigPath,
		hostIP:     opts.HostIP,
		nodeName:   opts.NodeName,
		log:        logger,
		lookup:     opts.Lookup,
		newManager: newManager,
		source:     source,
	}
}

// NodeName 返回本节点名
func (a *Agent) NodeName() string { return a.nodeName }

// SourceDescription 返回策略来源描述，便于日志与自检
func (a *Agent) SourceDescription() string { return a.source.Describe() }

// Applied 返回上一次同步是否成功
func (a *Agent) Applied() bool { return a.applied }

// LastError 返回上一次同步的错误文本（空表示成功）
func (a *Agent) LastError() string { return a.lastError }

// Run 持续工作，直到 ctx 被取消；退出前清理自己管理的规则
func (a *Agent) Run(ctx context.Context) error {
	cfg, err := a.waitForConfig(ctx)
	if err != nil {
		return err
	}

	if err := a.applyConfig(ctx, cfg); err != nil {
		a.log.Error("首次应用规则失败", "err", err)
	}

	events := filewatch.New(a.configPath, cfg.Options.ConfigInterval.D(), a.log).Watch(ctx)

	tick := time.NewTicker(tickInterval)
	defer tick.Stop()

	defer func() {
		if a.mgr == nil {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := a.mgr.Cleanup(cleanupCtx); err != nil {
			a.log.Warn("清理 iptables 规则失败，请人工检查", "chain", a.mgr.Chain(), "err", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			a.log.Info("收到退出信号，开始清理规则")
			return nil

		case content, ok := <-events:
			if !ok {
				return nil
			}
			newCfg, err := config.Parse(content)
			if err != nil {
				a.log.Error("新配置无效，沿用当前配置", "err", err)
				continue
			}
			if a.cfg != nil && newCfg.Hash == a.cfg.Hash {
				continue
			}
			a.log.Info("检测到静态配置变化", "hash", shortHash(newCfg.Hash),
				"policyUrl", newCfg.Options.PolicyURL)
			if err := a.applyConfig(ctx, newCfg); err != nil {
				a.log.Error("应用新配置失败，将按 syncInterval 继续重试", "err", err)
			}

		case now := <-tick.C:
			if a.cfg == nil {
				continue
			}
			needReconcile := false

			if !now.Before(a.nextPolicyAt) {
				a.nextPolicyAt = now.Add(a.cfg.Options.PolicyInterval.D())
				if a.refreshPolicy(ctx) {
					needReconcile = true
				}
			}

			if !now.Before(a.nextResolveAt) {
				a.nextResolveAt = now.Add(a.cfg.Options.ResolveInterval.D())
				resolveCtx, cancel := context.WithTimeout(ctx, a.cfg.Options.ResolveInterval.D())
				changed := a.res.Refresh(resolveCtx, domainHosts(a.compiled))
				cancel()
				if changed {
					a.log.Debug("域名解析结果变化，准备重建规则")
					needReconcile = true
				}
			}

			if !now.Before(a.nextSyncAt) {
				a.nextSyncAt = now.Add(a.cfg.Options.SyncInterval.D())
				needReconcile = true
			}

			if needReconcile {
				if err := a.Reconcile(ctx); err != nil {
					a.log.Error("同步规则失败", "err", err)
				}
			}
		}
	}
}

// Reconcile 让内核中的规则与当前策略、当前解析结果一致（幂等）
func (a *Agent) Reconcile(ctx context.Context) error {
	if a.cfg == nil {
		return i18n.NewCoded(msgConfigNotLoaded)
	}
	plan, err := a.Plan()
	if err != nil {
		a.recordFailure(ctx, err)
		return err
	}
	changed, err := a.mgr.Apply(ctx, plan)
	if err != nil {
		a.recordFailure(ctx, err)
		return err
	}
	a.applied = true
	a.lastError = ""
	a.lastErrorEn = ""
	if changed {
		a.log.Info("iptables 规则已更新",
			"chain", a.mgr.Chain(), "mode", a.mode().String(),
			"chains", len(plan.Chains), "jumps", len(plan.Jumps),
			"targets", a.targetCount(), "generation", a.generation())
	}
	a.report(ctx, true)
	return nil
}

func (a *Agent) recordFailure(ctx context.Context, err error) {
	a.applied = false
	a.lastError, a.lastErrorEn = i18n.Bilingual(err)
	a.report(ctx, false)
}

// Plan 生成期望的规则计划（不写内核），供 Reconcile 与自检使用
func (a *Agent) Plan() (iptables.Plan, error) {
	if a.cfg == nil {
		return iptables.Plan{}, i18n.NewCoded(msgConfigNotLoaded)
	}
	if a.compiled == nil {
		return iptables.Plan{}, i18n.NewCoded(msgPolicyNotLoaded)
	}

	targets := make([]rules.ResolvedTarget, 0, len(a.compiled.Targets))
	missing := make([]string, 0, 2)
	for _, t := range a.compiled.Targets {
		ips := a.resolveIPs(t.Host)
		if len(ips) == 0 {
			missing = append(missing, t.Host)
		}
		targets = append(targets, rules.ResolvedTarget{
			Host:         t.Host,
			Port:         t.Port,
			ProxyPort:    t.ProxyPort,
			IPs:          ips,
			AllowSources: t.AllowSources,
		})
	}
	if len(missing) > 0 {
		a.log.Warn("以下目标当前没有解析结果，本次不生成直连拒绝规则（子链仍为空，等于全部拒绝）",
			"hosts", strings.Join(missing, ","))
	}

	opts := rules.Options{
		ProxyIP:       a.cfg.ProxyIP(),
		ChainName:     a.cfg.Options.ChainName,
		ExcludeCIDRs:  a.cfg.Options.ExcludeCIDRs,
		Mode:          a.compiled.Mode,
		Comment:       iptables.DefaultComment,
		IncludeOutput: !a.IsProxyNode(a.cfg),
	}
	return rules.BuildPlan(opts, targets)
}

// refreshPolicy 拉取策略，返回是否发生变化
func (a *Agent) refreshPolicy(ctx context.Context) bool {
	timeout := a.cfg.Options.PolicyInterval.D()
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	compiled, err := a.source.Fetch(fetchCtx)
	if err != nil {
		a.log.Warn("拉取四元组策略失败", "source", a.source.Describe(), "err", err)
	}
	if compiled == nil {
		return false
	}
	if compiledEqual(a.compiled, compiled) {
		return false
	}
	prevMode := i18n.Text("(无)")
	if a.compiled != nil {
		prevMode = a.compiled.Mode.String()
	}
	a.compiled = compiled
	a.log.Info("四元组策略已更新",
		"generation", compiled.Generation, "mode", compiled.Mode.String(),
		"previousMode", prevMode, "targets", len(compiled.Targets))
	return true
}

// report 把本节点状态上报给控制器（尽力而为）
func (a *Agent) report(ctx context.Context, applied bool) {
	if a.source == nil {
		return
	}
	status := policy.Status{
		Node:       a.nodeName,
		Generation: a.generation(),
		Applied:    applied,
		Mode:       a.mode().String(),
		Error:      a.lastError,
		ErrorEn:    a.lastErrorEn,
	}
	reportCtx, cancel := context.WithTimeout(ctx, reportTimeout)
	defer cancel()
	if err := a.source.Report(reportCtx, status); err != nil {
		a.log.Debug("上报节点状态失败", "err", err)
	}
}

func (a *Agent) mode() policymodel.Mode {
	if a.compiled == nil {
		return policymodel.ModeDisabled
	}
	return a.compiled.Mode
}

func (a *Agent) generation() int64 {
	if a.compiled == nil {
		return 0
	}
	return a.compiled.Generation
}

func (a *Agent) targetCount() int {
	if a.compiled == nil {
		return 0
	}
	return len(a.compiled.Targets)
}

// resolveIPs 返回目标的 IPv4 地址列表（IP 字面量直接返回，域名走本节点解析）
func (a *Agent) resolveIPs(host string) []net.IP {
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return []net.IP{v4}
		}
		return nil
	}
	if a.res == nil {
		return nil
	}
	return a.res.IPs(host)
}

// IsProxyNode 判断本节点是否为配置中的代理节点
// HOST_IP 缺失时退化为「本机是否直接拥有该地址」，避免在代理节点上误挂 OUTPUT 链
func (a *Agent) IsProxyNode(cfg *config.Config) bool {
	proxyIP := cfg.ProxyIP()
	if proxyIP == nil {
		return false
	}
	if a.hostIP != nil {
		return cfg.IsProxyNode(a.hostIP)
	}
	return HasLocalAddr(proxyIP)
}

// HasLocalAddr 判断本机是否拥有指定地址
func HasLocalAddr(ip net.IP) bool {
	if ip == nil {
		return false
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var candidate net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			candidate = v.IP
		case *net.IPAddr:
			candidate = v.IP
		}
		if candidate != nil && candidate.To4() != nil && candidate.To4().Equal(ip.To4()) {
			return true
		}
	}
	return false
}

// applyConfig 在静态配置变化时更新管理器与解析器，并立即对齐内核规则
func (a *Agent) applyConfig(ctx context.Context, cfg *config.Config) error {
	// 链名或 iptables 实现变化时，先清理旧链，避免遗留
	if a.mgr != nil && (a.mgr.Chain() != cfg.Options.ChainName || a.mgr.Binary() != cfg.Options.IptablesBinary) {
		cleanupCtx, cancel := context.WithTimeout(ctx, cleanupTimeout)
		if err := a.mgr.Cleanup(cleanupCtx); err != nil {
			a.log.Warn("清理旧链失败", "chain", a.mgr.Chain(), "err", err)
		}
		cancel()
		a.mgr = nil
	}
	if a.mgr == nil {
		a.mgr = a.newManager(cfg.Options.IptablesBinary, cfg.Options.ChainName)
	}

	dnsKey := strings.Join(cfg.NormalizeDNSServers(), ",") + fmt.Sprintf("|maxIPs=%d", cfg.Options.MaxIPsPerHost)
	if a.res == nil || dnsKey != a.dnsKey {
		a.res = resolver.New(resolver.Options{
			DNSServers:    cfg.NormalizeDNSServers(),
			MaxIPsPerHost: cfg.Options.MaxIPsPerHost,
			Logger:        a.log,
			Lookup:        a.lookup,
		})
		a.dnsKey = dnsKey
	}

	a.cfg = cfg
	now := time.Now()
	a.nextPolicyAt = now.Add(cfg.Options.PolicyInterval.D())
	a.nextResolveAt = now.Add(cfg.Options.ResolveInterval.D())
	a.nextSyncAt = now.Add(cfg.Options.SyncInterval.D())

	// 策略来源：配置了 policyUrl 就走控制器，否则用配置文件 targets（旧行为）
	if a.source == nil || a.sourceURL != cfg.Options.PolicyURL {
		a.source = buildSource(cfg, a.nodeName, a.log)
		a.sourceURL = cfg.Options.PolicyURL
		a.log.Info("策略来源已切换", "source", a.source.Describe())
	}

	// 立刻拉一次策略与域名解析，然后应用
	a.refreshPolicy(ctx)
	if a.compiled == nil && len(cfg.Targets) > 0 {
		// 控制器不可用且没有缓存：退化为配置文件 targets 全量直通（fail-open）
		a.compiled = policy.CompileLegacy(cfg.Targets)
		a.log.Warn("未能从控制器获取策略，暂时退化为配置文件 targets 全量直通",
			"source", a.source.Describe(), "targets", len(a.compiled.Targets))
	}

	resolveCtx, cancel := context.WithTimeout(ctx, cfg.Options.DialTimeout.D()+cfg.Options.ResolveInterval.D())
	a.res.Refresh(resolveCtx, domainHosts(a.compiled))
	cancel()

	return a.Reconcile(ctx)
}

// waitForConfig 等待配置文件可用（ConfigMap 挂载完成）并解析成功
func (a *Agent) waitForConfig(ctx context.Context) (*config.Config, error) {
	deadline := time.Now().Add(configWaitTimeout)
	for {
		cfg, err := config.Load(a.configPath)
		if err == nil {
			return cfg, nil
		}
		if time.Now().After(deadline) {
			return nil, i18n.NewCoded(msgWaitConfigTimeout, a.configPath, err)
		}
		a.log.Warn("配置文件暂不可用，稍后重试", "path", a.configPath, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// domainHosts 返回需要解析的域名型目标（去重）
func domainHosts(compiled *policymodel.Compiled) []string {
	if compiled == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(compiled.Targets))
	out := make([]string, 0, len(compiled.Targets))
	for _, t := range compiled.Targets {
		host := strings.TrimSpace(t.Host)
		if host == "" || net.ParseIP(host) != nil {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

// compiledEqual 比较两份编译结果是否等价（用于判断是否需要重建规则）
func compiledEqual(a, b *policymodel.Compiled) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Mode != b.Mode || a.Generation != b.Generation {
		return false
	}
	if len(a.Targets) != len(b.Targets) {
		return false
	}
	for i := range a.Targets {
		x, y := a.Targets[i], b.Targets[i]
		if x.Host != y.Host || x.Port != y.Port || x.ProxyPort != y.ProxyPort {
			return false
		}
		if len(x.AllowSources) != len(y.AllowSources) {
			return false
		}
		for k := range x.AllowSources {
			if x.AllowSources[k] != y.AllowSources[k] {
				return false
			}
		}
	}
	return true
}

// buildSource 按配置构造策略来源：配置了 policyUrl 就走控制器，否则用配置文件 targets
func buildSource(cfg *config.Config, nodeName string, logger *slog.Logger) policy.Source {
	baseURL := strings.TrimSpace(cfg.Options.PolicyURL)
	if baseURL == "" {
		return policy.NewStaticSource(cfg.Targets)
	}
	return policy.NewHTTPClient(policy.Options{
		BaseURL:   baseURL,
		NodeName:  nodeName,
		Token:     strings.TrimSpace(os.Getenv("EGRESS_CONTROLLER_TOKEN")),
		Timeout:   cfg.Options.PolicyInterval.D(),
		CachePath: policyCachePath(),
		Logger:    logger,
	})
}

// policyCachePath 返回策略缓存文件路径（容器内只有 /run 可写）；不可写时返回空表示不落盘
func policyCachePath() string {
	if err := os.MkdirAll("/run/egress-proxy", 0o755); err != nil {
		return ""
	}
	return DefaultCachePath
}

// EnvHostIP 读取 Downward API 注入的节点 IP（HOST_IP），未设置或非法时返回 nil
func EnvHostIP() net.IP {
	raw := strings.TrimSpace(os.Getenv("HOST_IP"))
	if raw == "" {
		return nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return nil
	}
	return ip.To4()
}

// EnvNodeName 读取 Downward API 注入的节点名（NODE_NAME）
func EnvNodeName() string {
	return strings.TrimSpace(os.Getenv("NODE_NAME"))
}

func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
