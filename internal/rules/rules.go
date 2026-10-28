// Package rules 把「四元组策略的编译结果」翻译成 iptables 规则计划（iptables.Plan）
//
// 规则结构（每个 target 一条子链，子链内每条授权源一条 DNAT）：
//
//	nat 表
//	  <chain>                       主链：代理节点/回环/排除网段的 RETURN + 每 target 的跳转
//	  <chain>-T-<hash>              子链：-s <源> -j DNAT --to <proxyIP>:<proxyPort>
//	                               （子链为空 = 该目标谁都不许，天然 fail-closed）
//	filter 表
//	  <chain>-DENY                  拒绝链：代理节点/回环/排除网段的 RETURN + 每 target 的跳转
//	  <chain>-DENY-T-<hash>         子链：授权源 RETURN，末尾兜底 REJECT（observe 模式改为 LOG）
//
// 这样策略变更只会改动子链内容，规则结构（链数、跳转数）保持稳定
package rules

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"egress-proxy/internal/i18n"
	"egress-proxy/internal/iptables"
	"egress-proxy/internal/policymodel"
)

const (
	// denySuffix 是拒绝链相对主链名的后缀
	denySuffix = "-DENY"
	// targetSuffix 是每目标子链的中间段
	targetSuffix = "-T-"
	// hashLen 是子链名中哈希的长度（6 位十六进制足以避免冲突，且保证链名不超长）
	hashLen = 6
	// denyLogPrefix 是观察模式下 LOG 动作的前缀
	denyLogPrefix = "egp-would-deny "
)

// Options 是生成规则所需的静态参数
type Options struct {
	// ProxyIP 是代理节点 IPv4 地址
	ProxyIP net.IP
	// ChainName 是主链名（默认 EGRESS-PROXY）
	ChainName string
	// ExcludeCIDRs 是需要提前 RETURN 的网段（Pod/Service CIDR 等）
	ExcludeCIDRs []string
	// Mode 是策略模式
	Mode policymodel.Mode
	// Comment 写入规则的注释前缀，便于排障
	Comment string
	// IncludeOutput 为 false 时不挂 OUTPUT 跳转（代理节点自身，避免 forwarder 出站回绕）
	IncludeOutput bool
}

// ResolvedTarget 是完成域名解析后的目标
type ResolvedTarget struct {
	Host      string
	Port      int
	ProxyPort int
	// IPs 是解析出的目标 IPv4 地址（域名型目标由各节点自行解析）
	IPs []net.IP
	// AllowSources 是被授权访问该目标的源地址（IP 或 CIDR）
	AllowSources []string
}

// Key 返回 host:port
func (t ResolvedTarget) Key() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// NatChain 返回该目标在主链上跳转的子链名
func (t ResolvedTarget) NatChain(chain string) string {
	return chain + targetSuffix + shortHash(t.Key())
}

// DenyChain 返回该目标在拒绝链上跳转的子链名
func (t ResolvedTarget) DenyChain(chain string) string {
	return chain + denySuffix + targetSuffix + shortHash(t.Key())
}

// MainChain 返回主链名
func MainChain(opts Options) string { return opts.ChainName }

// DenyMainChain 返回拒绝链名
func DenyMainChain(opts Options) string { return opts.ChainName + denySuffix }

// MaxBaseChainLen 返回主链名允许的最大长度（保证派生链名不超过 iptables 上限）
func MaxBaseChainLen() int {
	return iptables.MaxChainNameLen - len(denySuffix+targetSuffix) - hashLen
}

// BuildPlan 生成完整的规则计划
func BuildPlan(opts Options, targets []ResolvedTarget) (iptables.Plan, error) {
	var plan iptables.Plan

	if opts.ChainName == "" {
		return plan, i18n.NewCoded(msgChainNameEmpty)
	}
	if len(opts.ChainName) > MaxBaseChainLen() {
		return plan, i18n.NewCoded(msgChainNameTooLong,
			opts.ChainName, len(opts.ChainName), iptables.MaxChainNameLen, MaxBaseChainLen())
	}
	proxyV4 := opts.ProxyIP.To4()
	if proxyV4 == nil {
		return plan, i18n.NewCoded(msgProxyIPNotIPv4, opts.ProxyIP)
	}
	proxyPrefix := proxyV4.String() + "/32"
	comment := opts.Comment
	if comment == "" {
		comment = iptables.DefaultComment
	}

	excludes := make([]string, 0, len(opts.ExcludeCIDRs))
	for _, cidr := range opts.ExcludeCIDRs {
		prefix, err := normalizeCIDR(cidr)
		if err != nil {
			return plan, codedWithCause(msgExcludeCIDRInvalid, err, cidr)
		}
		excludes = append(excludes, prefix)
	}

	sorted := append([]ResolvedTarget(nil), targets...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Host != sorted[j].Host {
			return sorted[i].Host < sorted[j].Host
		}
		return sorted[i].Port < sorted[j].Port
	})

	natMain := []iptables.Rule{
		{DstPrefix: proxyPrefix, Action: iptables.ActionReturn, Comment: comment + i18n.Text(" 代理节点自身，避免回绕")},
		{DstPrefix: "127.0.0.0/8", Action: iptables.ActionReturn, Comment: comment + i18n.Text(" 本机回环")},
	}
	for _, cidr := range excludes {
		natMain = append(natMain, iptables.Rule{
			DstPrefix: cidr, Action: iptables.ActionReturn, Comment: comment + i18n.Text(" 排除网段"),
		})
	}

	denyMain := []iptables.Rule{
		{SrcPrefix: proxyPrefix, Action: iptables.ActionReturn, Comment: comment + i18n.Text(" 代理节点自身出站")},
		{DstPrefix: "127.0.0.0/8", Action: iptables.ActionReturn, Comment: comment + i18n.Text(" 本机回环")},
	}
	for _, cidr := range excludes {
		denyMain = append(denyMain, iptables.Rule{
			DstPrefix: cidr, Action: iptables.ActionReturn, Comment: comment + i18n.Text(" 排除网段"),
		})
	}

	plan.Chains = append(plan.Chains, iptables.Chain{
		Table: iptables.TableNat, Name: opts.ChainName, Rules: natMain,
	})
	if opts.Mode != policymodel.ModeDisabled {
		plan.Chains = append(plan.Chains, iptables.Chain{
			Table: iptables.TableFilter, Name: DenyMainChain(opts), Rules: denyMain,
		})
	}

	for _, t := range sorted {
		if t.Port < 1 || t.Port > 65535 {
			return plan, i18n.NewCoded(msgTargetPortOutOfRange, t.Key(), t.Port)
		}
		if t.ProxyPort < 1 || t.ProxyPort > 65535 {
			return plan, i18n.NewCoded(msgTargetProxyPortOutOfRange, t.Key(), t.ProxyPort)
		}

		toDestination := net.JoinHostPort(proxyV4.String(), strconv.Itoa(t.ProxyPort))
		natSubName := t.NatChain(opts.ChainName)
		sources := policymodel.SortSources(t.AllowSources)

		natSub := make([]iptables.Rule, 0, len(sources))
		if opts.Mode == policymodel.ModeEnforce {
			for _, src := range sources {
				natSub = append(natSub, iptables.Rule{
					// -p tcp 必须显式带上：iptables 规定 --to-destination 带端口时
					// 必须先匹配协议，否则报 "Need TCP, UDP, SCTP or DCCP with port
					// specification" 并退出码 2
					SrcPrefix:     src,
					Protocol:      "tcp",
					Action:        iptables.ActionDNAT,
					ToDestination: toDestination,
					Comment:       fmt.Sprintf("%s %s ← %s", comment, t.Key(), src),
				})
			}
		} else {
			// disabled / observe：不做源匹配，保持改造前的「所有 Pod 都走代理」行为
			natSub = append(natSub, iptables.Rule{
				Protocol:      "tcp",
				Action:        iptables.ActionDNAT,
				ToDestination: toDestination,
				Comment:       fmt.Sprintf(i18n.Text("%s %s（不限源）"), comment, t.Key()),
			})
		}
		plan.Chains = append(plan.Chains, iptables.Chain{
			Table: iptables.TableNat, Name: natSubName, Rules: natSub,
		})

		if opts.Mode != policymodel.ModeDisabled {
			denySubName := t.DenyChain(opts.ChainName)
			denySub := make([]iptables.Rule, 0, len(sources)+1)
			for _, src := range sources {
				denySub = append(denySub, iptables.Rule{
					SrcPrefix: src,
					Action:    iptables.ActionReturn,
					Comment:   fmt.Sprintf(i18n.Text("%s 已授权 %s"), comment, src),
				})
			}
			if opts.Mode == policymodel.ModeObserve {
				denySub = append(denySub, iptables.Rule{
					Action:    iptables.ActionLog,
					LogPrefix: denyLogPrefix,
					Comment:   fmt.Sprintf(i18n.Text("%s 观察模式：记录本应被拒的连接 %s"), comment, t.Key()),
				})
			} else {
				denySub = append(denySub, iptables.Rule{
					Action: iptables.ActionReject,
					// 同理：--reject-with tcp-reset 要求规则本身匹配 tcp
					Protocol:   "tcp",
					RejectWith: "tcp-reset",
					Comment:    fmt.Sprintf(i18n.Text("%s 未授权访问 %s"), comment, t.Key()),
				})
			}
			plan.Chains = append(plan.Chains, iptables.Chain{
				Table: iptables.TableFilter, Name: denySubName, Rules: denySub,
			})
		}

		// 目标地址 → 子链的跳转（域名型目标可能有多个 IP）
		for _, ip := range sortedIPs(t.IPs) {
			v4 := ip.To4()
			if v4 == nil {
				continue
			}
			prefix := v4.String() + "/32"
			natMain = append(natMain, iptables.Rule{
				DstPrefix:  prefix,
				Protocol:   "tcp",
				Port:       t.Port,
				Action:     iptables.ActionJump,
				JumpTarget: natSubName,
				Comment:    fmt.Sprintf("%s %s → %s", comment, t.Key(), v4),
			})
			if opts.Mode != policymodel.ModeDisabled {
				denyMain = append(denyMain, iptables.Rule{
					DstPrefix:  prefix,
					Protocol:   "tcp",
					Port:       t.Port,
					Action:     iptables.ActionJump,
					JumpTarget: t.DenyChain(opts.ChainName),
					Comment:    fmt.Sprintf(i18n.Text("%s 拒绝未授权访问 %s"), comment, t.Key()),
				})
			}
		}
	}

	// 主链内容在收集完跳转后回填
	for i := range plan.Chains {
		switch {
		case plan.Chains[i].Table == iptables.TableNat && plan.Chains[i].Name == opts.ChainName:
			plan.Chains[i].Rules = natMain
		case plan.Chains[i].Table == iptables.TableFilter && plan.Chains[i].Name == DenyMainChain(opts):
			plan.Chains[i].Rules = denyMain
		}
	}

	plan.Jumps = append(plan.Jumps,
		iptables.Jump{Table: iptables.TableNat, Parent: "PREROUTING", Child: opts.ChainName, Position: 1},
	)
	if opts.IncludeOutput {
		plan.Jumps = append(plan.Jumps,
			iptables.Jump{Table: iptables.TableNat, Parent: "OUTPUT", Child: opts.ChainName, Position: 1},
		)
	}
	if opts.Mode != policymodel.ModeDisabled {
		plan.Jumps = append(plan.Jumps,
			iptables.Jump{Table: iptables.TableFilter, Parent: "FORWARD", Child: DenyMainChain(opts), Position: 1},
		)
		if opts.IncludeOutput {
			plan.Jumps = append(plan.Jumps,
				iptables.Jump{Table: iptables.TableFilter, Parent: "OUTPUT", Child: DenyMainChain(opts), Position: 1},
			)
		}
	}

	if err := plan.Validate(); err != nil {
		return iptables.Plan{}, err
	}
	return plan, nil
}

// shortHash 返回目标键的短哈希，用于生成稳定且不超长的子链名
func shortHash(key string) string {
	sum := sha1.Sum([]byte(key))
	return hex.EncodeToString(sum[:])[:hashLen]
}

func sortedIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	seen := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		text := v4.String()
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}
		out = append(out, v4)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].To4(), out[j].To4()
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		return false
	})
	return out
}

func normalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			return "", i18n.NewCoded(msgInvalidIPv4OrCIDR)
		}
		return ip.To4().String() + "/32", nil
	}
	_, ipnet, err := net.ParseCIDR(s)
	if err != nil || ipnet.IP.To4() == nil {
		return "", i18n.NewCoded(msgInvalidIPv4CIDR)
	}
	return ipnet.String(), nil
}
