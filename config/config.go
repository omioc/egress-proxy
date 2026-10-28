// Package config 定义并校验 egress-proxy 的配置
//
// 配置以 YAML 形式存放于 ConfigMap（data key: config.yaml），由 redirect-agent
// （DaemonSet）与 tcp-forwarder（代理节点服务）共同读取，两者使用完全相同的
// 解析、默认值与校验逻辑
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"egress-proxy/internal/i18n"

	"gopkg.in/yaml.v3"
)

// 默认值
const (
	DefaultListen          = "0.0.0.0"
	DefaultResolveInterval = 30 * time.Second
	DefaultConfigInterval  = 2 * time.Second
	DefaultSyncInterval    = 60 * time.Second
	DefaultDialTimeout     = 5 * time.Second
	DefaultMaxIPsPerHost   = 8
	DefaultIptablesBinary  = "iptables"
	DefaultChainName       = "EGRESS-PROXY"
	DefaultHealthPort      = 18081
	DefaultPolicyInterval  = 2 * time.Second

	// MinInterval 是各项轮询/重解析周期的下限，避免误配置导致空转
	MinInterval = 500 * time.Millisecond
)

// Duration 包装 time.Duration，使其可从 YAML 字符串（"30s"）或整数（秒）解析
type Duration time.Duration

// D 返回标准库的 time.Duration
func (d Duration) D() time.Duration { return time.Duration(d) }

// String 实现 fmt.Stringer
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML 支持 "30s" / "2m" 字符串与整数秒两种写法
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err == nil {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			*d = 0
			return nil
		}
		parsed, perr := time.ParseDuration(raw)
		if perr != nil {
			// 允许纯数字字符串，按秒处理
			if secs, nerr := strconv.ParseInt(raw, 10, 64); nerr == nil {
				*d = Duration(time.Duration(secs) * time.Second)
				return nil
			}
			return fmt.Errorf("invalid duration %q: %w", raw, perr)
		}
		*d = Duration(parsed)
		return nil
	}

	var secs int64
	if err := value.Decode(&secs); err != nil {
		return fmt.Errorf(i18n.Text("invalid duration %q: 需要形如 \"30s\" 的字符串或整数秒"), value.Value)
	}
	*d = Duration(time.Duration(secs) * time.Second)
	return nil
}

// MarshalYAML 输出可读的字符串形式
func (d Duration) MarshalYAML() (interface{}, error) { return time.Duration(d).String(), nil }

// ProxyConfig 描述代理节点信息
type ProxyConfig struct {
	// Address 是代理节点 IP（IPv4），工作节点会把命中的流量 DNAT 到该地址
	Address string `yaml:"address"`
	// Listen 是 tcp-forwarder 的监听地址，默认 0.0.0.0
	Listen string `yaml:"listen"`
}

// Target 是一条原始目标与服务端口、代理监听端口的映射
type Target struct {
	// Host 为域名或 IPv4 字面量
	Host string `yaml:"host"`
	// Port 为原始目标端口
	Port int `yaml:"port"`
	// ProxyPort 为代理节点上的监听端口，必须全局唯一
	ProxyPort int `yaml:"proxyPort"`
}

// IsIP 判断 Host 是否为 IP 字面量
func (t Target) IsIP() bool { return net.ParseIP(t.Host) != nil }

// Addr 返回原始目标的 host:port
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Key 返回用于唯一性校验的 host:port
func (t Target) Key() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// String 便于日志输出
func (t Target) String() string {
	return fmt.Sprintf("%s -> proxyPort %d", t.Addr(), t.ProxyPort)
}

// Options 是可选的运行参数，全部有默认值
type Options struct {
	ResolveInterval Duration `yaml:"resolveInterval"`
	ConfigInterval  Duration `yaml:"configInterval"`
	SyncInterval    Duration `yaml:"syncInterval"`
	DialTimeout     Duration `yaml:"dialTimeout"`
	MaxIPsPerHost   int      `yaml:"maxIPsPerHost"`
	IptablesBinary  string   `yaml:"iptablesBinary"`
	ChainName       string   `yaml:"chainName"`
	HealthPort      int      `yaml:"healthPort"`
	DNSServers      []string `yaml:"dnsServers"`
	ExcludeCIDRs    []string `yaml:"excludeCIDRs"`
	// PolicyURL 是控制器地址，例如 http://egress-proxy-controller.egress-proxy.svc:18082
	// 为空表示未启用四元组管控，退回「按配置文件的 targets 全量直通代理」的旧行为
	PolicyURL string `yaml:"policyUrl"`
	// PolicyInterval 是向控制器拉取编译结果（四元组策略）的周期，默认 2s
	PolicyInterval Duration `yaml:"policyInterval"`
}

// Config 是完整配置
type Config struct {
	Proxy   ProxyConfig `yaml:"proxy"`
	Targets []Target    `yaml:"targets"`
	Options Options     `yaml:"options"`

	// Hash 是配置文件内容的 SHA-256，用于判断配置是否变化
	Hash string `yaml:"-"`
}

// utf8BOM 是 UTF-8 字节序标记；Windows 的记事本 / PowerShell 另存为 UTF-8 时可能写入，
// 这里显式去掉：既避免影响 YAML 解析，也让「有 BOM / 无 BOM 的同一份配置」哈希一致
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Parse 解析并校验配置内容，同时填充默认值与内容哈希
func Parse(data []byte) (*Config, error) {
	data = bytes.TrimPrefix(data, utf8BOM)
	sum := sha256.Sum256(data)

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf(i18n.Text("解析 YAML 失败: %w"), err)
	}
	cfg.Hash = hex.EncodeToString(sum[:])
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Load 从文件读取配置（用于启动引导与本地调试）
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Proxy.Listen == "" {
		c.Proxy.Listen = DefaultListen
	}
	o := &c.Options
	if o.ResolveInterval <= 0 {
		o.ResolveInterval = Duration(DefaultResolveInterval)
	}
	if o.ConfigInterval <= 0 {
		o.ConfigInterval = Duration(DefaultConfigInterval)
	}
	if o.SyncInterval <= 0 {
		o.SyncInterval = Duration(DefaultSyncInterval)
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = Duration(DefaultDialTimeout)
	}
	if o.MaxIPsPerHost == 0 {
		o.MaxIPsPerHost = DefaultMaxIPsPerHost
	}
	if o.IptablesBinary == "" {
		o.IptablesBinary = DefaultIptablesBinary
	}
	if o.ChainName == "" {
		o.ChainName = DefaultChainName
	}
	if o.HealthPort == 0 {
		o.HealthPort = DefaultHealthPort
	}
	if o.PolicyInterval <= 0 {
		o.PolicyInterval = Duration(DefaultPolicyInterval)
	}
}

// ProxyIP 返回解析后的代理节点 IPv4 地址
func (c *Config) ProxyIP() net.IP {
	return net.ParseIP(c.Proxy.Address).To4()
}

// DomainHosts 返回所有域名型目标去重并排序后的主机名
func (c *Config) DomainHosts() []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, t := range c.Targets {
		if t.IsIP() {
			continue
		}
		if _, ok := seen[t.Host]; ok {
			continue
		}
		seen[t.Host] = struct{}{}
		hosts = append(hosts, t.Host)
	}
	sort.Strings(hosts)
	return hosts
}

// SortedTargets 返回按 host、port、proxyPort 排序的目标副本，保证规则生成稳定
func (c *Config) SortedTargets() []Target {
	out := make([]Target, len(c.Targets))
	copy(out, c.Targets)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host != out[j].Host {
			return out[i].Host < out[j].Host
		}
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].ProxyPort < out[j].ProxyPort
	})
	return out
}

// IsProxyNode 判断给定节点 IP 是否为配置中的代理节点
func (c *Config) IsProxyNode(nodeIP net.IP) bool {
	proxy := c.ProxyIP()
	if proxy == nil || nodeIP == nil {
		return false
	}
	return proxy.Equal(nodeIP.To4())
}

// Validate 返回所有校验错误；完全合法时返回 nil
func (c *Config) Validate() error {
	var errs []string
	addf := func(format string, args ...interface{}) {
		errs = append(errs, fmt.Sprintf(format, args...))
	}

	if strings.TrimSpace(c.Proxy.Address) == "" {
		addf(i18n.Text("proxy.address 不能为空（需填写代理节点的 IPv4 地址）"))
	} else if ip := net.ParseIP(c.Proxy.Address); ip == nil {
		addf(i18n.Text("proxy.address %q 不是合法 IP"), c.Proxy.Address)
	} else if ip.To4() == nil {
		addf(i18n.Text("proxy.address %q 不是 IPv4（第一阶段仅支持 IPv4）"), c.Proxy.Address)
	}

	// targets 允许为空：
	//   * 启用四元组管控（options.policyUrl 非空）时，targets 完全由控制器下发；
	//   * 未启用时，空 targets 表示「不代理任何目标」，是一种合法的空策略
	// 因此这里只校验每一项的合法性，不要求至少一条

	if err := validateListen(c.Proxy.Listen); err != nil {
		addf(i18n.Text("proxy.listen 无效: %v"), err)
	}

	seenTarget := make(map[string]int, len(c.Targets))
	seenProxyPort := make(map[int]string, len(c.Targets))
	for i, t := range c.Targets {
		where := fmt.Sprintf("targets[%d]", i)
		if err := validateHost(t.Host); err != nil {
			addf("%s (%s): %v", where, t.Host, err)
		}
		if err := validatePort(t.Port); err != nil {
			addf("%s (%s): port %v", where, t.Host, err)
		}
		if err := validatePort(t.ProxyPort); err != nil {
			addf("%s (%s): proxyPort %v", where, t.Host, err)
		}
		if t.Host != "" && t.Port > 0 {
			key := t.Key()
			if prev, ok := seenTarget[key]; ok {
				addf(i18n.Text("%s: host+port 组合 %s 与 targets[%d] 重复"), where, key, prev)
			} else {
				seenTarget[key] = i
			}
		}
		if t.ProxyPort > 0 {
			if prev, ok := seenProxyPort[t.ProxyPort]; ok {
				addf(i18n.Text("%s: proxyPort %d 与 %s 重复，必须全局唯一"), where, t.ProxyPort, prev)
			} else {
				seenProxyPort[t.ProxyPort] = t.Key()
			}
		}
	}

	o := c.Options
	checkInterval := func(name string, d Duration) {
		if d > 0 && d.D() < MinInterval {
			addf(i18n.Text("options.%s 过小（%s），不能小于 %s"), name, d, MinInterval)
		}
	}
	checkInterval("resolveInterval", o.ResolveInterval)
	checkInterval("configInterval", o.ConfigInterval)
	checkInterval("syncInterval", o.SyncInterval)
	checkInterval("dialTimeout", o.DialTimeout)
	checkInterval("policyInterval", o.PolicyInterval)

	if o.MaxIPsPerHost < 0 {
		addf(i18n.Text("options.maxIPsPerHost 不能为负数，当前 %d"), o.MaxIPsPerHost)
	}
	if o.HealthPort < 0 || o.HealthPort > 65535 {
		addf(i18n.Text("options.healthPort %d 超出范围 1-65535"), o.HealthPort)
	}
	if err := validateChainName(o.ChainName); err != nil {
		addf(i18n.Text("options.chainName 无效: %v"), err)
	}
	if err := validateBinary(o.IptablesBinary); err != nil {
		addf(i18n.Text("options.iptablesBinary 无效: %v"), err)
	}
	for i, cidr := range o.ExcludeCIDRs {
		if _, err := ParseCIDR(cidr); err != nil {
			addf(i18n.Text("options.excludeCIDRs[%d] %q 无效: %v"), i, cidr, err)
		}
	}
	for i, srv := range o.DNSServers {
		if _, err := normalizeDNSServer(srv); err != nil {
			addf(i18n.Text("options.dnsServers[%d] %q 无效: %v"), i, srv, err)
		}
	}

	if raw := strings.TrimSpace(o.PolicyURL); raw != "" {
		if u, err := url.Parse(raw); err != nil {
			addf(i18n.Text("options.policyUrl %q 无效: %v"), raw, err)
		} else if u.Scheme != "http" && u.Scheme != "https" {
			addf(i18n.Text("options.policyUrl %q 必须以 http:// 或 https:// 开头"), raw)
		} else if u.Host == "" {
			addf(i18n.Text("options.policyUrl %q 缺少主机名"), raw)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf(i18n.Text("配置校验失败:\n  - %s"), strings.Join(errs, "\n  - "))
}

// ParseCIDR 解析 IPv4 CIDR，返回规范化后的网段字符串
func ParseCIDR(s string) (string, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	if ipnet.IP.To4() == nil {
		return "", fmt.Errorf(i18n.Text("仅支持 IPv4 网段"))
	}
	return ipnet.String(), nil
}

// NormalizeDNSServers 把配置中的 DNS 服务器规范化为 host:port 形式
func (c *Config) NormalizeDNSServers() []string {
	out := make([]string, 0, len(c.Options.DNSServers))
	for _, s := range c.Options.DNSServers {
		if normalized, err := normalizeDNSServer(s); err == nil {
			out = append(out, normalized)
		}
	}
	return out
}

func normalizeDNSServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf(i18n.Text("不能为空"))
	}
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf(i18n.Text("需要 IP 或 IP:port 形式"))
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf(i18n.Text("%q 不是合法 IP"), host)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf(i18n.Text("端口 %q 无效"), port)
	}
	return net.JoinHostPort(host, port), nil
}

func validateListen(s string) error {
	if s == "" {
		return fmt.Errorf(i18n.Text("不能为空"))
	}
	if ip := net.ParseIP(s); ip != nil {
		return nil
	}
	// 允许绑定 hostname（如 localhost）之外的形式会被拒绝；这里只需保证可用于 join
	if strings.ContainsAny(s, " \t/\\") {
		return fmt.Errorf(i18n.Text("包含非法字符"))
	}
	return nil
}

// validateHostLang 校验目标 host（域名或 IPv4 字面量）；错误文案按语言渲染，供策略模型复用
func validateHostLang(l i18n.Lang, host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return msgHostEmpty.E(l)
	}
	trimmed := strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(trimmed); ip != nil {
		if ip.To4() == nil {
			return msgHostIPv6Only.E(l, host)
		}
		return nil
	}
	if strings.Contains(trimmed, ":") {
		return msgHostLooksPort.E(l, host)
	}
	if len(trimmed) > 253 {
		return msgHostTooLong.E(l, len(trimmed))
	}
	labels := strings.Split(trimmed, ".")
	for _, label := range labels {
		if label == "" {
			return msgHostEmptyLabel.E(l, host)
		}
		if len(label) > 63 {
			return msgHostLabelTooLong.E(l, host, label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return msgHostLabelHyphen.E(l, host, label)
		}
		for _, r := range label {
			switch {
			case r >= 'a' && r <= 'z',
				r >= 'A' && r <= 'Z',
				r >= '0' && r <= '9',
				r == '-', r == '_':
			default:
				return msgHostBadChar.E(l, host, string(r))
			}
		}
	}
	return nil
}

// validateHost 是中文默认实现的包装，供 Parse 与既有调用点使用
func validateHost(host string) error { return validateHostLang(i18n.ProcessLang(), host) }

func validatePortLang(l i18n.Lang, p int) error {
	if p < 1 || p > 65535 {
		return msgPortOutOfRange.E(l, p)
	}
	return nil
}

// validatePort 是中文默认实现的包装，供 Parse 与既有调用点使用
func validatePort(p int) error { return validatePortLang(i18n.ProcessLang(), p) }

// ValidateHost 校验目标 host（域名或 IPv4 字面量），供策略模型复用
func ValidateHost(host string) error { return validateHostLang(i18n.ZH, host) }

// ValidateHostLang 同 ValidateHost，但按语言返回文案
func ValidateHostLang(l i18n.Lang, host string) error { return validateHostLang(l, host) }

// ValidatePort 校验端口是否落在 1-65535，供策略模型复用
func ValidatePort(p int) error { return validatePortLang(i18n.ZH, p) }

// ValidatePortLang 同 ValidatePort，但按语言返回文案
func ValidatePortLang(l i18n.Lang, p int) error { return validatePortLang(l, p) }

func validateChainName(name string) error {
	if name == "" {
		return fmt.Errorf(i18n.Text("不能为空"))
	}
	if len(name) > 28 {
		return fmt.Errorf(i18n.Text("长度 %d 超过 iptables 上限 28"), len(name))
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf(i18n.Text("不能以 - 开头"))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return fmt.Errorf(i18n.Text("含非法字符 %q（仅允许字母、数字、- 和 _）"), string(r))
		}
	}
	switch name {
	case "PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING":
		return fmt.Errorf(i18n.Text("%q 是 iptables 内建链，不能使用"), name)
	}
	return nil
}

func validateBinary(bin string) error {
	if bin == "" {
		return fmt.Errorf(i18n.Text("不能为空"))
	}
	if strings.ContainsAny(bin, " \t/\\") {
		return fmt.Errorf(i18n.Text("%q 不能包含空格或路径分隔符"), bin)
	}
	if filepath.Base(bin) != bin {
		return fmt.Errorf(i18n.Text("%q 只能是可执行文件名"), bin)
	}
	return nil
}
