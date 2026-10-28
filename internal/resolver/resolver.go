// Package resolver 负责把配置中的域名解析为 IPv4 地址并缓存
//
// 各工作节点上的 redirect-agent 独立解析域名（设计文档要求），因此本包不做跨节点
// 共享缓存；解析失败时保留上一次成功的结果，绝不清空已有规则
package resolver

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"egress-proxy/internal/i18n"
)

// DefaultTimeout 是单次 DNS 查询的超时
const DefaultTimeout = 5 * time.Second

// LookupFunc 按主机名返回 IPv4 地址列表
type LookupFunc func(ctx context.Context, host string) ([]net.IP, error)

// Options 配置 Resolver
type Options struct {
	// DNSServers 为形如 "10.96.0.10:53" 的服务器列表；为空则使用系统配置
	DNSServers []string
	// MaxIPsPerHost 限制单个域名保留的最大 IP 数（默认 8）
	MaxIPsPerHost int
	// Timeout 为单次解析超时（默认 5s）
	Timeout time.Duration
	// Logger 可为 nil
	Logger *slog.Logger
	// Lookup 用于测试注入，nil 时使用系统解析器
	Lookup LookupFunc
}

// Resolver 缓存域名到 IPv4 地址列表的映射
type Resolver struct {
	mu      sync.RWMutex
	ips     map[string][]net.IP
	errs    map[string]error
	lookup  LookupFunc
	maxIPs  int
	timeout time.Duration
	log     *slog.Logger
}

// New 创建一个 Resolver
func New(opts Options) *Resolver {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxIPs := opts.MaxIPsPerHost
	if maxIPs <= 0 {
		maxIPs = 8
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	lookup := opts.Lookup
	if lookup == nil {
		lookup = newNetLookup(opts.DNSServers, timeout)
	}
	return &Resolver{
		ips:     make(map[string][]net.IP),
		errs:    make(map[string]error),
		lookup:  lookup,
		maxIPs:  maxIPs,
		timeout: timeout,
		log:     log,
	}
}

// IsLiteralIPv4 判断 host 是否本身就是 IPv4 字面量
func IsLiteralIPv4(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.To4() != nil
}

// ParseLiteralIPv4 把 IPv4 字面量解析为 4 字节地址，失败返回 nil
func ParseLiteralIPv4(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip.To4()
	}
	return nil
}

// IPs 返回某主机当前缓存的 IPv4 列表（副本）
// 若 host 为 IPv4 字面量则直接返回该地址
func (r *Resolver) IPs(host string) []net.IP {
	if ip := ParseLiteralIPv4(host); ip != nil {
		return []net.IP{ip}
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return copyIPs(r.ips[host])
}

// Snapshot 返回所有缓存条目的副本，仅包含域名
func (r *Resolver) Snapshot() map[string][]net.IP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]net.IP, len(r.ips))
	for host, ips := range r.ips {
		out[host] = copyIPs(ips)
	}
	return out
}

// Error 返回某主机最近一次解析错误，nil 表示最近一次成功
func (r *Resolver) Error(host string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.errs[host]
}

// Refresh 解析 hosts 中的域名并更新缓存，返回是否有主机的解析结果发生变化
// 解析失败的域名保留上一次结果（包括「从未成功过」的 nil），并记录错误
// hosts 之外的缓存条目会被清理
func (r *Resolver) Refresh(ctx context.Context, hosts []string) bool {
	wanted := make(map[string]struct{}, len(hosts))
	changed := false

	for _, host := range hosts {
		if host == "" || IsLiteralIPv4(host) {
			continue
		}
		wanted[host] = struct{}{}

		ips, err := r.lookupWithTimeout(ctx, host)

		r.mu.Lock()
		if err != nil {
			r.errs[host] = err
			prev := copyIPs(r.ips[host])
			r.mu.Unlock()
			r.log.Warn(i18n.Text("域名解析失败，沿用上次结果"),
				"host", host, "cachedIPs", ipStrings(prev), "err", err)
			continue
		}
		prev, had := r.ips[host]
		r.ips[host] = copyIPs(ips)
		delete(r.errs, host)
		r.mu.Unlock()

		if !had || !EqualIPs(prev, ips) {
			changed = true
			r.log.Info(i18n.Text("域名解析结果变化"),
				"host", host, "previous", ipStrings(prev), "current", ipStrings(ips))
		}
	}

	// 清理配置中已删除的域名缓存
	r.mu.Lock()
	for host := range r.ips {
		if _, ok := wanted[host]; !ok {
			delete(r.ips, host)
			delete(r.errs, host)
		}
	}
	r.mu.Unlock()

	return changed
}

func (r *Resolver) lookupWithTimeout(ctx context.Context, host string) ([]net.IP, error) {
	lookupCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	ips, err := r.lookup(lookupCtx, host)
	if err != nil {
		return nil, err
	}

	ips = normalizeIPs(ips)
	if len(ips) == 0 {
		return nil, i18n.NewCoded(msgNoARecord, host)
	}
	if len(ips) > r.maxIPs {
		r.log.Warn(i18n.Text("域名解析结果超过上限，已截断"),
			"host", host, "count", len(ips), "maxIPsPerHost", r.maxIPs)
		ips = ips[:r.maxIPs]
	}
	return ips, nil
}

func newNetLookup(servers []string, timeout time.Duration) LookupFunc {
	var res *net.Resolver
	if len(servers) > 0 {
		var counter atomic.Uint64
		res = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				i := counter.Add(1) - 1
				server := servers[int(i%uint64(len(servers)))]
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, server)
			},
		}
	} else {
		res = net.DefaultResolver
	}

	return func(ctx context.Context, host string) ([]net.IP, error) {
		addrs, err := res.LookupIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			if v4 := addr.To4(); v4 != nil {
				ips = append(ips, v4)
			}
		}
		return ips, nil
	}
}

// normalizeIPs 去重、按字节序排序，保证结果稳定可比
func normalizeIPs(ips []net.IP) []net.IP {
	seen := make(map[string]net.IP, len(ips))
	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		key := v4.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = v4
	}
	out := make([]net.IP, 0, len(seen))
	for _, ip := range seen {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i], out[j]) < 0 })
	return out
}

// EqualIPs 按地址集合比较（顺序、重复无关）
func EqualIPs(a, b []net.IP) bool {
	na, nb := normalizeIPs(a), normalizeIPs(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if !na[i].Equal(nb[i]) {
			return false
		}
	}
	return true
}

func copyIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, len(ips))
	for i, ip := range ips {
		out[i] = append(net.IP(nil), ip...)
	}
	return out
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}
