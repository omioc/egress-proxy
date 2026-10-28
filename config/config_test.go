package config

import (
	"net"
	"strings"
	"testing"
	"time"
)

// docExample 是设计文档中的完整示例
const docExample = `
proxy:
  address: "10.238.29.6"

targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001

  - host: b.example.com
    port: 443
    proxyPort: 20002

  - host: b.example.com
    port: 8443
    proxyPort: 20003

  - host: 10.20.30.40
    port: 5432
    proxyPort: 20004

  - host: 10.20.30.40
    port: 3306
    proxyPort: 20005

  - host: 10.20.30.41
    port: 3306
    proxyPort: 20006
`

func TestParseDocExample(t *testing.T) {
	cfg, err := Parse([]byte(docExample))
	if err != nil {
		t.Fatalf("Parse(docExample) 返回错误: %v", err)
	}
	if cfg.Proxy.Address != "10.238.29.6" {
		t.Errorf("Proxy.Address = %q, 期望 10.238.29.6", cfg.Proxy.Address)
	}
	if cfg.Proxy.Listen != DefaultListen {
		t.Errorf("Proxy.Listen = %q, 期望默认 %q", cfg.Proxy.Listen, DefaultListen)
	}
	if len(cfg.Targets) != 6 {
		t.Fatalf("len(Targets) = %d, 期望 6", len(cfg.Targets))
	}
	if got := cfg.Targets[0]; got.Host != "a.example.com" || got.Port != 443 || got.ProxyPort != 20001 {
		t.Errorf("targets[0] = %+v, 期望 a.example.com:443 -> 20001", got)
	}
	if cfg.Hash == "" {
		t.Error("Hash 不能被设置为空")
	}

	// 默认值
	o := cfg.Options
	if o.ResolveInterval.D() != DefaultResolveInterval {
		t.Errorf("ResolveInterval = %s, 期望 %s", o.ResolveInterval, DefaultResolveInterval)
	}
	if o.ConfigInterval.D() != DefaultConfigInterval {
		t.Errorf("ConfigInterval = %s, 期望 %s", o.ConfigInterval, DefaultConfigInterval)
	}
	if o.SyncInterval.D() != DefaultSyncInterval {
		t.Errorf("SyncInterval = %s, 期望 %s", o.SyncInterval, DefaultSyncInterval)
	}
	if o.DialTimeout.D() != DefaultDialTimeout {
		t.Errorf("DialTimeout = %s, 期望 %s", o.DialTimeout, DefaultDialTimeout)
	}
	if o.MaxIPsPerHost != DefaultMaxIPsPerHost {
		t.Errorf("MaxIPsPerHost = %d, 期望 %d", o.MaxIPsPerHost, DefaultMaxIPsPerHost)
	}
	if o.IptablesBinary != DefaultIptablesBinary {
		t.Errorf("IptablesBinary = %q, 期望 %q", o.IptablesBinary, DefaultIptablesBinary)
	}
	if o.ChainName != DefaultChainName {
		t.Errorf("ChainName = %q, 期望 %q", o.ChainName, DefaultChainName)
	}
	if o.HealthPort != DefaultHealthPort {
		t.Errorf("HealthPort = %d, 期望 %d", o.HealthPort, DefaultHealthPort)
	}

	// 域名去重且排序
	hosts := cfg.DomainHosts()
	want := []string{"a.example.com", "b.example.com"}
	if len(hosts) != len(want) {
		t.Fatalf("DomainHosts() = %v, 期望 %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Fatalf("DomainHosts() = %v, 期望 %v", hosts, want)
		}
	}

	// IP 判定
	if cfg.Targets[0].IsIP() {
		t.Error("a.example.com 不應被判定为 IP")
	}
	if !cfg.Targets[3].IsIP() {
		t.Error("10.20.30.40 应被判定为 IP")
	}
	if got := cfg.Targets[3].Addr(); got != "10.20.30.40:5432" {
		t.Errorf("Addr() = %q", got)
	}

	// 代理节点判定
	if !cfg.IsProxyNode(net.ParseIP("10.238.29.6")) {
		t.Error("IsProxyNode(10.238.29.6) 应为 true")
	}
	if cfg.IsProxyNode(net.ParseIP("10.238.29.7")) {
		t.Error("IsProxyNode(10.238.29.7) 应为 false")
	}
	if cfg.IsProxyNode(nil) {
		t.Error("IsProxyNode(nil) 应为 false")
	}
}

func TestParseOptionsExplicit(t *testing.T) {
	yml := `
proxy:
  address: 10.238.29.6
  listen: 127.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  resolveInterval: 5s
  configInterval: 1s
  syncInterval: "90s"
  dialTimeout: 3
  maxIPsPerHost: 2
  iptablesBinary: iptables-legacy
  chainName: MY-PROXY
  healthPort: 19000
  dnsServers:
    - 10.96.0.10
    - 8.8.8.8:5353
  excludeCIDRs:
    - 10.244.0.0/16
    - 10.96.0.0/12
`
	cfg, err := Parse([]byte(yml))
	if err != nil {
		t.Fatalf("Parse 返回错误: %v", err)
	}
	o := cfg.Options
	if o.ResolveInterval.D() != 5*time.Second {
		t.Errorf("ResolveInterval = %s, 期望 5s", o.ResolveInterval)
	}
	if o.ConfigInterval.D() != time.Second {
		t.Errorf("ConfigInterval = %s, 期望 1s", o.ConfigInterval)
	}
	if o.SyncInterval.D() != 90*time.Second {
		t.Errorf("SyncInterval = %s, 期望 90s", o.SyncInterval)
	}
	if o.DialTimeout.D() != 3*time.Second {
		t.Errorf("DialTimeout = %s, 期望 3s（整数秒写法）", o.DialTimeout)
	}
	if o.MaxIPsPerHost != 2 {
		t.Errorf("MaxIPsPerHost = %d, 期望 2", o.MaxIPsPerHost)
	}
	if o.IptablesBinary != "iptables-legacy" {
		t.Errorf("IptablesBinary = %q", o.IptablesBinary)
	}
	if o.ChainName != "MY-PROXY" {
		t.Errorf("ChainName = %q", o.ChainName)
	}
	if o.HealthPort != 19000 {
		t.Errorf("HealthPort = %d", o.HealthPort)
	}
	if cfg.Proxy.Listen != "127.0.0.1" {
		t.Errorf("Listen = %q", cfg.Proxy.Listen)
	}
	if got := cfg.NormalizeDNSServers(); len(got) != 2 || got[0] != "10.96.0.10:53" || got[1] != "8.8.8.8:5353" {
		t.Errorf("NormalizeDNSServers() = %v", got)
	}
}

func TestParseInvalid(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name: "缺少 proxy.address",
			yaml: `
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
`,
			wantSub: "proxy.address 不能为空",
		},
		{
			name: "proxy.address 非法",
			yaml: `
proxy:
  address: not-an-ip
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
`,
			wantSub: "不是合法 IP",
		},
		{
			name: "proxy.address 为 IPv6",
			yaml: `
proxy:
  address: "fd00::1"
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
`,
			wantSub: "不是 IPv4",
		},
		{
			name: "host+port 重复",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
  - host: a.example.com
    port: 443
    proxyPort: 20002
`,
			wantSub: "重复",
		},
		{
			name: "proxyPort 重复",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
  - host: b.example.com
    port: 443
    proxyPort: 20001
`,
			wantSub: "必须全局唯一",
		},
		{
			name: "端口越界",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 70000
    proxyPort: 20001
`,
			wantSub: "超出范围",
		},
		{
			name: "端口为 0",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 0
`,
			wantSub: "超出范围",
		},
		{
			name: "IPv6 目标",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: "fd00::2"
    port: 443
    proxyPort: 20001
`,
			wantSub: "仅支持 IPv4",
		},
		{
			name: "主机名含非法字符",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: "bad_host!.example.com"
    port: 443
    proxyPort: 20001
`,
			wantSub: "非法字符",
		},
		{
			name: "host 写成 host:port",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: "a.example.com:443"
    port: 443
    proxyPort: 20001
`,
			wantSub: "host 字段只写主机名",
		},
		{
			name: "excludeCIDRs 为 IPv6",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  excludeCIDRs:
    - "fd00::/8"
`,
			wantSub: "仅支持 IPv4 网段",
		},
		{
			name: "excludeCIDRs 非法",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  excludeCIDRs:
    - "10.0.0.0/99"
`,
			wantSub: "excludeCIDRs[0]",
		},
		{
			name: "chainName 为内建链",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  chainName: OUTPUT
`,
			wantSub: "内建链",
		},
		{
			name: "chainName 含非法字符",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  chainName: "bad chain"
`,
			wantSub: "非法字符",
		},
		{
			name: "iptablesBinary 带路径",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  iptablesBinary: /sbin/iptables
`,
			wantSub: "iptablesBinary",
		},
		{
			name: "duration 非法",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  resolveInterval: "abc"
`,
			wantSub: "invalid duration",
		},
		{
			name: "duration 过小",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  resolveInterval: 10ms
`,
			wantSub: "不能小于",
		},
		{
			name: "maxIPsPerHost 非法",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  maxIPsPerHost: -1
`,
			wantSub: "maxIPsPerHost",
		},
		{
			name: "dnsServers 非法",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  dnsServers:
    - "dns.example.com"
`,
			wantSub: "dnsServers[0]",
		},
		{
			name: "healthPort 越界",
			yaml: `
proxy:
  address: 10.0.0.1
targets:
  - host: a.example.com
    port: 443
    proxyPort: 20001
options:
  healthPort: 70000
`,
			wantSub: "healthPort",
		},
		{
			name:    "YAML 语法错误",
			yaml:    "proxy: [address",
			wantSub: "解析 YAML 失败",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil {
				t.Fatalf("期望报错，但 Parse 成功")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("错误信息 %q 未包含 %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestHashChangesWithContent(t *testing.T) {
	a, err := Parse([]byte(docExample))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse([]byte(docExample))
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash != b.Hash {
		t.Errorf("相同内容应产生相同 Hash: %s != %s", a.Hash, b.Hash)
	}

	modified := strings.Replace(docExample, "20001", "21001", 1)
	c, err := Parse([]byte(modified))
	if err != nil {
		t.Fatal(err)
	}
	if c.Hash == a.Hash {
		t.Error("内容变化后 Hash 应不同")
	}
}

func TestSortedTargets(t *testing.T) {
	cfg, err := Parse([]byte(docExample))
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.SortedTargets()
	// 期望顺序：按 host 升序（数字排在字母前），同一 host 内按 port 升序
	want := []string{
		"10.20.30.40", "10.20.30.40", "10.20.30.41",
		"a.example.com", "b.example.com", "b.example.com",
	}
	if len(got) != len(want) {
		t.Fatalf("len(SortedTargets()) = %d, 期望 %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Host != want[i] {
			t.Fatalf("SortedTargets()[%d].Host = %q, 期望 %q", i, got[i].Host, want[i])
		}
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Host == got[i].Host && got[i-1].Port > got[i].Port {
			t.Fatalf("同一 host 内未按 port 升序: %v", got)
		}
	}
	if got[0].Port != 3306 {
		t.Errorf("10.20.30.40 内应先排序 port 3306，实际 %d", got[0].Port)
	}
	// 原始切片不应被修改
	if cfg.Targets[0].Host != "a.example.com" {
		t.Error("SortedTargets 不应修改原切片顺序")
	}
}

func TestParseCIDRAndHostValidation(t *testing.T) {
	if _, err := ParseCIDR("10.244.0.0/16"); err != nil {
		t.Errorf("ParseCIDR(10.244.0.0/16) 报错: %v", err)
	}
	if got, err := ParseCIDR("10.0.0.1/8"); err != nil || got != "10.0.0.0/8" {
		t.Errorf("ParseCIDR 应返回规范化网段，得到 %q err=%v", got, err)
	}

	valid := []string{"a.example.com", "a-b.example.com", "10.1.2.3", "a.example.com.", "svc_name.example.com"}
	for _, h := range valid {
		if err := validateHost(h); err != nil {
			t.Errorf("validateHost(%q) 期望通过，实际 %v", h, err)
		}
	}
	invalid := []string{"", "-a.example.com", "a-.example.com", "a..b", "a b", "a/b", "10.0.0.1:443"}
	for _, h := range invalid {
		if err := validateHost(h); err == nil {
			t.Errorf("validateHost(%q) 期望失败", h)
		}
	}

	long := strings.Repeat("a", 64) + ".example.com"
	if err := validateHost(long); err == nil {
		t.Error("超长标签应校验失败")
	}
}

func TestParseToleratesUTF8BOM(t *testing.T) {
	// Windows 的记事本 / PowerShell 另存为 UTF-8 时可能在文件开头写入 BOM
	// 配置来自 ConfigMap 挂载文件（很可能是人在 Windows 上编辑的），必须容忍这种情况
	withBOM := append([]byte{0xEF, 0xBB, 0xBF}, []byte(docExample)...)

	cfg, err := Parse(withBOM)
	if err != nil {
		t.Fatalf("带 UTF-8 BOM 的配置应能正常解析，实际报错: %v", err)
	}
	if cfg.Proxy.Address != "10.238.29.6" {
		t.Errorf("proxy.address = %q，期望 10.238.29.6", cfg.Proxy.Address)
	}
	if len(cfg.Targets) != 6 {
		t.Errorf("len(Targets) = %d，期望 6", len(cfg.Targets))
	}

	// 有 BOM 与无 BOM 的内容应被视为同一份配置（避免无谓的规则重建）
	plain, err := Parse([]byte(docExample))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hash != plain.Hash {
		t.Errorf("带 BOM 与不带 BOM 的相同配置应产生相同 Hash: %s != %s", cfg.Hash, plain.Hash)
	}
}
