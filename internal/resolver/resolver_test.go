package resolver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type fakeLookup struct {
	mu      sync.Mutex
	answers map[string][]net.IP
	errs    map[string]error
	calls   map[string]int
}

func newFakeLookup() *fakeLookup {
	return &fakeLookup{
		answers: make(map[string][]net.IP),
		errs:    make(map[string]error),
		calls:   make(map[string]int),
	}
}

func (f *fakeLookup) set(host string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var parsed []net.IP
	for _, s := range ips {
		parsed = append(parsed, net.ParseIP(s))
	}
	f.answers[host] = parsed
	delete(f.errs, host)
}

func (f *fakeLookup) fail(host string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.answers, host)
	f.errs[host] = err
}

func (f *fakeLookup) callCount(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

func (f *fakeLookup) lookup(_ context.Context, host string) ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[host]++
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	ips, ok := f.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	out := make([]net.IP, len(ips))
	copy(out, ips)
	return out, nil
}

func ipsOf(t *testing.T, r *Resolver, host string) []string {
	t.Helper()
	var out []string
	for _, ip := range r.IPs(host) {
		out = append(out, ip.String())
	}
	return out
}

func TestRefreshChangeDetection(t *testing.T) {
	f := newFakeLookup()
	f.set("a.example.com", "1.1.1.1", "2.2.2.2")
	r := New(Options{Lookup: f.lookup, Logger: quietLogger()})
	ctx := context.Background()

	if !r.Refresh(ctx, []string{"a.example.com"}) {
		t.Fatal("首次解析应判定为发生变化")
	}
	got := ipsOf(t, r, "a.example.com")
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "2.2.2.2" {
		t.Fatalf("IPs = %v, 期望 [1.1.1.1 2.2.2.2]", got)
	}
	if r.Error("a.example.com") != nil {
		t.Errorf("解析成功后 Error 应为 nil，实际 %v", r.Error("a.example.com"))
	}

	if r.Refresh(ctx, []string{"a.example.com"}) {
		t.Error("解析结果相同时不应判定为变化")
	}

	// 仅顺序与重复变化：不算变化
	f.set("a.example.com", "2.2.2.2", "1.1.1.1", "1.1.1.1")
	if r.Refresh(ctx, []string{"a.example.com"}) {
		t.Error("仅顺序/重复变化不应判定为变化")
	}
	if got := ipsOf(t, r, "a.example.com"); len(got) != 2 {
		t.Fatalf("去重后应有 2 个地址，实际 %v", got)
	}

	// 新增地址：算变化
	f.set("a.example.com", "1.1.1.1", "2.2.2.2", "3.3.3.3")
	if !r.Refresh(ctx, []string{"a.example.com"}) {
		t.Error("新增 IP 应判定为变化")
	}

	// 移除地址：算变化
	f.set("a.example.com", "1.1.1.1")
	if !r.Refresh(ctx, []string{"a.example.com"}) {
		t.Error("移除 IP 应判定为变化")
	}
	if got := ipsOf(t, r, "a.example.com"); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("IPs = %v, 期望 [1.1.1.1]", got)
	}
}

func TestFailureKeepsLastGoodResult(t *testing.T) {
	f := newFakeLookup()
	f.set("a.example.com", "1.1.1.1")
	r := New(Options{Lookup: f.lookup, Logger: quietLogger()})
	ctx := context.Background()

	if !r.Refresh(ctx, []string{"a.example.com"}) {
		t.Fatal("首次解析应判定为变化")
	}

	f.fail("a.example.com", errors.New("临时解析失败"))
	if r.Refresh(ctx, []string{"a.example.com"}) {
		t.Error("解析失败不应判定为变化（规则必须保留）")
	}
	if got := ipsOf(t, r, "a.example.com"); len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("解析失败后应保留上次结果，实际 %v", got)
	}
	if r.Error("a.example.com") == nil {
		t.Error("解析失败后 Error 不应为 nil")
	}

	// 恢复后清除错误
	f.set("a.example.com", "1.1.1.1")
	r.Refresh(ctx, []string{"a.example.com"})
	if r.Error("a.example.com") != nil {
		t.Errorf("恢复成功后 Error 应为 nil，实际 %v", r.Error("a.example.com"))
	}
}

func TestNeverResolvedHost(t *testing.T) {
	f := newFakeLookup()
	f.fail("bad.example.com", errors.New("NXDOMAIN"))
	r := New(Options{Lookup: f.lookup, Logger: quietLogger()})

	if r.Refresh(context.Background(), []string{"bad.example.com"}) {
		t.Error("从未成功解析过的域名不应判定为变化")
	}
	if got := r.IPs("bad.example.com"); got != nil {
		t.Errorf("从未成功解析过时 IPs 应为空，实际 %v", got)
	}
	if r.Error("bad.example.com") == nil {
		t.Error("应记录解析错误")
	}

	// 空结果（无 A 记录）同样视为错误，不写入缓存
	f.set("empty.example.com")
	if r.Refresh(context.Background(), []string{"empty.example.com"}) {
		t.Error("空 A 记录不应判定为变化")
	}
	if r.Error("empty.example.com") == nil {
		t.Error("空 A 记录应记录为错误")
	}
}

func TestMaxIPsPerHost(t *testing.T) {
	f := newFakeLookup()
	f.set("many.example.com", "1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4")
	r := New(Options{Lookup: f.lookup, MaxIPsPerHost: 2, Logger: quietLogger()})

	if !r.Refresh(context.Background(), []string{"many.example.com"}) {
		t.Fatal("首次解析应判定为变化")
	}
	if got := r.IPs("many.example.com"); len(got) != 2 {
		t.Fatalf("应截断为 2 个地址，实际 %v", got)
	}
}

func TestLiteralIPv4SkipsLookup(t *testing.T) {
	f := newFakeLookup()
	r := New(Options{Lookup: f.lookup, Logger: quietLogger()})

	got := ipsOf(t, r, "10.20.30.40")
	if len(got) != 1 || got[0] != "10.20.30.40" {
		t.Fatalf("字面量 IPv4 应直接返回，实际 %v", got)
	}

	r.Refresh(context.Background(), []string{"10.20.30.40", "a.example.com"})
	if f.callCount("10.20.30.40") != 0 {
		t.Error("字面量 IPv4 不应触发 DNS 查询")
	}
}

func TestPruneRemovedHosts(t *testing.T) {
	f := newFakeLookup()
	f.set("a.example.com", "1.1.1.1")
	f.set("b.example.com", "2.2.2.2")
	r := New(Options{Lookup: f.lookup, Logger: quietLogger()})
	ctx := context.Background()

	r.Refresh(ctx, []string{"a.example.com", "b.example.com"})
	if len(r.Snapshot()) != 2 {
		t.Fatalf("Snapshot 应有 2 条，实际 %v", r.Snapshot())
	}

	r.Refresh(ctx, []string{"a.example.com"})
	snap := r.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("移除域名后 Snapshot 应有 1 条，实际 %v", snap)
	}
	if _, ok := snap["a.example.com"]; !ok {
		t.Error("应保留 a.example.com")
	}
}

func TestIPsReturnsCopy(t *testing.T) {
	f := newFakeLookup()
	f.set("a.example.com", "1.1.1.1", "2.2.2.2")
	r := New(Options{Lookup: f.lookup, Logger: quietLogger()})
	r.Refresh(context.Background(), []string{"a.example.com"})

	first := r.IPs("a.example.com")
	first[0] = net.ParseIP("9.9.9.9")
	second := r.IPs("a.example.com")
	if second[0].String() != "1.1.1.1" {
		t.Errorf("IPs 应返回副本，实际被修改为 %v", second)
	}
}

func TestEqualIPs(t *testing.T) {
	a := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}
	b := []net.IP{net.ParseIP("2.2.2.2"), net.ParseIP("1.1.1.1"), net.ParseIP("1.1.1.1")}
	if !EqualIPs(a, b) {
		t.Error("顺序与重复不同的相同集合应判定为相等")
	}
	if EqualIPs(a, []net.IP{net.ParseIP("1.1.1.1")}) {
		t.Error("不同集合不应判定为相等")
	}
	if !EqualIPs(nil, nil) {
		t.Error("均为空应判定为相等")
	}
	// IPv6 在规范化时被丢弃
	if EqualIPs([]net.IP{net.ParseIP("fd00::1")}, nil) != true {
		t.Error("IPv6 地址应被规范化为空集合")
	}
}

func TestParseLiteralIPv4(t *testing.T) {
	if IsLiteralIPv4("fd00::1") {
		t.Error("IPv6 不应被判定为字面量 IPv4")
	}
	if !IsLiteralIPv4("10.0.0.1") {
		t.Error("10.0.0.1 应被判定为字面量 IPv4")
	}
	if ParseLiteralIPv4("10.0.0.1") == nil || ParseLiteralIPv4("example.com") != nil {
		t.Error("ParseLiteralIPv4 行为不符合预期")
	}
}
