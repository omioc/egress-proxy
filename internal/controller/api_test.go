package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"egress-proxy/internal/policy"
	"egress-proxy/internal/policymodel"
)

func newTestServer(t *testing.T, token string) (*httptest.Server, *Store) {
	t.Helper()
	store := NewStore(&MemoryStorage{}, nil)
	store.ReplacePods([]policymodel.Pod{
		{Namespace: "prod-shop", Name: "order-0", NodeName: "node-a", IP: "10.244.5.7", Labels: map[string]string{"app": "order-svc"}},
		{Namespace: "prod-shop", Name: "order-1", NodeName: "node-b", IP: "10.244.6.9", Labels: map[string]string{"app": "order-svc"}},
		{Namespace: "prod-shop", Name: "other", NodeName: "node-a", IP: "10.244.5.8", Labels: map[string]string{"app": "other"}},
	})
	api := NewAPI(store, token, nil)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, store
}

func doJSON(t *testing.T, srv *httptest.Server, method, path string, body interface{}, token string) (*http.Response, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求失败: %v", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("X-EGP-Token", token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func decodeState(t *testing.T, srv *httptest.Server) State {
	t.Helper()
	resp, body := doJSON(t, srv, http.MethodGet, "/api/v1/state", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("state 返回 %d: %s", resp.StatusCode, body)
	}
	var state State
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatalf("解析 state 失败: %v", err)
	}
	return state
}

func validRequest(generation int64) policyRequest {
	return policyRequest{
		Generation: generation,
		Mode:       policymodel.ModeEnforce,
		Payloads: []policymodel.Payload{{
			Name:        "order-svc",
			Namespaces:  []string{"prod-shop"},
			MatchLabels: map[string]string{"app": "order-svc"},
		}},
		Targets: []policymodel.Target{
			{Host: "a.example.com", Port: 443, ProxyPort: 20001},
			{Host: "10.20.30.40", Port: 5432, ProxyPort: 20002},
		},
		Grants: []policymodel.Grant{
			{Payload: "order-svc", Target: "a.example.com:443"},
		},
	}
}

func TestStateInitiallyEmpty(t *testing.T) {
	srv, _ := newTestServer(t, "")
	state := decodeState(t, srv)
	if state.Mode != policymodel.ModeDisabled {
		t.Fatalf("初始模式应为 disabled，实际 %q", state.Mode)
	}
	if state.Generation != 0 {
		t.Fatalf("初始 generation 应为 0，实际 %d", state.Generation)
	}
	if state.Stats.PodsKnown != 3 {
		t.Fatalf("Pod 数不对: %d", state.Stats.PodsKnown)
	}
	if state.Store != "memory" {
		t.Fatalf("store 描述不对: %q", state.Store)
	}
}

func TestPutPolicyAndCompile(t *testing.T) {
	srv, _ := newTestServer(t, "")

	resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", validRequest(0), "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("写入策略返回 %d: %s", resp.StatusCode, body)
	}

	state := decodeState(t, srv)
	if state.Generation != 1 {
		t.Fatalf("generation 应为 1，实际 %d", state.Generation)
	}
	if state.Mode != policymodel.ModeEnforce {
		t.Fatalf("mode 未生效: %q", state.Mode)
	}
	if len(state.Payloads) != 1 || len(state.Targets) != 2 || len(state.Grants) != 1 {
		t.Fatalf("策略未完整保存: %+v", state)
	}
	if len(state.Members["order-svc"]) != 2 {
		t.Fatalf("成员解析不对: %+v", state.Members)
	}
	// 有授权的目标应展开出两个 Pod IP；未授权的目标允许源为空
	if got := len(state.Sources["a.example.com:443"]); got != 2 {
		t.Fatalf("a.example.com:443 的允许源数应为 2，实际 %d: %v", got, state.Sources)
	}
	if got := len(state.Sources["10.20.30.40:5432"]); got != 0 {
		t.Fatalf("未授权目标不应有允许源: %v", state.Sources["10.20.30.40:5432"])
	}
	if state.Stats.TargetsArmed != 1 {
		t.Fatalf("已生效目标数不对: %d", state.Stats.TargetsArmed)
	}
	// 未授权目标应产生 warning
	found := false
	for _, w := range state.Warnings {
		if strings.Contains(w, "没有任何授权") {
			found = true
		}
	}
	if !found {
		t.Fatalf("应提示未授权目标: %v", state.Warnings)
	}
}

func TestCompiledFiltersByNode(t *testing.T) {
	srv, _ := newTestServer(t, "")
	if resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", validRequest(0), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("写入策略失败: %s", body)
	}

	resp, body := doJSON(t, srv, http.MethodGet, "/api/v1/compiled?node=node-a", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("compiled 返回 %d: %s", resp.StatusCode, body)
	}
	var compiled policymodel.Compiled
	if err := json.Unmarshal(body, &compiled); err != nil {
		t.Fatalf("解析 compiled 失败: %v", err)
	}
	if compiled.Mode != policymodel.ModeEnforce || compiled.Generation != 1 {
		t.Fatalf("编译结果头部不对: %+v", compiled)
	}
	target, ok := compiled.TargetByKey("a.example.com:443")
	if !ok {
		t.Fatalf("缺少目标: %+v", compiled.Targets)
	}
	if len(target.AllowSources) != 1 || target.AllowSources[0] != "10.244.5.7/32" {
		t.Fatalf("按节点过滤失败: %v", target.AllowSources)
	}
}

func TestPutPolicyRejectsInvalid(t *testing.T) {
	srv, _ := newTestServer(t, "")

	bad := validRequest(0)
	bad.Payloads[0].Name = "BAD NAME"
	resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", bad, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法策略应返回 400，实际 %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "error") {
		t.Fatalf("错误响应应包含 error 字段: %s", body)
	}
}

func TestPutPolicyConflict(t *testing.T) {
	srv, _ := newTestServer(t, "")
	if resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", validRequest(0), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("首次写入失败: %s", body)
	}
	// 客户端基于 generation=1 提交，成功
	if resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", validRequest(1), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("基于当前版本提交应成功: %s", body)
	}
	// 另一个客户端仍基于 generation=1 提交 → 冲突
	resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", validRequest(1), "")
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("generation 冲突应返回 409，实际 %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "error") {
		t.Fatalf("冲突响应应包含 error: %s", body)
	}
}

func TestModeAndGrantEndpoints(t *testing.T) {
	srv, _ := newTestServer(t, "")
	if resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", validRequest(0), ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("写入策略失败: %s", body)
	}

	// 切到 observe
	resp, body := doJSON(t, srv, http.MethodPost, "/api/v1/mode",
		map[string]string{"mode": "observe"}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("切换模式失败 %d: %s", resp.StatusCode, body)
	}
	if state := decodeState(t, srv); state.Mode != policymodel.ModeObserve {
		t.Fatalf("模式未生效: %q", state.Mode)
	}

	// 非法模式
	resp, body = doJSON(t, srv, http.MethodPost, "/api/v1/mode",
		map[string]string{"mode": "bogus"}, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法模式应返回 400，实际 %d: %s", resp.StatusCode, body)
	}

	// 新增一条授权
	resp, body = doJSON(t, srv, http.MethodPost, "/api/v1/grant",
		map[string]interface{}{"payload": "order-svc", "target": "10.20.30.40:5432", "allowed": true}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("新增授权失败 %d: %s", resp.StatusCode, body)
	}
	state := decodeState(t, srv)
	if len(state.Grants) != 2 {
		t.Fatalf("授权数应为 2，实际 %d", len(state.Grants))
	}
	if len(state.Sources["10.20.30.40:5432"]) != 2 {
		t.Fatalf("新增授权后允许源应为 2，实际 %v", state.Sources["10.20.30.40:5432"])
	}

	// 删除授权
	resp, body = doJSON(t, srv, http.MethodPost, "/api/v1/grant",
		map[string]interface{}{"payload": "order-svc", "target": "a.example.com:443", "allowed": false}, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("删除授权失败 %d: %s", resp.StatusCode, body)
	}
	state = decodeState(t, srv)
	if len(state.Sources["a.example.com:443"]) != 0 {
		t.Fatalf("删除授权后不应有允许源: %v", state.Sources["a.example.com:443"])
	}

	// 不存在的 target
	resp, _ = doJSON(t, srv, http.MethodPost, "/api/v1/grant",
		map[string]interface{}{"payload": "order-svc", "target": "nope:1", "allowed": true}, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("不存在的 target 应返回 400，实际 %d", resp.StatusCode)
	}
}

func TestAgentStatusReportedInState(t *testing.T) {
	srv, _ := newTestServer(t, "")
	resp, body := doJSON(t, srv, http.MethodPost, "/api/v1/agent-status", policy.Status{
		Node: "node-a", Generation: 5, Applied: true, Mode: "enforce",
	}, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("上报状态应返回 204，实际 %d: %s", resp.StatusCode, body)
	}

	state := decodeState(t, srv)
	if len(state.Agents) != 1 {
		t.Fatalf("应有 1 个 agent，实际 %+v", state.Agents)
	}
	agent := state.Agents[0]
	if agent.Node != "node-a" || agent.Generation != 5 || !agent.Applied || agent.Mode != "enforce" {
		t.Fatalf("agent 状态不对: %+v", agent)
	}
	if agent.Stale {
		t.Fatalf("刚上报不应标记为失联: %+v", agent)
	}

	// node 为空应拒绝
	resp, _ = doJSON(t, srv, http.MethodPost, "/api/v1/agent-status", policy.Status{}, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少 node 应返回 400，实际 %d", resp.StatusCode)
	}
}

func TestAgentStaleDetection(t *testing.T) {
	store := NewStore(&MemoryStorage{}, nil)
	old := time.Now().Add(-2 * agentStaleAfter)
	store.RecordAgent(policy.Status{Node: "node-old", Applied: true}, old)
	views := store.AgentViews(time.Now())
	if len(views) != 1 || !views[0].Stale {
		t.Fatalf("超过阈值应标记失联: %+v", views)
	}
}

func TestTokenAuth(t *testing.T) {
	srv, _ := newTestServer(t, "s3cret")

	resp, body := doJSON(t, srv, http.MethodGet, "/api/v1/state", nil, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("缺少令牌应返回 401，实际 %d: %s", resp.StatusCode, body)
	}

	resp, body = doJSON(t, srv, http.MethodGet, "/api/v1/state", nil, "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误令牌应返回 401，实际 %d: %s", resp.StatusCode, body)
	}

	resp, body = doJSON(t, srv, http.MethodGet, "/api/v1/state", nil, "s3cret")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正确令牌应通过，实际 %d: %s", resp.StatusCode, body)
	}

	// 页面本身不需要令牌
	resp, _ = doJSON(t, srv, http.MethodGet, "/", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("首页应可访问，实际 %d", resp.StatusCode)
	}
}

func TestUIServed(t *testing.T) {
	srv, _ := newTestServer(t, "")
	resp, body := doJSON(t, srv, http.MethodGet, "/", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("首页返回 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type 不对: %q", ct)
	}
	if !bytes.Contains(body, []byte("<html")) {
		t.Fatalf("首页内容看起来不是 HTML（前 80 字节）: %q", string(body[:min(80, len(body))]))
	}

	// 任意路径都返回同一个单页（便于刷新）
	resp, _ = doJSON(t, srv, http.MethodGet, "/some/deep/path", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("深层路径也应返回页面，实际 %d", resp.StatusCode)
	}
}

func TestHealthEndpoints(t *testing.T) {
	srv, _ := newTestServer(t, "")
	for _, path := range []string{"/healthz", "/readyz"} {
		resp, body := doJSON(t, srv, http.MethodGet, path, nil, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s 返回 %d: %s", path, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), `"status"`) {
			t.Fatalf("%s 响应缺少 status: %s", path, body)
		}
	}
}

func TestStorePersistsAndReloads(t *testing.T) {
	storage := &MemoryStorage{}
	store := NewStore(storage, nil)
	if _, err := store.ApplyPolicy(context.Background(), &policymodel.Policy{
		Mode:     policymodel.ModeEnforce,
		Payloads: []policymodel.Payload{{Name: "p1", Namespaces: []string{"ns1"}}},
		Targets:  []policymodel.Target{{Host: "a.example.com", Port: 443, ProxyPort: 20001}},
		Grants:   []policymodel.Grant{{Payload: "p1", Target: "a.example.com:443"}},
	}, 0); err != nil {
		t.Fatalf("写入策略失败: %v", err)
	}

	// 模拟控制器重启
	restored := NewStore(storage, nil)
	if err := restored.Load(context.Background()); err != nil {
		t.Fatalf("加载策略失败: %v", err)
	}
	pol, gen := restored.Policy()
	if gen != 1 || pol.Mode != policymodel.ModeEnforce || len(pol.Grants) != 1 {
		t.Fatalf("恢复结果不对: gen=%d pol=%+v", gen, pol)
	}
}

func TestStoreRejectsInvalidPolicyAndKeepsOld(t *testing.T) {
	store := NewStore(&MemoryStorage{}, nil)
	store.ReplacePods(nil)
	if _, err := store.ApplyPolicy(context.Background(), &policymodel.Policy{Mode: "bogus"}, 0); err == nil {
		t.Fatal("非法策略应报错")
	}
	if store.Generation() != 0 {
		t.Fatalf("非法策略不应改变 generation: %d", store.Generation())
	}
}

func TestStoreCompiledCacheInvalidated(t *testing.T) {
	store := NewStore(&MemoryStorage{}, nil)
	store.ReplacePods([]policymodel.Pod{
		{Namespace: "ns1", Name: "p1", NodeName: "node-a", IP: "10.244.1.1", Labels: map[string]string{"app": "x"}},
	})
	pol := &policymodel.Policy{
		Mode:     policymodel.ModeEnforce,
		Payloads: []policymodel.Payload{{Name: "pl", Namespaces: []string{"ns1"}, MatchLabels: map[string]string{"app": "x"}}},
		Targets:  []policymodel.Target{{Host: "a.example.com", Port: 443, ProxyPort: 20001}},
		Grants:   []policymodel.Grant{},
	}
	if _, err := store.ApplyPolicy(context.Background(), pol, 0); err != nil {
		t.Fatalf("写入策略失败: %v", err)
	}

	first := store.Compiled("node-a")
	if len(first.Targets[0].AllowSources) != 0 {
		t.Fatalf("未授权时不应有允许源: %v", first.Targets[0].AllowSources)
	}

	// 加授权后缓存必须失效
	if _, err := store.ToggleGrant(context.Background(), "pl", "a.example.com:443", true); err != nil {
		t.Fatalf("加授权失败: %v", err)
	}
	second := store.Compiled("node-a")
	if len(second.Targets[0].AllowSources) != 1 {
		t.Fatalf("变更后应重新编译: %v", second.Targets[0].AllowSources)
	}

	// Pod 变化后同样失效
	store.ReplacePods([]policymodel.Pod{
		{Namespace: "ns1", Name: "p2", NodeName: "node-a", IP: "10.244.1.2", Labels: map[string]string{"app": "x"}},
	})
	third := store.Compiled("node-a")
	if len(third.Targets[0].AllowSources) != 1 || third.Targets[0].AllowSources[0] != "10.244.1.2/32" {
		t.Fatalf("Pod 变化后应重新编译: %v", third.Targets[0].AllowSources)
	}
}

func TestMemoryStorage(t *testing.T) {
	m := &MemoryStorage{}
	if desc := m.Describe(); desc != "memory" {
		t.Fatalf("Describe = %q", desc)
	}
	raw, err := m.LoadPolicy(context.Background())
	if err != nil || raw != nil {
		t.Fatalf("空存储应返回 nil, nil: %v %v", raw, err)
	}
	if err := m.SavePolicy(context.Background(), []byte(`{"a":1}`)); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	raw, _ = m.LoadPolicy(context.Background())
	if string(raw) != `{"a":1}` {
		t.Fatalf("读取结果不对: %s", raw)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// fakeCluster 是 ClusterReader 的测试替身
type fakeCluster struct {
	namespaces []string
	workloads  map[string][]policymodel.Workload
	err        error
}

func (f *fakeCluster) ListNamespaces(context.Context) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]string(nil), f.namespaces...), nil
}

func (f *fakeCluster) ListWorkloads(_ context.Context, namespace string) ([]policymodel.Workload, error) {
	if f.err != nil {
		return nil, f.err
	}
	return append([]policymodel.Workload(nil), f.workloads[namespace]...), nil
}

func newClusterServer(t *testing.T, cluster ClusterReader) (*httptest.Server, *Store) {
	t.Helper()
	store := NewStore(&MemoryStorage{}, nil)
	store.ReplacePods([]policymodel.Pod{
		{Namespace: "prod-shop", Name: "order-0", NodeName: "node-a", IP: "10.244.5.7", Labels: map[string]string{"app": "order-svc"}},
		{Namespace: "prod-shop", Name: "order-1", NodeName: "node-b", IP: "10.244.6.9", Labels: map[string]string{"app": "order-svc"}},
	})
	api := NewAPI(store, "", nil)
	api.SetCluster(cluster)
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return srv, store
}

// 没有连接 apiserver 时，下拉接口必须明确报 503，让 WebUI 退化为手动输入
func TestClusterEndpointsUnavailable(t *testing.T) {
	srv, _ := newTestServer(t, "")
	for _, path := range []string{
		"/api/v1/cluster/namespaces",
		"/api/v1/cluster/workloads?namespace=prod-shop",
	} {
		resp, body := doJSON(t, srv, http.MethodGet, path, nil, "")
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("%s 应返回 503，实际 %d: %s", path, resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "error") {
			t.Fatalf("%s 应返回 error 字段: %s", path, body)
		}
	}
}

func TestClusterEndpointsAndWorkloadResolve(t *testing.T) {
	cluster := &fakeCluster{
		namespaces: []string{"kube-system", "prod-shop"},
		workloads: map[string][]policymodel.Workload{
			"prod-shop": {{
				Kind: "Deployment", Namespace: "prod-shop", Name: "order-svc",
				Selector: map[string]string{"app": "order-svc"}, Ready: "2/2",
			}},
		},
	}
	srv, _ := newClusterServer(t, cluster)

	resp, body := doJSON(t, srv, http.MethodGet, "/api/v1/cluster/namespaces", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("命名空间接口返回 %d: %s", resp.StatusCode, body)
	}
	var nsResp struct {
		Namespaces []string `json:"namespaces"`
	}
	if err := json.Unmarshal(body, &nsResp); err != nil {
		t.Fatalf("解析命名空间响应失败: %v", err)
	}
	if len(nsResp.Namespaces) != 2 {
		t.Fatalf("命名空间数量不对: %v", nsResp.Namespaces)
	}

	resp, body = doJSON(t, srv, http.MethodGet, "/api/v1/cluster/workloads?namespace=prod-shop", nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("工作负载接口返回 %d: %s", resp.StatusCode, body)
	}
	var wlResp struct {
		Namespace string                 `json:"namespace"`
		Workloads []policymodel.Workload `json:"workloads"`
	}
	if err := json.Unmarshal(body, &wlResp); err != nil {
		t.Fatalf("解析工作负载响应失败: %v", err)
	}
	if wlResp.Namespace != "prod-shop" || len(wlResp.Workloads) != 1 ||
		wlResp.Workloads[0].Name != "order-svc" || wlResp.Workloads[0].Ready != "2/2" {
		t.Fatalf("工作负载响应不对: %+v", wlResp)
	}

	// 只提交工作负载引用：控制器负责解析成 matchLabels 并落盘
	req := validRequest(0)
	req.Payloads = []policymodel.Payload{{
		Name:       "order",
		Namespaces: []string{"prod-shop"},
		Workload:   &policymodel.WorkloadRef{Kind: "Deployment", Name: "order-svc"},
	}}
	req.Grants = []policymodel.Grant{{Payload: "order", Target: "a.example.com:443"}}
	resp, body = doJSON(t, srv, http.MethodPut, "/api/v1/policy", req, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("按工作负载名写入策略失败 %d: %s", resp.StatusCode, body)
	}
	state := decodeState(t, srv)
	if got := state.Payloads[0].MatchLabels["app"]; got != "order-svc" {
		t.Fatalf("工作负载未被解析成标签: %+v", state.Payloads[0])
	}
	if len(state.Members["order"]) != 2 {
		t.Fatalf("解析成员不对: %+v", state.Members)
	}

	// 工作负载不存在 → 400，且旧策略不受影响
	req.Generation = state.Generation
	req.Payloads[0].Workload = &policymodel.WorkloadRef{Kind: "Deployment", Name: "ghost"}
	resp, body = doJSON(t, srv, http.MethodPut, "/api/v1/policy", req, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("不存在的工作负载应返回 400，实际 %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "找不到工作负载") {
		t.Fatalf("错误信息应说明找不到工作负载: %s", body)
	}
	if gen := decodeState(t, srv).Generation; gen != state.Generation {
		t.Fatalf("失败的提交不应改变 generation: %d", gen)
	}
}

// apiserver 不可用时：已解析过的负载沿用旧标签，新建的同类负载仍然必须报错
func TestWorkloadResolveFailStale(t *testing.T) {
	srv, _ := newClusterServer(t, &fakeCluster{err: errors.New("apiserver 不可用")})
	req := validRequest(0)
	req.Payloads = []policymodel.Payload{{
		Name:        "order",
		Namespaces:  []string{"prod-shop"},
		Workload:    &policymodel.WorkloadRef{Kind: "Deployment", Name: "order-svc"},
		MatchLabels: map[string]string{"app": "order-svc"},
	}}
	req.Grants = []policymodel.Grant{{Payload: "order", Target: "a.example.com:443"}}

	resp, body := doJSON(t, srv, http.MethodPut, "/api/v1/policy", req, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("已有标签时读取工作负载失败应降级放行，实际 %d: %s", resp.StatusCode, body)
	}
	state := decodeState(t, srv)
	if state.Payloads[0].MatchLabels["app"] != "order-svc" {
		t.Fatalf("旧标签被改动: %+v", state.Payloads[0])
	}

	req.Generation = state.Generation
	req.Payloads[0].MatchLabels = nil
	resp, body = doJSON(t, srv, http.MethodPut, "/api/v1/policy", req, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("没有旧标签时必须报错，实际 %d: %s", resp.StatusCode, body)
	}
}
