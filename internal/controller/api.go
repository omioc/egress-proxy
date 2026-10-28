package controller

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"egress-proxy/internal/i18n"
	"egress-proxy/internal/policy"
	"egress-proxy/internal/policymodel"
)

// maxBodyBytes 是请求体上限，防御超大请求
const maxBodyBytes = 4 << 20

// metaCacheTTL 是集群元数据（命名空间 / 工作负载）的缓存时长：
// 打开表单时连续的下拉请求不必每次都打 apiserver
const metaCacheTTL = 5 * time.Second

// errNoCluster 表示控制器没有连接 apiserver，无法提供下拉数据
var errNoCluster = i18n.NewCoded(msgNoCluster)

// API 提供 REST 接口与内置 WebUI
type API struct {
	store *Store
	token string
	log   *slog.Logger
	now   func() time.Time

	// cluster 为空表示控制器没有连接 apiserver，cluster/* 接口返回 503
	cluster ClusterReader

	metaMu  sync.Mutex
	nsCache []string
	nsAt    time.Time
	wlCache map[string]cachedWorkloads
}

// cachedWorkloads 是某个命名空间工作负载列表的缓存项
type cachedWorkloads struct {
	list []policymodel.Workload
	at   time.Time
}

// NewAPI 创建 API
func NewAPI(store *Store, token string, logger *slog.Logger) *API {
	if logger == nil {
		logger = slog.Default()
	}
	return &API{
		store: store,
		token: strings.TrimSpace(token),
		log:   logger,
		now:   time.Now,
	}
}

// SetCluster 注入集群元数据来源；未注入时（例如以 -in-cluster=false 运行）
// /api/v1/cluster/* 一律返回 503，WebUI 会自动退化为手动输入
func (a *API) SetCluster(c ClusterReader) { a.cluster = c }

// namespaces 返回命名空间列表（带短缓存）
func (a *API) namespaces(ctx context.Context) ([]string, error) {
	if a.cluster == nil {
		return nil, errNoCluster
	}
	a.metaMu.Lock()
	if a.nsCache != nil && a.now().Sub(a.nsAt) < metaCacheTTL {
		cached := append([]string(nil), a.nsCache...)
		a.metaMu.Unlock()
		return cached, nil
	}
	a.metaMu.Unlock()

	list, err := a.cluster.ListNamespaces(ctx)
	if err != nil {
		return nil, locErr(msgReadNamespaceList, err)
	}
	a.metaMu.Lock()
	a.nsCache, a.nsAt = list, a.now()
	a.metaMu.Unlock()
	return append([]string(nil), list...), nil
}

// workloads 返回某个命名空间的工作负载列表（带短缓存）
func (a *API) workloads(ctx context.Context, namespace string) ([]policymodel.Workload, error) {
	if a.cluster == nil {
		return nil, errNoCluster
	}
	a.metaMu.Lock()
	if cached, ok := a.wlCache[namespace]; ok && a.now().Sub(cached.at) < metaCacheTTL {
		list := append([]policymodel.Workload(nil), cached.list...)
		a.metaMu.Unlock()
		return list, nil
	}
	a.metaMu.Unlock()

	list, err := a.cluster.ListWorkloads(ctx, namespace)
	if err != nil {
		return nil, locErr(msgReadWorkloadList, err)
	}
	a.metaMu.Lock()
	if a.wlCache == nil {
		a.wlCache = make(map[string]cachedWorkloads)
	}
	a.wlCache[namespace] = cachedWorkloads{list: list, at: a.now()}
	a.metaMu.Unlock()
	return list, nil
}

// resolvePayloads 把「按工作负载名」的负载解析成标签选择器
//
// 解析在写入前完成，策略里只保存解析结果：读取时不再依赖 apiserver，
// 因此控制器重启或 apiserver 短时不可用都不会改变已经生效的规则
func (a *API) resolvePayloads(ctx context.Context, payloads []policymodel.Payload) ([]policymodel.Payload, error) {
	out := make([]policymodel.Payload, 0, len(payloads))
	cache := make(map[string][]policymodel.Workload, 1)
	for _, p := range payloads {
		if p.Workload == nil {
			out = append(out, p)
			continue
		}
		ns := ""
		if len(p.Namespaces) > 0 {
			ns = p.Namespaces[0]
		}
		list, ok := cache[ns]
		var err error
		if !ok {
			list, err = a.workloads(ctx, ns)
			if err == nil {
				cache[ns] = list
			}
		}
		var resolved policymodel.Payload
		if err == nil {
			resolved, err = p.ResolveLang(i18n.FromContext(ctx), list)
		}
		if err != nil {
			// 已经有解析结果的负载沿用旧标签（fail-stale）：工作负载被删掉或 apiserver
			// 短时不可用时，不应该阻塞「加一个目标」这类与之无关的编辑
			// 新建负载没有旧标签，仍然必须是硬错误（否则会退化成匹配整个命名空间）
			if len(p.MatchLabels) > 0 {
				a.log.Warn("工作负载解析失败，沿用上次解析的标签选择器", "payload", p.Name, "err", err)
				out = append(out, p)
				continue
			}
			return nil, locErrArgs(msgPayloadWrap, err, p.Name)
		}
		out = append(out, resolved)
	}
	return out, nil
}

func (a *API) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	list, err := a.namespaces(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, renderError(i18n.FromContext(r.Context()), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"namespaces": list})
}

func (a *API) handleWorkloads(w http.ResponseWriter, r *http.Request) {
	ns := strings.TrimSpace(r.URL.Query().Get("namespace"))
	list, err := a.workloads(r.Context(), ns)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, renderError(i18n.FromContext(r.Context()), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"namespace": ns, "workloads": list})
}

// Handler 返回完整路由
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/state", a.handleState)
	mux.HandleFunc("PUT /api/v1/policy", a.handlePutPolicy)
	mux.HandleFunc("POST /api/v1/mode", a.handleMode)
	mux.HandleFunc("POST /api/v1/grant", a.handleGrant)
	mux.HandleFunc("GET /api/v1/compiled", a.handleCompiled)
	mux.HandleFunc("POST /api/v1/agent-status", a.handleAgentStatus)
	mux.HandleFunc("GET /api/v1/cluster/namespaces", a.handleNamespaces)
	mux.HandleFunc("GET /api/v1/cluster/workloads", a.handleWorkloads)
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /readyz", a.handleHealth)
	// 其余路径一律交给内置单页 WebUI（便于刷新与直接访问 /）
	mux.Handle("/", UIHandler())

	return withLang(a.withAuth(mux))
}

// withAuth 对 /api/ 路径做可选的令牌校验
func (a *API) withAuth(next http.Handler) http.Handler {
	if a.token == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("X-EGP-Token")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if got != a.token {
			writeErrorMsg(w, r, http.StatusUnauthorized, msgUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) handleState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.StateLang(i18n.FromContext(r.Context()), a.now()))
}

// policyRequest 是 PUT /api/v1/policy 的请求体
type policyRequest struct {
	Generation int64                 `json:"generation"`
	Mode       policymodel.Mode      `json:"mode"`
	Payloads   []policymodel.Payload `json:"payloads"`
	Targets    []policymodel.Target  `json:"targets"`
	Grants     []policymodel.Grant   `json:"grants"`
}

func (a *API) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if err := decodeBody(r, &req); err != nil {
		writeErrorMsg(w, r, http.StatusBadRequest, msgDecodeBody, err)
		return
	}
	payloads, err := a.resolvePayloads(r.Context(), req.Payloads)
	if err != nil {
		writeError(w, http.StatusBadRequest, renderError(i18n.FromContext(r.Context()), err))
		return
	}
	p := &policymodel.Policy{
		Mode:     req.Mode,
		Payloads: payloads,
		Targets:  req.Targets,
		Grants:   req.Grants,
	}
	gen, err := a.store.ApplyPolicy(r.Context(), p, req.Generation)
	if err != nil {
		if errors.Is(err, ErrConflict) {
			writeError(w, http.StatusConflict, renderError(i18n.FromContext(r.Context()), err))
			return
		}
		writeError(w, http.StatusBadRequest, renderError(i18n.FromContext(r.Context()), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"generation": gen})
}

func (a *API) handleMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode policymodel.Mode `json:"mode"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErrorMsg(w, r, http.StatusBadRequest, msgDecodeBody, err)
		return
	}
	gen, err := a.store.SetMode(r.Context(), req.Mode)
	if err != nil {
		writeError(w, http.StatusBadRequest, renderError(i18n.FromContext(r.Context()), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"generation": gen})
}

func (a *API) handleGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Payload string `json:"payload"`
		Target  string `json:"target"`
		Allowed bool   `json:"allowed"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErrorMsg(w, r, http.StatusBadRequest, msgDecodeBody, err)
		return
	}
	if strings.TrimSpace(req.Payload) == "" || strings.TrimSpace(req.Target) == "" {
		writeErrorMsg(w, r, http.StatusBadRequest, msgGrantNeedsBoth)
		return
	}
	gen, err := a.store.ToggleGrant(r.Context(), req.Payload, req.Target, req.Allowed)
	if err != nil {
		writeError(w, http.StatusBadRequest, renderError(i18n.FromContext(r.Context()), err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"generation": gen})
}

func (a *API) handleCompiled(w http.ResponseWriter, r *http.Request) {
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	writeJSON(w, http.StatusOK, a.store.Compiled(node))
}

func (a *API) handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	var status policy.Status
	if err := decodeBody(r, &status); err != nil {
		writeErrorMsg(w, r, http.StatusBadRequest, msgDecodeBody, err)
		return
	}
	status.Node = strings.TrimSpace(status.Node)
	if status.Node == "" {
		writeErrorMsg(w, r, http.StatusBadRequest, msgNodeRequired)
		return
	}
	a.store.RecordAgent(status, a.now())
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	state := a.store.State(a.now())
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "ok",
		"generation":  state.Generation,
		"mode":        state.Mode,
		"store":       state.Store,
		"podsKnown":   state.Stats.PodsKnown,
		"podsAge":     state.PodsAge,
		"targets":     len(state.Targets),
		"payloads":    len(state.Payloads),
		"agentNodes":  len(state.Agents),
		"persistFail": state.Store == "memory",
	})
}

func decodeBody(r *http.Request, dst interface{}) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return i18n.NewCoded(msgEmptyBody)
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeErrorMsg 按请求语言渲染预置文案（Accept-Language 决定中英文）
func writeErrorMsg(w http.ResponseWriter, r *http.Request, status int, m i18n.Msg, args ...any) {
	writeError(w, status, m.S(i18n.FromContext(r.Context()), args...))
}

// withLang 依据 Accept-Language 决定本次请求的文案语言（缺省中文）
func withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := i18n.FromHeader(r.Header.Get("Accept-Language"))
		next.ServeHTTP(w, r.WithContext(i18n.WithLang(r.Context(), l)))
	})
}
