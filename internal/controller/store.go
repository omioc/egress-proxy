// Package controller 实现 egress-proxy 的四元组策略控制面：
// 保存策略（payload / target / 授权关系）、维护集群 Pod 索引、按节点编译
// 「每个目标允许的源地址集合」，并通过 REST API + 内置 WebUI 提供管理能力
//
// 单实例（replicas: 1）即可：策略与 Pod 索引都很小，转发与规则下发完全在数据面完成，
// 控制器只负责「算清楚谁可以访问什么」
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"egress-proxy/internal/i18n"
	"egress-proxy/internal/policy"
	"egress-proxy/internal/policymodel"
)

const (
	// policyDataKey 是 ConfigMap 中保存策略的 key
	policyDataKey = "policy.json"
	// DefaultConfigMapName 是默认的策略 ConfigMap 名
	DefaultConfigMapName = "egress-proxy-policy"
	// agentStaleAfter 超过该时长未上报的 agent 视为失联
	agentStaleAfter = 60 * time.Second
)

// ErrConflict 表示 generation 冲突：客户端基于旧状态提交
var ErrConflict = errors.New("策略版本冲突，请刷新页面后重试")

// persistedPolicy 是持久化的策略文档
type persistedPolicy struct {
	Generation int64              `json:"generation"`
	Policy     policymodel.Policy `json:"policy"`
}

// agentStatus 记录某个节点最近一次上报的状态
type agentStatus struct {
	Status policy.Status
	SeenAt time.Time
}

// Store 保存策略、Pod 索引与节点状态，并发安全
type Store struct {
	log     *slog.Logger
	storage PolicyStorage

	mu          sync.RWMutex
	pol         *policymodel.Policy
	generation  int64
	index       *policymodel.Index
	podsAt      time.Time
	podsErr     error
	podsVersion int64
	agents      map[string]agentStatus
	persistErr  *persistIssue

	cacheMu sync.Mutex
	cache   map[string]cachedCompiled
}

type cachedCompiled struct {
	key      string
	compiled *policymodel.Compiled
}

// NewStore 创建空策略的 Store
func NewStore(storage PolicyStorage, logger *slog.Logger) *Store {
	if logger == nil {
		logger = slog.Default()
	}
	if storage == nil {
		storage = &MemoryStorage{}
	}
	return &Store{
		log:     logger,
		storage: storage,
		pol:     &policymodel.Policy{Mode: policymodel.ModeDisabled},
		index:   policymodel.NewIndex(nil),
		agents:  make(map[string]agentStatus),
		cache:   make(map[string]cachedCompiled),
		podsAt:  time.Now(),
	}
}

// StorageDescription 返回存储位置描述
func (s *Store) StorageDescription() string {
	if s.storage == nil {
		return "memory"
	}
	return s.storage.Describe()
}

// Load 从存储恢复策略；没有历史策略时保持空的 disabled 策略
func (s *Store) Load(ctx context.Context) error {
	raw, err := s.storage.LoadPolicy(ctx)
	if err != nil {
		return fmt.Errorf(i18n.Text("读取已保存的策略失败: %w"), err)
	}
	if len(raw) == 0 {
		s.log.Info("没有已保存的策略，从空白开始", "store", s.storage.Describe())
		return nil
	}

	var doc persistedPolicy
	if err := json.Unmarshal(raw, &doc); err != nil {
		s.log.Warn("已保存的策略无法解析，忽略它并从空白开始", "err", err)
		return nil
	}
	doc.Policy.Normalize()
	if err := doc.Policy.Validate(); err != nil {
		s.log.Warn("已保存的策略不合法，忽略它并从空白开始", "err", err)
		return nil
	}

	s.mu.Lock()
	s.pol = doc.Policy.Clone()
	s.generation = doc.Generation
	s.mu.Unlock()
	s.invalidateCache()

	s.log.Info("已恢复策略",
		"generation", doc.Generation, "mode", doc.Policy.Mode.String(),
		"payloads", len(doc.Policy.Payloads), "targets", len(doc.Policy.Targets),
		"grants", len(doc.Policy.Grants))
	return nil
}

// Policy 返回策略副本与当前 generation
func (s *Store) Policy() (*policymodel.Policy, int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.pol.Clone(), s.generation
}

// Generation 返回当前 generation
func (s *Store) Generation() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

// ApplyPolicy 用新策略整体替换旧策略；expectGeneration 非 0 时做乐观并发校验
func (s *Store) ApplyPolicy(ctx context.Context, p *policymodel.Policy, expectGeneration int64) (int64, error) {
	if p == nil {
		return 0, msgPolicyEmpty.E(i18n.FromContext(ctx))
	}
	next := p.Clone()
	next.Normalize()
	if err := next.ValidateLang(i18n.FromContext(ctx)); err != nil {
		return 0, err
	}

	s.mu.Lock()
	if expectGeneration > 0 && expectGeneration != s.generation {
		current := s.generation
		s.mu.Unlock()
		return current, &conflictError{current: current}
	}
	s.pol = next
	s.generation++
	gen := s.generation
	s.mu.Unlock()

	s.invalidateCache()
	s.persist(ctx, gen)
	s.log.Info("策略已更新",
		"generation", gen, "mode", next.Mode.String(),
		"payloads", len(next.Payloads), "targets", len(next.Targets), "grants", len(next.Grants))
	return gen, nil
}

// SetMode 只修改执行模式
func (s *Store) SetMode(ctx context.Context, mode policymodel.Mode) (int64, error) {
	if !mode.Valid() {
		return 0, msgInvalidMode.E(i18n.FromContext(ctx), string(mode))
	}
	s.mu.Lock()
	next := s.pol.Clone()
	next.Mode = mode
	s.pol = next
	s.generation++
	gen := s.generation
	s.mu.Unlock()

	s.invalidateCache()
	s.persist(ctx, gen)
	s.log.Info("执行模式已变更", "generation", gen, "mode", mode.String())
	return gen, nil
}

// ToggleGrant 增加或删除一条 (payload, target) 授权
func (s *Store) ToggleGrant(ctx context.Context, payload, target string, allowed bool) (int64, error) {
	s.mu.Lock()
	next := s.pol.Clone()
	if !next.ToggleGrant(payload, target, allowed) {
		current := s.generation
		s.mu.Unlock()
		return current, msgNoGrantChange.E(i18n.FromContext(ctx), payload, target, allowed)
	}
	next.Normalize()
	if err := next.ValidateLang(i18n.FromContext(ctx)); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	s.pol = next
	s.generation++
	gen := s.generation
	s.mu.Unlock()

	s.invalidateCache()
	s.persist(ctx, gen)
	s.log.Info("授权已变更", "generation", gen, "payload", payload, "target", target, "allowed", allowed)
	return gen, nil
}

func (s *Store) persist(ctx context.Context, generation int64) {
	if s.storage == nil {
		return
	}
	s.mu.RLock()
	doc := persistedPolicy{Generation: generation, Policy: *s.pol.Clone()}
	s.mu.RUnlock()

	data, err := json.Marshal(doc)
	if err != nil {
		s.setPersistIssue(msgSerializeFailed, err)
		return
	}
	if err := s.storage.SavePolicy(ctx, data); err != nil {
		s.setPersistIssue(msgPersistFailed, err)
		s.log.Error("策略持久化失败", "err", err, "store", s.storage.Describe())
		return
	}
	s.setPersistIssue(i18n.Msg{})
}

// setPersistIssue 记录/清除持久化失败的提示（传空 Msg 表示清除）
func (s *Store) setPersistIssue(m i18n.Msg, args ...any) {
	s.mu.Lock()
	if m.ZH == "" {
		s.persistErr = nil
	} else {
		s.persistErr = &persistIssue{msg: m, args: args}
	}
	s.mu.Unlock()
}

// ReplacePods 用最新的 Pod 列表替换索引
func (s *Store) ReplacePods(pods []policymodel.Pod) {
	index := policymodel.NewIndex(pods)
	s.mu.Lock()
	s.index = index
	s.podsAt = time.Now()
	s.podsErr = nil
	s.podsVersion++
	s.mu.Unlock()
	s.invalidateCache()
}

// SetPodsError 记录最近一次列取 Pod 失败的原因（保留旧索引，fail-stale）
func (s *Store) SetPodsError(err error) {
	s.mu.Lock()
	if err != nil {
		s.podsErr = err
	}
	s.mu.Unlock()
}

// RecordAgent 记录节点上报的状态
func (s *Store) RecordAgent(status policy.Status, at time.Time) {
	s.mu.Lock()
	s.agents[status.Node] = agentStatus{Status: status, SeenAt: at}
	s.mu.Unlock()
}

func (s *Store) invalidateCache() {
	s.cacheMu.Lock()
	s.cache = make(map[string]cachedCompiled)
	s.cacheMu.Unlock()
}

// Compiled 返回某节点的编译结果（带缓存）
func (s *Store) Compiled(node string) *policymodel.Compiled {
	s.mu.RLock()
	pol := s.pol
	index := s.index
	key := fmt.Sprintf("%d/%d", s.generation, s.podsVersion)
	s.mu.RUnlock()

	s.cacheMu.Lock()
	cached, ok := s.cache[node]
	s.cacheMu.Unlock()
	if ok && cached.key == key {
		return cached.compiled
	}

	compiled := policymodel.Compile(pol, index, node)
	compiled.Generation = s.Generation()

	s.cacheMu.Lock()
	s.cache[node] = cachedCompiled{key: key, compiled: compiled}
	s.cacheMu.Unlock()
	return compiled
}

// AgentView 是 WebUI 展示的节点状态
type AgentView struct {
	Node       string    `json:"node"`
	Generation int64     `json:"generation"`
	Applied    bool      `json:"applied"`
	Mode       string    `json:"mode"`
	LastSeen   time.Time `json:"lastSeen"`
	Stale      bool      `json:"stale"`
	Error      string    `json:"error,omitempty"`
}

// AgentViews 返回按节点名排序的 agent 状态
// AgentViews 返回按节点名排序的 agent 状态（中文文案）
func (s *Store) AgentViews(now time.Time) []AgentView { return s.AgentViewsLang(i18n.ZH, now) }

// AgentViewsLang 同 AgentViews，但按语言挑选节点上报的错误文本
func (s *Store) AgentViewsLang(l i18n.Lang, now time.Time) []AgentView {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AgentView, 0, len(s.agents))
	for node, st := range s.agents {
		out = append(out, AgentView{
			Node:       node,
			Generation: st.Status.Generation,
			Applied:    st.Status.Applied,
			Mode:       st.Status.Mode,
			LastSeen:   st.SeenAt,
			Stale:      now.Sub(st.SeenAt) > agentStaleAfter,
			Error:      st.Status.Error,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// Stats 是 WebUI 顶部的统计信息
type Stats struct {
	PodsKnown        int `json:"podsKnown"`
	PayloadsResolved int `json:"payloadsResolved"`
	TargetsArmed     int `json:"targetsArmed"`
}

// State 是 GET /api/v1/state 的响应体
type State struct {
	Generation int64                           `json:"generation"`
	Mode       policymodel.Mode                `json:"mode"`
	Payloads   []policymodel.Payload           `json:"payloads"`
	Targets    []policymodel.Target            `json:"targets"`
	Grants     []policymodel.Grant             `json:"grants"`
	Members    map[string][]policymodel.Member `json:"members"`
	Sources    map[string][]string             `json:"sources"`
	Agents     []AgentView                     `json:"agents"`
	Stats      Stats                           `json:"stats"`
	Store      string                          `json:"store"`
	Warnings   []string                        `json:"warnings"`
	PodsAge    string                          `json:"podsAge"`
	PodsError  string                          `json:"podsError,omitempty"`
}

// State 汇总当前策略、解析结果与节点状态
func (s *Store) State(now time.Time) State { return s.StateLang(i18n.ZH, now) }

// StateLang 同 State，但按语言渲染 warnings / podsError 这类提示文案
func (s *Store) StateLang(l i18n.Lang, now time.Time) State {
	s.mu.RLock()
	pol := s.pol.Clone()
	gen := s.generation
	index := s.index
	podsAt := s.podsAt
	podsErr := s.podsErr
	persistIssue := s.persistErr
	s.mu.RUnlock()

	compiled := policymodel.Compile(pol, index, "")
	compiled.Generation = gen

	members := index.MembersMap(pol)
	resolved := 0
	for _, list := range members {
		if len(list) > 0 {
			resolved++
		}
	}
	armed := 0
	for _, t := range compiled.Targets {
		if len(t.AllowSources) > 0 {
			armed++
		}
	}

	warnings := pol.WarningsLang(l)
	if persistIssue != nil {
		warnings = append(warnings, persistIssue.S(l))
	}
	if podsErr != nil {
		warnings = append(warnings, renderError(l, podsErr))
	}

	state := State{
		Generation: gen,
		Mode:       pol.Mode,
		Payloads:   pol.Payloads,
		Targets:    pol.Targets,
		Grants:     pol.Grants,
		Members:    members,
		Sources:    policymodel.SourcesMap(compiled),
		Agents:     s.AgentViewsLang(l, now),
		Store:      s.StorageDescription(),
		Warnings:   warnings,
		PodsAge:    now.Sub(podsAt).Truncate(time.Second).String(),
		PodsError:  renderError(l, podsErr),
		Stats: Stats{
			PodsKnown:        index.Len(),
			PayloadsResolved: resolved,
			TargetsArmed:     armed,
		},
	}
	if state.Payloads == nil {
		state.Payloads = []policymodel.Payload{}
	}
	if state.Targets == nil {
		state.Targets = []policymodel.Target{}
	}
	if state.Grants == nil {
		state.Grants = []policymodel.Grant{}
	}
	if state.Agents == nil {
		state.Agents = []AgentView{}
	}
	if state.Warnings == nil {
		state.Warnings = []string{}
	}
	return state
}
