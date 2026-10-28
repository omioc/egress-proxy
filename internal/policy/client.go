// Package policy 负责从控制器拉取「四元组策略的编译结果」，并在控制器不可用时降级
//
// 故障姿态（与设计文档一致）：
//   - 启动即失败：返回 nil，调用方回退到「配置文件里的 targets 全量直通」，
//     也就是四元组管控未生效（fail-open），避免一上手就把集群出网打死；
//   - 运行中失败：返回最近一次成功的结果（fail-stale），保持既有管控强度，
//     不会因为控制器抖动而突然全放开
package policy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"egress-proxy/config"
	"egress-proxy/internal/i18n"
	"egress-proxy/internal/policymodel"
)

// Status 是 agent 上报给控制器的运行状态
type Status struct {
	Node       string `json:"node"`
	Generation int64  `json:"generation"`
	Applied    bool   `json:"applied"`
	Mode       string `json:"mode"`
	Error      string `json:"error"`
	ErrorEn    string `json:"errorEn,omitempty"`
}

// Source 抽象编译结果的来源
type Source interface {
	// Fetch 返回当前生效的编译结果；失败时可能同时返回上一次成功的结果（stale）
	Fetch(ctx context.Context) (*policymodel.Compiled, error)
	// Describe 返回来源描述，用于日志
	Describe() string
	// Report 上报本节点状态；没有控制器的来源应返回 nil
	Report(ctx context.Context, status Status) error
}

// CompileLegacy 把配置文件的 targets 翻译成「全量直通」的编译结果，
// 用于未启用四元组管控（没有控制器）的兼容场景
func CompileLegacy(targets []config.Target) *policymodel.Compiled {
	out := &policymodel.Compiled{Mode: policymodel.ModeDisabled}
	for _, t := range targets {
		out.Targets = append(out.Targets, policymodel.CompiledTarget{
			Host:         t.Host,
			Port:         t.Port,
			ProxyPort:    t.ProxyPort,
			AllowSources: []string{},
		})
	}
	return out
}

// Options 配置 HTTP 来源
type Options struct {
	// BaseURL 是控制器地址，例如 http://egress-proxy-controller.egress-proxy.svc:18082
	BaseURL string
	// NodeName 用于按节点过滤允许源（空表示不过滤）
	NodeName string
	// Token 是可选的接口令牌
	Token string
	// Timeout 是单次请求超时
	Timeout time.Duration
	// CachePath 是本地缓存文件路径（为空则不落盘）
	CachePath string
	// Logger 可为 nil
	Logger *slog.Logger
	// HTTPClient 用于测试注入
	HTTPClient *http.Client
}

// HTTPClient 从控制器拉取编译结果
type HTTPClient struct {
	opts   Options
	client *http.Client
	log    *slog.Logger

	mu   sync.Mutex
	last *policymodel.Compiled
}

// NewHTTPClient 创建 HTTP 来源
func NewHTTPClient(opts Options) *HTTPClient {
	if opts.Timeout <= 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout}
	}
	c := &HTTPClient{opts: opts, client: client, log: opts.Logger}
	c.loadCache()
	return c
}

// Describe 实现 Source
func (c *HTTPClient) Describe() string {
	return "controller " + strings.TrimSuffix(c.opts.BaseURL, "/")
}

// Fetch 拉取编译结果
func (c *HTTPClient) Fetch(ctx context.Context) (*policymodel.Compiled, error) {
	endpoint := strings.TrimSuffix(c.opts.BaseURL, "/") + "/api/v1/compiled"
	if c.opts.NodeName != "" {
		endpoint += "?node=" + url.QueryEscape(c.opts.NodeName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return c.fallback(i18n.NewCoded(msgBuildRequestFailed, err))
	}
	if c.opts.Token != "" {
		req.Header.Set("X-EGP-Token", c.opts.Token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return c.fallback(i18n.NewCoded(msgRequestControllerFailed, err))
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return c.fallback(i18n.NewCoded(msgReadResponseFailed, err))
	}
	if resp.StatusCode != http.StatusOK {
		return c.fallback(i18n.NewCoded(msgControllerStatus, resp.StatusCode, strings.TrimSpace(string(body))))
	}

	var compiled policymodel.Compiled
	if err := json.Unmarshal(body, &compiled); err != nil {
		return c.fallback(i18n.NewCoded(msgParseCompiledFailed, err))
	}
	if !compiled.Mode.Valid() {
		return c.fallback(i18n.NewCoded(msgModeInvalid, string(compiled.Mode)))
	}

	c.mu.Lock()
	c.last = &compiled
	c.mu.Unlock()
	c.saveCache(&compiled)
	return &compiled, nil
}

// fallback 返回上一次成功的结果（若有）与错误
func (c *HTTPClient) fallback(err error) (*policymodel.Compiled, error) {
	c.mu.Lock()
	last := c.last
	c.mu.Unlock()
	if last == nil {
		return nil, err
	}
	// 双语拼装：中文用中文错误、英文用英文错误（这里的 err 都是 Coded，英文必然存在）
	zh, en := i18n.Bilingual(err)
	if en == "" {
		en = zh
	}
	return last, i18n.NewCoded(i18n.Msg{
		ZH: msgKeepLastSuccess.S(i18n.ZH, zh, last.Generation),
		EN: msgKeepLastSuccess.S(i18n.EN, en, last.Generation),
	})
}

// Report 上报节点状态（尽力而为，失败只记日志）
func (c *HTTPClient) Report(ctx context.Context, status Status) error {
	payload, err := json.Marshal(status)
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(c.opts.BaseURL, "/") + "/api/v1/agent-status"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.opts.Token != "" {
		req.Header.Set("X-EGP-Token", c.opts.Token)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode >= 300 {
		return i18n.NewCoded(msgReportStatusFailed, resp.StatusCode)
	}
	return nil
}

func (c *HTTPClient) loadCache() {
	if c.opts.CachePath == "" {
		return
	}
	data, err := os.ReadFile(c.opts.CachePath)
	if err != nil {
		if !os.IsNotExist(err) {
			c.log.Debug(i18n.Text("读取策略缓存失败"), "path", c.opts.CachePath, "err", err)
		}
		return
	}
	var compiled policymodel.Compiled
	if err := json.Unmarshal(data, &compiled); err != nil {
		c.log.Warn(i18n.Text("策略缓存内容无法解析，已忽略"), "path", c.opts.CachePath, "err", err)
		return
	}
	if !compiled.Mode.Valid() {
		return
	}
	c.last = &compiled
	c.log.Info(i18n.Text("已载入本地策略缓存"),
		"path", c.opts.CachePath, "generation", compiled.Generation, "mode", compiled.Mode.String())
}

func (c *HTTPClient) saveCache(compiled *policymodel.Compiled) {
	if c.opts.CachePath == "" {
		return
	}
	data, err := json.Marshal(compiled)
	if err != nil {
		c.log.Warn(i18n.Text("序列化策略缓存失败"), "err", err)
		return
	}
	dir := filepath.Dir(c.opts.CachePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		c.log.Debug(i18n.Text("创建策略缓存目录失败"), "dir", dir, "err", err)
		return
	}
	tmp := c.opts.CachePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		c.log.Debug(i18n.Text("写入策略缓存失败"), "path", tmp, "err", err)
		return
	}
	if err := os.Rename(tmp, c.opts.CachePath); err != nil {
		c.log.Debug(i18n.Text("重命名策略缓存失败"), "path", c.opts.CachePath, "err", err)
	}
}

// StaticSource 是「没有控制器」时的来源：始终返回配置文件的 targets（全量直通）
type StaticSource struct {
	Compiled *policymodel.Compiled
}

// NewStaticSource 由配置文件的 targets 构造静态来源
func NewStaticSource(targets []config.Target) *StaticSource {
	return &StaticSource{Compiled: CompileLegacy(targets)}
}

// Fetch 实现 Source
func (s *StaticSource) Fetch(context.Context) (*policymodel.Compiled, error) {
	return s.Compiled, nil
}

// Describe 实现 Source
func (s *StaticSource) Describe() string { return msgStaticSourceDesc.S(i18n.ProcessLang()) }

// Report 实现 Source（无控制器，空操作）
func (s *StaticSource) Report(context.Context, Status) error { return nil }

// FormatSources 把允许源列表格式化成一行日志文本
func FormatSources(sources []string) string {
	if len(sources) == 0 {
		return msgNoAllowSources.S(i18n.ProcessLang())
	}
	const max = 6
	if len(sources) <= max {
		return strings.Join(sources, ",")
	}
	return msgSourcesOverflow.S(i18n.ProcessLang(), strings.Join(sources[:max], ","), len(sources))
}

// ParsePortList 解析 "20001,20002" 形式的端口列表（供调试与测试使用）
func ParsePortList(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 {
			return nil, i18n.NewCoded(msgPortInvalid, part)
		}
		out = append(out, port)
	}
	return out, nil
}

// HostOf 返回 host:port 的 host 部分（容错处理非法输入）
func HostOf(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
