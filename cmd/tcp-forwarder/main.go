// Command tcp-forwarder 是运行在代理节点上的转发服务
//
// 目标列表（proxyPort → 原始目标）有两个来源：
//   - 启用四元组管控（配置了 options.policyUrl）：从控制器 /api/v1/compiled 拉取，
//     与各节点的 redirect-agent 使用同一份策略，WebUI 上改动即时生效；
//   - 未启用：沿用 ConfigMap 里的 targets（与改造前行为一致）
//
// 静态参数（监听地址、健康检查端口、拨号超时）始终来自 ConfigMap
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"egress-proxy/config"
	"egress-proxy/internal/filewatch"
	"egress-proxy/internal/forward"
	"egress-proxy/internal/i18n"
	"egress-proxy/internal/logging"
	"egress-proxy/internal/policy"
	"egress-proxy/internal/policymodel"
)

const (
	defaultConfigPath = "/etc/egress-proxy/config.yaml"
	// shutdownGrace 是退出时等待存量连接结束的宽限期
	shutdownGrace = 10 * time.Second
	// configWaitTimeout 是启动时等待配置文件出现的最长时间
	configWaitTimeout = 60 * time.Second
	// minPolicyInterval 是轮询策略的最小间隔
	minPolicyInterval = 500 * time.Millisecond
)

func main() {
	// 先按环境变量定进程语言，这样 -h 的输出也是当前语言
	i18n.SetProcessLangFromArgs(os.Args[1:])

	configPath := flag.String("config", defaultConfigPath, i18n.Text("配置文件路径（ConfigMap 挂载）"))
	logLevel := flag.String("log-level", "info", i18n.Text("日志级别：debug|info|warn|error"))
	lang := flag.String("lang", string(i18n.LangFromEnv(i18n.ZH)), i18n.Text("文案语言：zh|en（默认跟随 EGRESS_LANG，再缺省中文）"))
	flag.Parse()
	i18n.SetProcessLang(i18n.ParseLang(*lang, i18n.LangFromEnv(i18n.ZH)))

	logger, err := logging.New(*logLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, i18n.Text("初始化日志失败")+":", err)
		os.Exit(2)
	}
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	cfg, err := waitForConfig(ctx, *configPath, logger)
	if err != nil {
		logger.Error("读取配置失败，退出", "err", err)
		os.Exit(1)
	}

	if !checkNodeIdentity(cfg, logger) {
		os.Exit(1)
	}

	server := forward.New(cfg.Options.DialTimeout.D(), logger)
	state := &runtimeState{cfg: cfg, source: newSource(cfg, logger)}

	if err := syncOnce(ctx, server, state, logger); err != nil {
		logger.Error("启动监听失败，退出", "err", err)
		os.Exit(1)
	}
	logger.Info("tcp-forwarder 启动",
		"version", logging.VersionString(),
		"config", *configPath, "proxyAddress", cfg.Proxy.Address,
		"targets", len(cfg.Targets), "policyUrl", cfg.Options.PolicyURL,
		"source", state.source.Describe(), "listenPorts", len(server.Stats().Listeners))

	health := startHealthServer(cfg.Options.HealthPort, server, logger)
	events := filewatch.New(*configPath, cfg.Options.ConfigInterval.D(), logger).Watch(ctx)

	interval := state.cfg.Options.PolicyInterval.D()
	if interval < minPolicyInterval {
		interval = minPolicyInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("收到退出信号，停止接受新连接并等待存量连接结束")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
			if err := server.Shutdown(shutdownCtx); err != nil {
				logger.Warn("存量连接未在宽限期内排空", "err", err)
			}
			cancel()
			if health != nil {
				closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
				_ = health.Shutdown(closeCtx)
				closeCancel()
			}
			logger.Info("tcp-forwarder 已退出")
			return

		case content, ok := <-events:
			if !ok {
				return
			}
			newCfg, err := config.Parse(content)
			if err != nil {
				logger.Error("新配置无效，沿用当前配置", "err", err)
				continue
			}
			if newCfg.Hash == state.cfg.Hash {
				continue
			}
			urlChanged := newCfg.Options.PolicyURL != state.cfg.Options.PolicyURL
			state.cfg = newCfg
			if urlChanged {
				state.source = newSource(newCfg, logger)
				logger.Info("策略来源已切换", "source", state.source.Describe())
			}
			if err := syncOnce(ctx, server, state, logger); err != nil {
				logger.Error("应用新配置时部分端口失败", "err", err)
			}
			if newCfg.Options.HealthPort != cfg.Options.HealthPort {
				if health != nil {
					closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
					_ = health.Shutdown(closeCtx)
					closeCancel()
				}
				health = startHealthServer(newCfg.Options.HealthPort, server, logger)
			}
			logger.Info("配置已应用", "hash", shortHash(newCfg.Hash),
				"listenPorts", len(server.Stats().Listeners))

		case <-ticker.C:
			if err := syncOnce(ctx, server, state, logger); err != nil {
				logger.Warn("按策略同步监听端口失败", "err", err)
			}
		}
	}
}

// runtimeState 保存运行期的配置与策略来源
type runtimeState struct {
	cfg    *config.Config
	source policy.Source
}

// newSource 按配置选择策略来源（控制器或配置文件）
func newSource(cfg *config.Config, logger *slog.Logger) policy.Source {
	if strings.TrimSpace(cfg.Options.PolicyURL) == "" {
		return policy.NewStaticSource(cfg.Targets)
	}
	return policy.NewHTTPClient(policy.Options{
		BaseURL:  cfg.Options.PolicyURL,
		NodeName: envOrDefault("NODE_NAME", ""),
		Token:    strings.TrimSpace(os.Getenv("EGRESS_CONTROLLER_TOKEN")),
		Timeout:  cfg.Options.PolicyInterval.D(),
		Logger:   logger,
	})
}

// syncOnce 拉一次策略并把监听端口对齐
func syncOnce(ctx context.Context, server *forward.Server, state *runtimeState, logger *slog.Logger) error {
	fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	compiled, err := state.source.Fetch(fetchCtx)
	cancel()
	if err != nil {
		logger.Warn("拉取策略失败，沿用当前监听端口", "source", state.source.Describe(), "err", err)
	}
	if compiled == nil {
		// 控制器不可用且无缓存：退回配置文件 targets
		compiled = policy.CompileLegacy(state.cfg.Targets)
	}

	server.SetDialTimeout(state.cfg.Options.DialTimeout.D())
	desired := desiredTargets(compiled)
	if err := server.ApplyTargets(state.cfg.Proxy.Listen, desired); err != nil {
		return err
	}
	logger.Debug("监听端口已对齐", "mode", compiled.Mode.String(),
		"generation", compiled.Generation, "targets", len(desired))
	return nil
}

// desiredTargets 把编译结果转成「proxyPort → host:port」
func desiredTargets(compiled *policymodel.Compiled) map[int]string {
	desired := make(map[int]string, len(compiled.Targets))
	for _, t := range compiled.Targets {
		desired[t.ProxyPort] = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	return desired
}

// checkNodeIdentity 校验本节点是否为配置中指定的代理节点，避免代理地址配置错误
func checkNodeIdentity(cfg *config.Config, logger *slog.Logger) bool {
	raw := strings.TrimSpace(os.Getenv("HOST_IP"))
	if raw == "" {
		logger.Warn("未设置 HOST_IP 环境变量，跳过代理节点一致性校验")
		return true
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		logger.Error("HOST_IP 不是合法 IP，拒绝启动", "hostIP", raw)
		return false
	}
	if !cfg.IsProxyNode(ip) {
		logger.Error("本节点不是配置中指定的代理节点，拒绝启动（请检查 ConfigMap 的 proxy.address 与 nodeSelector）",
			"nodeIP", raw, "proxyAddress", cfg.Proxy.Address)
		return false
	}
	return true
}

// startHealthServer 启动健康检查端点（/healthz、/readyz）
// 使用 hostNetwork，因此绑定 0.0.0.0 以便 kubelet 的探针可以访问
func startHealthServer(port int, server *forward.Server, logger *slog.Logger) *http.Server {
	if port <= 0 {
		logger.Info("未启用健康检查端点（healthPort <= 0）")
		return nil
	}
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(port))
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	// 端口可能因配置热更新而重建，这里用 WaitGroup 之外的简单方式避免重复监听报错
	var once sync.Once
	go func() {
		once.Do(func() {
			logger.Info("健康检查端点已启动", "addr", addr, "path", "/healthz")
			if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("健康检查端点异常退出", "err", err)
			}
		})
	}()
	return httpSrv
}

// waitForConfig 等待配置文件可用（ConfigMap 挂载完成）并解析成功
func waitForConfig(ctx context.Context, path string, logger *slog.Logger) (*config.Config, error) {
	deadline := time.Now().Add(configWaitTimeout)
	for {
		cfg, err := config.Load(path)
		if err == nil {
			return cfg, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf(i18n.Text("等待配置文件 %s 就绪超时: %w"), path, err)
		}
		logger.Warn("配置文件暂不可用，稍后重试", "path", path, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func shortHash(hash string) string {
	if len(hash) > 12 {
		return hash[:12]
	}
	return hash
}
