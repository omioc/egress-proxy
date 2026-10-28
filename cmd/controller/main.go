// Command controller 是 egress-proxy 的四元组策略控制面：
// 提供 REST API 与内置 WebUI，负责策略持久化、Pod 解析与按节点编译
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"egress-proxy/internal/controller"
	"egress-proxy/internal/i18n"
	"egress-proxy/internal/logging"
	"egress-proxy/internal/policymodel"
)

const (
	defaultListen      = ":18082"
	defaultPodInterval = 5 * time.Second
	shutdownGrace      = 10 * time.Second
)

func main() {
	// 先按环境变量定进程语言，这样 -h 的输出也是当前语言
	i18n.SetProcessLangFromArgs(os.Args[1:])

	lang := flag.String("lang", string(i18n.LangFromEnv(i18n.ZH)), i18n.Text("文案语言：zh|en（默认跟随 EGRESS_LANG，再缺省中文）"))
	listen := flag.String("listen", defaultListen, i18n.Text("HTTP 监听地址（WebUI + API）"))
	logLevel := flag.String("log-level", "info", i18n.Text("日志级别：debug|info|warn|error"))
	inCluster := flag.Bool("in-cluster", true,
		i18n.Text("是否使用 in-cluster 凭据（Pod 只读、ConfigMap 持久化）；本地调试可设为 false 走纯内存"))
	namespace := flag.String("namespace", envOrDefault("POD_NAMESPACE", "egress-proxy"), i18n.Text("控制器所在命名空间"))
	configMap := flag.String("configmap", controller.DefaultConfigMapName, i18n.Text("策略持久化使用的 ConfigMap 名"))
	token := flag.String("token", envOrDefault("EGRESS_CONTROLLER_TOKEN", ""), i18n.Text("接口令牌（为空表示不校验）"))
	podInterval := flag.Duration("pod-interval", defaultPodInterval, i18n.Text("Pod 列表刷新周期"))
	insecureSkipVerify := flag.Bool("insecure-skip-verify", true,
		i18n.Text("不校验 apiserver 证书（默认 true；设为 false 时改用 /var/run/secrets/.../ca.crt 校验）"))
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

	var (
		storage controller.PolicyStorage
		pods    controller.PodLister
		cluster controller.ClusterReader
	)
	if *inCluster {
		client, err := controller.NewInCluster(*namespace, *configMap, *insecureSkipVerify)
		if err != nil {
			logger.Error("初始化 in-cluster 客户端失败（可加 -in-cluster=false 本地调试）", "err", err)
			os.Exit(1)
		}
		storage = client
		pods = client
		cluster = client
	} else {
		storage = &controller.MemoryStorage{}
		logger.Warn("以内存模式运行：策略不会持久化，也不会解析 Pod（仅用于本地调试）")
	}

	store := controller.NewStore(storage, logger)
	// 读取已保存的策略：失败时重试几次再退出
	// 刻意不做「读不到就从空策略开始」——那会在下次保存时覆盖掉已有策略
	if err := loadWithRetry(ctx, store, logger); err != nil {
		logger.Error("加载已保存的策略失败，退出（不会以空策略启动，以免覆盖已有策略）", "err", err)
		os.Exit(1)
	}

	if pods != nil {
		go podLoop(ctx, store, pods, *podInterval, logger)
	}

	api := controller.NewAPI(store, *token, logger)
	if cluster != nil {
		// 让 WebUI 表单能直接下拉选择命名空间与工作负载（只读）
		api.SetCluster(cluster)
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	if strings.TrimSpace(*token) == "" {
		logger.Warn("未配置接口令牌（-token / EGRESS_CONTROLLER_TOKEN），任何能访问该端口的人都能修改出网策略")
	}
	logger.Info("controller 启动",
		"version", logging.VersionString(),
		"listen", *listen, "inCluster", *inCluster,
		"namespace", *namespace, "configmap", *configMap,
		"podInterval", podInterval.String(),
		"clusterMeta", cluster != nil,
		"insecureSkipVerify", *insecureSkipVerify)
	if *insecureSkipVerify {
		logger.Warn("已跳过 apiserver 证书校验（默认行为）；需要严格校验时加 -insecure-skip-verify=false")
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("收到退出信号，正在关闭 HTTP 服务")
	case err := <-errCh:
		logger.Error("HTTP 服务异常退出", "err", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("关闭 HTTP 服务超时", "err", err)
	}
	logger.Info("controller 已退出")
}

// podLoop 周期性刷新 Pod 索引；失败时保留旧索引（fail-stale）
func podLoop(ctx context.Context, store *controller.Store, lister controller.PodLister, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = defaultPodInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lastCount = -1
	var lastErr string

	refresh := func() {
		timeout := interval
		if timeout < 5*time.Second {
			timeout = 5 * time.Second
		}
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		pods, err := lister.ListPods(fetchCtx)
		if err != nil {
			store.SetPodsError(err)
			if err.Error() != lastErr {
				logger.Error("列取 Pod 失败，沿用上一次的索引", "err", err)
				lastErr = err.Error()
			}
			return
		}
		lastErr = ""
		store.ReplacePods(pods)
		if len(pods) != lastCount {
			logger.Info("Pod 索引已更新", "pods", len(pods), "withIP", countWithIP(pods))
			lastCount = len(pods)
		}
	}

	refresh()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func countWithIP(pods []policymodel.Pod) int {
	n := 0
	for _, p := range pods {
		if strings.TrimSpace(p.IP) != "" {
			n++
		}
	}
	return n
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// loadWithRetry 最多尝试 5 次（约 20s）读取已保存的策略，覆盖 apiserver 短暂不可用的情况
func loadWithRetry(ctx context.Context, store *controller.Store, logger *slog.Logger) error {
	const attempts = 5
	var err error
	for i := 1; i <= attempts; i++ {
		err = store.Load(ctx)
		if err == nil {
			return nil
		}
		if i == attempts {
			break
		}
		delay := time.Duration(i) * 2 * time.Second
		logger.Warn("读取已保存的策略失败，稍后重试",
			"attempt", i, "max", attempts, "delay", delay.String(), "err", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return err
}
