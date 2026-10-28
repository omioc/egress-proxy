// Command redirect-agent 是运行在每个工作节点上的 DaemonSet 程序
//
// 它读取 ConfigMap 挂载的配置，独立解析域名，并把命中的目标流量通过专属 iptables 链
// 重定向到代理节点；配置或解析结果变化时更新规则，退出时清理自己管理的规则
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"egress-proxy/internal/agent"
	"egress-proxy/internal/i18n"
	"egress-proxy/internal/logging"
)

const defaultConfigPath = "/etc/egress-proxy/config.yaml"

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

	hostIP := agent.EnvHostIP()
	if hostIP == nil {
		logger.Warn("未读取到 HOST_IP 环境变量（Downward API 注入），将退化为按本机地址判断代理节点角色")
	}

	runner := agent.New(agent.Options{
		ConfigPath: *configPath,
		HostIP:     hostIP,
		NodeName:   agent.EnvNodeName(),
		Logger:     logger,
	})

	logger.Info("redirect-agent 启动",
		"version", logging.VersionString(),
		"config", *configPath, "hostIP", ipString(hostIP), "node", agent.EnvNodeName())
	if err := runner.Run(ctx); err != nil {
		logger.Error("运行失败，退出", "err", err)
		os.Exit(1)
	}
	logger.Info("redirect-agent 已退出")
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
