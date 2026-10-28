package i18n

// logText 是日志、命令行帮助、配置解析错误的「中文原文 → 英文」对照表。
//
// 为什么不给每条日志加一个 key：这些文案的调用点非常分散（几十处 logger.* 与 flag 定义），
// 用「原文即 key」可以一次性把翻译集中在一处，漏译也只是保留中文，不会报错。
// 覆盖情况由 internal/i18n/logs_test.go 静态校验：源码里出现的每一条日志/帮助文案
// 都必须在这里有英文，否则测试失败。
var logText = map[string]string{
	// ------------------------------------------------------------------
	// 通用 / 启动
	// ------------------------------------------------------------------
	"初始化日志失败":   "failed to initialize logging",
	"日志级别无效":    "invalid log level",
	"收到退出信号":    "received shutdown signal",
	"已退出":       "exited",
	"运行失败，退出":   "run failed, exiting",
	"启动失败，退出":   "startup failed, exiting",
	"读取配置失败，退出": "failed to read configuration, exiting",

	// ------------------------------------------------------------------
	// controller
	// ------------------------------------------------------------------
	"HTTP 监听地址（WebUI + API）": "HTTP listen address (WebUI + API)",
	"是否使用 in-cluster 凭据（Pod 只读、ConfigMap 持久化）；本地调试可设为 false 走纯内存": "use in-cluster credentials (read-only Pod access, ConfigMap persistence); set false for a pure in-memory local run",
	"日志级别：debug|info|warn|error": "log level: debug|info|warn|error",
	"控制器所在命名空间":                  "namespace the controller runs in",
	"策略持久化使用的 ConfigMap 名":       "ConfigMap used to persist the policy",
	"接口令牌（为空表示不校验）":              "API token (empty means no authentication)",
	"Pod 列表刷新周期":                 "Pod list refresh interval",
	"不校验 apiserver 证书（默认 true；设为 false 时改用 /var/run/secrets/.../ca.crt 校验）": "skip apiserver certificate verification (default true; set false to verify with /var/run/secrets/.../ca.crt)",
	"文案语言：zh|en（默认跟随 EGRESS_LANG，再缺省中文）":                                    "message language: zh|en (defaults to EGRESS_LANG, then Chinese)",
	"初始化 in-cluster 客户端失败（可加 -in-cluster=false 本地调试）":                       "failed to initialize the in-cluster client (use -in-cluster=false for local debugging)",
	"以内存模式运行：策略不会持久化，也不会解析 Pod（仅用于本地调试）":                                    "running in memory mode: the policy is not persisted and Pods are not resolved (local debugging only)",
	"加载已保存的策略失败，退出（不会以空策略启动，以免覆盖已有策略）":                                      "failed to load the saved policy, exiting (starting with an empty policy could overwrite it)",
	"未配置接口令牌（-token / EGRESS_CONTROLLER_TOKEN），任何能访问该端口的人都能修改出网策略":          "no API token configured (-token / EGRESS_CONTROLLER_TOKEN): anyone who can reach this port can change the egress policy",
	"controller 启动": "controller started",
	"已跳过 apiserver 证书校验（默认行为）；需要严格校验时加 -insecure-skip-verify=false": "apiserver certificate verification is skipped (default); add -insecure-skip-verify=false for strict verification",
	"收到退出信号，正在关闭 HTTP 服务":                                           "shutdown signal received, closing the HTTP server",
	"HTTP 服务异常退出":        "HTTP server exited with an error",
	"关闭 HTTP 服务超时":       "timed out closing the HTTP server",
	"controller 已退出":     "controller exited",
	"列取 Pod 失败，沿用上一次的索引": "listing Pods failed, keeping the previous index",
	"Pod 索引已更新":          "Pod index updated",
	"读取已保存的策略失败，稍后重试":    "failed to read the saved policy, will retry later",

	// ------------------------------------------------------------------
	// redirect-agent / tcp-forwarder
	// ------------------------------------------------------------------
	"配置文件路径（ConfigMap 挂载）": "config file path (mounted from the ConfigMap)",
	"未读取到 HOST_IP 环境变量（Downward API 注入），将退化为按本机地址判断代理节点角色": "HOST_IP is not set (injected by the Downward API); falling back to the local address to decide the proxy-node role",
	"redirect-agent 启动":  "redirect-agent started",
	"redirect-agent 已退出": "redirect-agent exited",
	"启动监听失败，退出":          "failed to start listening, exiting",
	"tcp-forwarder 启动":   "tcp-forwarder started",
	"收到退出信号，停止接受新连接并等待存量连接结束":      "shutdown signal received: stopping new connections and waiting for existing ones to drain",
	"存量连接未在宽限期内排空":                 "existing connections did not drain within the grace period",
	"tcp-forwarder 已退出":            "tcp-forwarder exited",
	"新配置无效，沿用当前配置":                 "new configuration is invalid, keeping the current one",
	"策略来源已切换":                      "policy source switched",
	"应用新配置时部分端口失败":                 "applying the new configuration failed for some ports",
	"配置已应用":                        "configuration applied",
	"按策略同步监听端口失败":                  "syncing listen ports from the policy failed",
	"拉取策略失败，沿用当前监听端口":              "fetching the policy failed, keeping the current listen ports",
	"监听端口已对齐":                      "listen ports aligned",
	"未设置 HOST_IP 环境变量，跳过代理节点一致性校验": "HOST_IP is not set; skipping the proxy-node consistency check",
	"HOST_IP 不是合法 IP，拒绝启动":         "HOST_IP is not a valid IP address, refusing to start",
	"本节点不是配置中指定的代理节点，拒绝启动（请检查 ConfigMap 的 proxy.address 与 nodeSelector）": "this node is not the configured proxy node, refusing to start (check proxy.address in the ConfigMap and the nodeSelector)",
	"未启用健康检查端点（healthPort <= 0）":                                         "health check endpoint disabled (healthPort <= 0)",
	"健康检查端点已启动":          "health check endpoint started",
	"健康检查端点异常退出":         "health check endpoint exited with an error",
	"等待配置文件 %s 就绪超时: %w": "timed out waiting for the config file %s: %w",
	"配置文件暂不可用，稍后重试":      "config file not available yet, will retry",

	// ------------------------------------------------------------------
	// 控制器运行期
	// ------------------------------------------------------------------
	"没有已保存的策略，从空白开始":       "no saved policy found, starting from empty",
	"已保存的策略无法解析，忽略它并从空白开始": "the saved policy cannot be parsed; ignoring it and starting from empty",
	"已保存的策略不合法，忽略它并从空白开始":  "the saved policy is invalid; ignoring it and starting from empty",
	"已恢复策略":   "policy restored",
	"策略已更新":   "policy updated",
	"执行模式已变更": "execution mode changed",
	"授权已变更":   "grant changed",
	"策略持久化失败": "failed to persist the policy",
	"序列化策略失败": "failed to serialize the policy",
	"工作负载解析失败，沿用上次解析的标签选择器": "workload resolution failed; keeping the previously resolved label selector",
}
