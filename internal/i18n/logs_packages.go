package i18n

// logTextPackages 收录内部包（iptables / rules / agent / forward / policy / resolver /
// filewatch / config / cmd）里的日志、命令行帮助、配置校验与 iptables 规则注释的英文翻译。
//
// 这些文案由 internal/logging 的 handler 与各处 i18n.Text(...) 在写日志/拼帮助时按进程语言取用；
// 覆盖情况由 logs_test.go 静态校验（源码里出现的每一条都必须在这里有英文）。
var logTextPackages = map[string]string{
	// ---------------- iptables 规则注释（会出现在 iptables -S 里） ----------------
	" 代理节点自身出站":            " the proxy node itself (egress)",
	" 代理节点自身，避免回绕":         " the proxy node itself, avoiding a loop back",
	" 排除网段":                " excluded CIDR",
	" 本机回环":                " local loopback",
	"%s %s（不限源）":           "%s %s (any source)",
	"%s 已授权 %s":            "%s authorized %s",
	"%s 拒绝未授权访问 %s":        "%s reject unauthorized access to %s",
	"%s 未授权访问 %s":          "%s unauthorized access to %s",
	"%s 观察模式：记录本应被拒的连接 %s": "%s observe mode: log connections that would be rejected %s",

	// ---------------- config：文件解析与校验 ----------------
	"invalid duration %q: 需要形如 \"30s\" 的字符串或整数秒": "invalid duration %q: expected a string like \"30s\" or an integer number of seconds",
	"解析 YAML 失败: %w": "failed to parse YAML: %w",
	"proxy.address 不能为空（需填写代理节点的 IPv4 地址）":           "proxy.address must not be empty (set the IPv4 address of the proxy node)",
	"proxy.address %q 不是合法 IP":                       "proxy.address %q is not a valid IP address",
	"proxy.address %q 不是 IPv4（第一阶段仅支持 IPv4）":         "proxy.address %q is not IPv4 (only IPv4 is supported for now)",
	"proxy.listen 无效: %v":                            "proxy.listen is invalid: %v",
	"%s: host+port 组合 %s 与 targets[%d] 重复":           "%s: host+port combination %s duplicates targets[%d]",
	"%s: proxyPort %d 与 %s 重复，必须全局唯一":                "%s: proxyPort %d duplicates %s; proxyPort must be globally unique",
	"options.%s 过小（%s），不能小于 %s":                      "options.%s is too small (%s), it must not be less than %s",
	"options.maxIPsPerHost 不能为负数，当前 %d":              "options.maxIPsPerHost must not be negative, currently %d",
	"options.healthPort %d 超出范围 1-65535":             "options.healthPort %d is out of range 1-65535",
	"options.chainName 无效: %v":                       "options.chainName is invalid: %v",
	"options.iptablesBinary 无效: %v":                  "options.iptablesBinary is invalid: %v",
	"options.excludeCIDRs[%d] %q 无效: %v":             "options.excludeCIDRs[%d] %q is invalid: %v",
	"options.dnsServers[%d] %q 无效: %v":               "options.dnsServers[%d] %q is invalid: %v",
	"options.policyUrl %q 无效: %v":                    "options.policyUrl %q is invalid: %v",
	"options.policyUrl %q 必须以 http:// 或 https:// 开头": "options.policyUrl %q must start with http:// or https://",
	"options.policyUrl %q 缺少主机名":                     "options.policyUrl %q has no host name",
	"配置校验失败:\n  - %s":                                "configuration validation failed:\n  - %s",
	"仅支持 IPv4 网段":                                    "only IPv4 CIDR ranges are supported",
	"不能为空":                                           "must not be empty",
	"需要 IP 或 IP:port 形式":                             "expected IP or IP:port",
	"%q 不是合法 IP":                                     "%q is not a valid IP address",
	"端口 %q 无效":                                       "port %q is invalid",
	"包含非法字符":                                         "contains illegal characters",
	"不能以 - 开头":                                       "must not start with -",
	"长度 %d 超过 iptables 上限 28":                        "length %d exceeds the iptables limit of 28",
	"含非法字符 %q（仅允许字母、数字、- 和 _）":                       "contains the illegal character %q (only letters, digits, - and _ are allowed)",
	"%q 是 iptables 内建链，不能使用":                         "%q is a builtin iptables chain and cannot be used",
	"%q 不能包含空格或路径分隔符":                                "%q must not contain spaces or path separators",
	"%q 只能是可执行文件名":                                   "%q must be an executable name only",

	// ---------------- internal/iptables ----------------
	"删除多余托管链失败":                     "failed to delete stale managed chains",
	"读取 iptables 状态失败，按空快照处理":       "failed to read the iptables state, treating it as an empty snapshot",
	"iptables-restore 失败，回退为逐条添加规则": "iptables-restore failed, falling back to adding rules one by one",
	"清空遗留链失败":                       "failed to flush the leftover chain",
	"已删除不再需要的链":                     "deleted a chain that is no longer needed",
	"删除跳转失败":                        "failed to delete the jump rule",
	"删除旧跳转失败":                       "failed to delete the old jump rule",
	"已添加跳转规则":                       "jump rule added",
	"清空链失败":                         "failed to flush the chain",
	"已删除链":                          "deleted the chain",

	// ---------------- internal/rules / internal/agent ----------------
	"iptables 规则已更新":               "iptables rules updated",
	"四元组策略已更新":                     "four-tuple policy updated",
	"检测到静态配置变化":                    "static configuration change detected",
	"域名解析结果变化，准备重建规则":              "DNS resolution changed, rebuilding rules",
	"首次应用规则失败":                     "the first rule apply failed",
	"新配置无效，沿用当前配置":                 "the new configuration is invalid, keeping the current one",
	"应用新配置失败，将按 syncInterval 继续重试": "applying the new configuration failed; retrying every syncInterval",
	"同步规则失败":                       "syncing rules failed",
	"上报节点状态失败":                     "reporting node status failed",
	"拉取四元组策略失败":                    "fetching the four-tuple policy failed",
	"未能从控制器获取策略，暂时退化为配置文件 targets 全量直通":      "could not get a policy from the controller; temporarily passing every config-file target straight through",
	"以下目标当前没有解析结果，本次不生成直连拒绝规则（子链仍为空，等于全部拒绝）": "these targets have no resolved addresses yet, so no deny rules are generated this round (the sub-chain stays empty, which means deny everything)",
	"收到退出信号，开始清理规则":                          "shutdown signal received, cleaning up rules",
	"清理 iptables 规则失败，请人工检查":                 "failed to clean up iptables rules; manual inspection required",
	"清理旧链失败": "failed to clean up the old chain",

	// ---------------- internal/forward ----------------
	"监听地址变化，重建全部监听端口":  "listen address changed, rebuilding every listener",
	"已停止监听（目标已从配置中移除）": "stopped listening (the target was removed from the configuration)",
	"已更新转发目标":          "forwarding targets updated",
	"开始监听端口并转发":        "started listening and forwarding",
	"等待存量连接排空超时，立即退出":  "timed out waiting for existing connections to drain, exiting now",
	"写入健康检查响应失败":       "failed to write the health check response",
	"接受连接失败，稍后重试":      "accepting a connection failed, retrying later",
	"关闭监听器返回错误":        "closing the listener returned an error",
	"该端口没有配置转发目标，断开连接": "no forwarding target is configured for this port, closing the connection",
	"连接原始目标失败":         "failed to connect to the original target",
	"开始转发":             "forwarding started",
	"转发结束":             "forwarding finished",

	// ---------------- internal/resolver / internal/filewatch ----------------
	"域名解析失败，沿用上次结果":  "DNS resolution failed, keeping the previous result",
	"域名解析结果变化":       "DNS resolution changed",
	"域名解析结果超过上限，已截断": "DNS results exceed the limit and were truncated",
	"读取配置文件失败，稍后重试":  "failed to read the config file, retrying later",

	// ---------------- internal/policy ----------------
	"读取策略缓存失败":       "failed to read the policy cache",
	"策略缓存内容无法解析，已忽略": "the policy cache cannot be parsed; ignoring it",
	"已载入本地策略缓存":      "loaded the local policy cache",
	"序列化策略缓存失败":      "failed to serialize the policy cache",
	"创建策略缓存目录失败":     "failed to create the policy cache directory",
	"写入策略缓存失败":       "failed to write the policy cache",
	"重命名策略缓存失败":      "failed to rename the policy cache",

	// ---------------- controller 的启动期与配置加载错误（会进日志） ----------------
	"未找到 KUBERNETES_SERVICE_HOST，请确认运行在集群内（或使用 -in-cluster=false）": "KUBERNETES_SERVICE_HOST is not set; make sure the process runs inside a cluster (or use -in-cluster=false)",
	"读取 ServiceAccount token（%s）失败: %w":                            "failed to read the ServiceAccount token (%s): %w",
	"读取集群 CA（%s）失败: %w":                                            "failed to read the cluster CA (%s): %w",
	"集群 CA（%s）内容无效，无法用于校验 apiserver 证书":                            "the cluster CA (%s) is not valid for verifying the apiserver certificate",
	"读取已保存的策略失败: %w":                                               "failed to read the saved policy: %w",
	"(无)":                                                          "(none)",
}

func init() {
	for zh, en := range logTextPackages {
		if _, ok := logText[zh]; !ok {
			logText[zh] = en
		}
	}
}
