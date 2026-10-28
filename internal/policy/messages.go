package policy

import "egress-proxy/internal/i18n"

// 本文件集中存放 policy 面向用户的文案：Fetch/Report 的错误会经 redirect-agent
// 上报到控制器的节点状态里（WebUI 可见），Describe/FormatSources 会作为日志字段输出。
// 中文是默认语言且必须与改造前的措辞逐字一致，英文为等价翻译；
// 模板里直接写 fmt 动词，中英文动词个数与顺序保持一致。
var (
	// Fetch：构造 HTTP 请求失败
	msgBuildRequestFailed = i18n.Msg{
		ZH: "构造请求失败: %v",
		EN: "failed to build the request: %v",
	}

	// Fetch：请求控制器失败（网络错误、超时等）
	msgRequestControllerFailed = i18n.Msg{
		ZH: "请求控制器失败: %v",
		EN: "requesting the controller failed: %v",
	}

	// Fetch：读取响应体失败
	msgReadResponseFailed = i18n.Msg{
		ZH: "读取响应失败: %v",
		EN: "failed to read the response: %v",
	}

	// Fetch：控制器返回非 200
	msgControllerStatus = i18n.Msg{
		ZH: "控制器返回 %d: %s",
		EN: "the controller returned %d: %s",
	}

	// Fetch：编译结果无法反序列化
	msgParseCompiledFailed = i18n.Msg{
		ZH: "解析编译结果失败: %v",
		EN: "failed to parse the compiled policy: %v",
	}

	// Fetch：编译结果的 mode 非法
	msgModeInvalid = i18n.Msg{
		ZH: "控制器返回了非法的 mode %q",
		EN: "the controller returned an invalid mode %q",
	}

	// fallback：带着上一次成功的结果继续运行（fail-stale）
	msgKeepLastSuccess = i18n.Msg{
		ZH: "%s（沿用上一次成功的结果 generation=%d）",
		EN: "%s (keeping the last successful result, generation=%d)",
	}

	// Report：上报状态被控制器拒绝
	msgReportStatusFailed = i18n.Msg{
		ZH: "上报状态返回 %d",
		EN: "reporting the status returned %d",
	}

	// ParsePortList：端口不是 1..65535 的数字
	msgPortInvalid = i18n.Msg{
		ZH: "端口 %q 无效",
		EN: "port %q is invalid",
	}

	// StaticSource.Describe：日志字段 source
	msgStaticSourceDesc = i18n.Msg{
		ZH: "配置文件 targets（四元组管控未启用）",
		EN: "config-file targets (four-tuple enforcement disabled)",
	}

	// FormatSources：没有任何允许源
	msgNoAllowSources = i18n.Msg{
		ZH: "（无，任何人都无法访问）",
		EN: "(none: nobody can reach it)",
	}

	// FormatSources：允许源过多时的截断提示
	msgSourcesOverflow = i18n.Msg{
		ZH: "%s …共%d个",
		EN: "%s …%d in total",
	}
)
