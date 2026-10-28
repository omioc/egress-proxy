package policymodel

import "egress-proxy/internal/i18n"

// 本文件集中存放 policymodel 面向用户的文案（WebUI / REST API 可见），
// 中文是默认语言且必须与改造前的措辞保持逐字一致，英文为等价翻译。
// 约定：模板里直接写 fmt 动词；中英文动词个数与顺序保持一致。
var (
	// Validate 汇总
	msgValidateFailed = i18n.Msg{
		ZH: "配置校验失败:\n  - %s",
		EN: "configuration validation failed:\n  - %s",
	}

	// mode
	msgModeInvalid = i18n.Msg{
		ZH: "mode %q 无效，只能是 disabled / observe / enforce",
		EN: "mode %q is invalid, must be one of disabled / observe / enforce",
	}

	// payloads
	msgPayloadNameInvalid = i18n.Msg{
		ZH: "%s: 名称 %q 非法，需匹配 %s",
		EN: "%s: name %q is invalid, must match %s",
	}
	msgPayloadNameDuplicate = i18n.Msg{
		ZH: "%s: 名称 %q 与 payloads[%d] 重复",
		EN: "%s: name %q duplicates payloads[%d]",
	}
	msgPayloadSelectorEmpty = i18n.Msg{
		ZH: "%s (%s): namespaces 与 matchLabels 不能同时为空（否则会匹配全部 Pod）",
		EN: "%s (%s): namespaces and matchLabels cannot both be empty (otherwise every Pod would match)",
	}
	msgWorkloadKindInvalid = i18n.Msg{
		ZH: "%s (%s): workload.kind %q 无效，只能是 Deployment / StatefulSet / DaemonSet",
		EN: "%s (%s): workload.kind %q is invalid, must be one of Deployment / StatefulSet / DaemonSet",
	}
	msgWorkloadNameInvalid = i18n.Msg{
		ZH: "%s (%s): workload.name %q 不是合法的工作负载名",
		EN: "%s (%s): workload.name %q is not a valid workload name",
	}
	msgWorkloadNamespaceCount = i18n.Msg{
		ZH: "%s (%s): 按工作负载名匹配时必须且只能指定 1 个命名空间（当前 %d 个）",
		EN: "%s (%s): matching by workload name requires exactly 1 namespace (currently %d)",
	}
	msgWorkloadSelectorUnresolved = i18n.Msg{
		ZH: "%s (%s): 未能把工作负载 %s/%s 解析成标签选择器（工作负载可能已删除，或只用了 matchExpressions），请改用标签模式",
		EN: "%s (%s): failed to resolve workload %s/%s into a label selector (the workload may have been deleted, or it only uses matchExpressions); use label mode instead",
	}
	msgNamespaceInvalid = i18n.Msg{
		ZH: "%s (%s): namespaces[%d] %q 不是合法的命名空间名",
		EN: "%s (%s): namespaces[%d] %q is not a valid namespace name",
	}
	msgMatchLabelKeyInvalid = i18n.Msg{
		ZH: "%s (%s): matchLabels 的键 %q 非法",
		EN: "%s (%s): matchLabels key %q is invalid",
	}
	msgMatchLabelValueInvalid = i18n.Msg{
		ZH: "%s (%s): matchLabels[%q] 的值 %q 非法",
		EN: "%s (%s): matchLabels[%q] value %q is invalid",
	}

	// targets
	msgHostInvalid = i18n.Msg{
		ZH: "%s: host %q 无效: %v",
		EN: "%s: host %q is invalid: %v",
	}
	msgTargetPortInvalid = i18n.Msg{
		ZH: "%s (%s): port %v",
		EN: "%s (%s): port %v",
	}
	msgTargetProxyPortInvalid = i18n.Msg{
		ZH: "%s (%s): proxyPort %v",
		EN: "%s (%s): proxyPort %v",
	}
	msgTargetDuplicate = i18n.Msg{
		ZH: "%s: %s 与 targets[%d] 重复",
		EN: "%s: %s duplicates targets[%d]",
	}
	msgProxyPortDuplicate = i18n.Msg{
		ZH: "%s: proxyPort %d 与 %s 重复，必须全局唯一",
		EN: "%s: proxyPort %d duplicates %s; proxyPort must be globally unique",
	}

	// grants
	msgGrantPayloadMissing = i18n.Msg{
		ZH: "%s: payload %q 不存在",
		EN: "%s: payload %q does not exist",
	}
	msgGrantTargetMissing = i18n.Msg{
		ZH: "%s: target %q 不存在（需写成 host:port）",
		EN: "%s: target %q does not exist (must be written as host:port)",
	}
	msgGrantDuplicate = i18n.Msg{
		ZH: "%s: (%s, %s) 与 grants[%d] 重复",
		EN: "%s: (%s, %s) duplicates grants[%d]",
	}

	// Warnings
	msgWarnPayloadNoMatchLabels = i18n.Msg{
		ZH: "payload %q 未设置 matchLabels：会匹配所选命名空间下的全部 Pod",
		EN: "payload %q has no matchLabels set: it will match every Pod in the selected namespaces",
	}
	msgWarnPayloadNoNamespaces = i18n.Msg{
		ZH: "payload %q 未限制命名空间：会匹配集群内所有命名空间",
		EN: "payload %q does not restrict namespaces: it will match every namespace in the cluster",
	}
	msgWarnTargetNoGrants = i18n.Msg{
		ZH: "target %s 没有任何授权：当前所有负载都无法访问它（默认拒绝）",
		EN: "target %s has no grant: no workload can reach it right now (default deny)",
	}

	// 源地址（IP / CIDR）解析错误
	msgSourceEmpty = i18n.Msg{
		ZH: "不能为空",
		EN: "must not be empty",
	}
	msgSourceNotIPOrCIDR = i18n.Msg{
		ZH: "不是合法的 IP 或 CIDR",
		EN: "not a valid IP or CIDR",
	}
	msgSourceIPv4Only = i18n.Msg{
		ZH: "仅支持 IPv4",
		EN: "only IPv4 is supported",
	}
	msgSourceNotCIDR = i18n.Msg{
		ZH: "不是合法的 CIDR",
		EN: "not a valid CIDR",
	}
	msgSourceIPv4CIDROnly = i18n.Msg{
		ZH: "仅支持 IPv4 网段",
		EN: "only IPv4 CIDR ranges are supported",
	}

	// 工作负载标签选择器解析错误
	msgResolveWorkloadNoSelector = i18n.Msg{
		ZH: "工作负载 %s/%s 没有 matchLabels 选择器（可能只用了 matchExpressions），请改用标签选择器手动填写",
		EN: "workload %s/%s has no matchLabels selector (it may only use matchExpressions); fill in a label selector manually instead",
	}
	msgResolveWorkloadNotFound = i18n.Msg{
		ZH: "找不到工作负载 %s %s/%s，请确认它存在且控制器有读取权限",
		EN: "workload %s %s/%s not found; make sure it exists and that the controller is allowed to read it",
	}
)
