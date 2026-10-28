package iptables

import "egress-proxy/internal/i18n"

// 本文件集中存放 iptables 包面向用户的文案（节点上报给控制器、最终在 WebUI/API 上渲染）。
// 中文是默认语言且必须与改造前的措辞保持逐字一致，英文为等价翻译；
// 模板里直接写 fmt 动词，中英文动词个数与顺序保持一致。
// 日志不在此列（日志按 internal/i18n 的约定保持中文，见各调用点的 i18n.Text）。
var (
	// Plan.Validate 汇总
	msgPlanInvalid = i18n.Msg{
		ZH: "规则计划无效:",
		EN: "invalid rule plan:",
	}

	// chains 校验
	msgPlanTableUnsupported = i18n.Msg{
		ZH: "%s: 表 %q 不支持（只允许 nat / filter）",
		EN: "%s: table %q is not supported (only nat / filter are allowed)",
	}
	msgPlanChainNameInvalid = i18n.Msg{
		ZH: "%s: 链名 %q 无效: %v",
		EN: "%s: chain name %q is invalid: %v",
	}
	msgPlanChainDuplicate = i18n.Msg{
		ZH: "%s: 链 %s 重复声明",
		EN: "%s: chain %s is declared more than once",
	}

	// rules 校验
	msgPlanJumpTargetMissing = i18n.Msg{
		ZH: "%s: 跳转目标 %q 不在同一 Plan 中",
		EN: "%s: jump target %q is not in the same Plan",
	}
	msgPlanDNATMissingDest = i18n.Msg{
		ZH: "%s: DNAT 缺少 --to-destination",
		EN: "%s: DNAT is missing --to-destination",
	}
	msgPlanDNATPortNeedsProtocol = i18n.Msg{
		ZH: "%s: DNAT 目标 %s 指定了端口但没有 Protocol（需要 -p tcp）",
		EN: "%s: DNAT destination %s specifies a port but no Protocol (needs -p tcp)",
	}
	msgPlanRejectResetNeedsTCP = i18n.Msg{
		ZH: "%s: REJECT --reject-with tcp-reset 要求规则匹配 tcp（当前 Protocol=%q）",
		EN: "%s: REJECT --reject-with tcp-reset requires the rule to match tcp (current Protocol=%q)",
	}
	msgPlanPortNeedsProtocol = i18n.Msg{
		ZH: "%s: 指定了 Port 但没有 Protocol",
		EN: "%s: Port is set but Protocol is empty",
	}
	msgPlanPortOutOfRange = i18n.Msg{
		ZH: "%s: Port %d 越界",
		EN: "%s: Port %d is out of range",
	}
	msgPlanSrcInvalid = i18n.Msg{
		ZH: "%s: src %q 无效: %v",
		EN: "%s: src %q is invalid: %v",
	}
	msgPlanDstInvalid = i18n.Msg{
		ZH: "%s: dst %q 无效: %v",
		EN: "%s: dst %q is invalid: %v",
	}

	// jumps 校验
	msgPlanJumpTableUnsupported = i18n.Msg{
		ZH: "%s: 表 %q 不支持",
		EN: "%s: table %q is not supported",
	}
	msgPlanParentNotBuiltin = i18n.Msg{
		ZH: "%s: 父链 %q 不是内建链",
		EN: "%s: parent chain %q is not a builtin chain",
	}
	msgPlanChildMissing = i18n.Msg{
		ZH: "%s: 子链 %q 不在同一 Plan 中",
		EN: "%s: child chain %q is not in the same Plan",
	}
	msgPlanPositionInvalid = i18n.Msg{
		ZH: "%s: Position %d 只支持 0（追加）或 1（置顶）",
		EN: "%s: Position %d only supports 0 (append) or 1 (insert first)",
	}

	// 链名校验
	msgChainNameEmpty = i18n.Msg{
		ZH: "不能为空",
		EN: "must not be empty",
	}
	msgChainNameTooLong = i18n.Msg{
		ZH: "长度 %d 超过上限 %d",
		EN: "length %d exceeds the maximum %d",
	}
	msgChainNameBuiltin = i18n.Msg{
		ZH: "是 iptables 内建链",
		EN: "is a builtin iptables chain",
	}
	msgChainNameLeadingDash = i18n.Msg{
		ZH: "不能以 - 开头",
		EN: "must not start with -",
	}
	msgChainNameInvalidChar = i18n.Msg{
		ZH: "含非法字符 %q",
		EN: "contains the illegal character %q",
	}

	// 地址/网段校验
	msgInvalidIPv4OrCIDR = i18n.Msg{
		ZH: "不是合法的 IPv4 地址或网段",
		EN: "not a valid IPv4 address or CIDR block",
	}

	// 实际写内核时的失败
	msgCreateChainFailed = i18n.Msg{
		ZH: "创建链 %s/%s 失败: %v",
		EN: "failed to create chain %s/%s: %v",
	}
	msgFlushChainFailed = i18n.Msg{
		ZH: "清空链 %s/%s 失败: %v",
		EN: "failed to flush chain %s/%s: %v",
	}
	msgAddRuleFailed = i18n.Msg{
		ZH: "写入规则失败（%s/%s）: %v",
		EN: "failed to add rule (%s/%s): %v",
	}
	msgDeleteChainFailed = i18n.Msg{
		ZH: "删除链 %s/%s 失败: %v",
		EN: "failed to delete chain %s/%s: %v",
	}
	msgAddJumpFailed = i18n.Msg{
		ZH: "添加跳转 %s/%s → %s 失败: %v",
		EN: "failed to add jump %s/%s → %s: %v",
	}
)
