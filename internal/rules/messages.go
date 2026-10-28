package rules

import "egress-proxy/internal/i18n"

// 本文件集中存放 rules 包面向用户的文案（节点上报给控制器、最终在 WebUI/API 上渲染）。
// 中文是默认语言且必须与改造前的措辞保持逐字一致，英文为等价翻译；
// 模板里直接写 fmt 动词，中英文动词个数与顺序保持一致。
// 规则注释（Comment）不在此列：它是写进内核供排障用的中文，与日志同属运维视角。
var (
	msgChainNameEmpty = i18n.Msg{
		ZH: "chainName 不能为空",
		EN: "chainName must not be empty",
	}
	msgChainNameTooLong = i18n.Msg{
		ZH: "chainName %q 过长（%d），派生链名会超过 iptables 上限 %d，请缩短到 %d 字符以内",
		EN: "chainName %q is too long (%d): derived chain names would exceed the iptables limit of %d, shorten it to at most %d characters",
	}
	msgProxyIPNotIPv4 = i18n.Msg{
		ZH: "proxy.address %v 不是合法的 IPv4 地址",
		EN: "proxy.address %v is not a valid IPv4 address",
	}
	msgExcludeCIDRInvalid = i18n.Msg{
		ZH: "排除网段 %q 无效: %v",
		EN: "exclude CIDR %q is invalid: %v",
	}
	msgTargetPortOutOfRange = i18n.Msg{
		ZH: "目标 %s 的 port %d 超出范围",
		EN: "target %s has port %d out of range",
	}
	msgTargetProxyPortOutOfRange = i18n.Msg{
		ZH: "目标 %s 的 proxyPort %d 超出范围",
		EN: "target %s has proxyPort %d out of range",
	}
	msgInvalidIPv4OrCIDR = i18n.Msg{
		ZH: "不是合法的 IPv4 地址或网段",
		EN: "not a valid IPv4 address or CIDR block",
	}
	msgInvalidIPv4CIDR = i18n.Msg{
		ZH: "不是合法的 IPv4 网段",
		EN: "not a valid IPv4 CIDR block",
	}
)

// codedWithCause 构造「前缀 + 内嵌原因」的双语错误：原因本身也是双语的（*i18n.Coded），
// 所以中英各取一份，避免英文文案里混进中文原因。
func codedWithCause(m i18n.Msg, cause error, args ...any) *i18n.Coded {
	causeZH, causeEN := i18n.Bilingual(cause)
	if causeEN == "" {
		causeEN = causeZH
	}
	return i18n.NewCoded(i18n.Msg{
		ZH: m.S(i18n.ZH, append(append([]any{}, args...), causeZH)...),
		EN: m.S(i18n.EN, append(append([]any{}, args...), causeEN)...),
	})
}
