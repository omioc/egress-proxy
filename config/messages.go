package config

import "egress-proxy/internal/i18n"

// host / port 的校验文案：这些错误会经策略校验出现在 API 响应与 WebUI 上，
// 所以需要中英双语。两种语言的参数顺序保持一致（Sprintf 按位置取参）。
var (
	msgHostEmpty        = i18n.Msg{ZH: "host 不能为空", EN: "host must not be empty"}
	msgHostIPv6Only     = i18n.Msg{ZH: "第一阶段仅支持 IPv4，不支持 IPv6 地址 %q", EN: "only IPv4 is supported for now; IPv6 address %q is not allowed"}
	msgHostLooksPort    = i18n.Msg{ZH: "%q 形似 IPv6 或非法的 host:port，host 字段只写主机名或 IPv4", EN: "%q looks like IPv6 or an invalid host:port; write only a hostname or an IPv4 address"}
	msgHostTooLong      = i18n.Msg{ZH: "主机名过长（%d > 253）", EN: "hostname is too long (%d > 253)"}
	msgHostEmptyLabel   = i18n.Msg{ZH: "主机名 %q 含有空标签", EN: "hostname %q contains an empty label"}
	msgHostLabelTooLong = i18n.Msg{ZH: "主机名 %q 的标签 %q 过长（> 63）", EN: "hostname %q has a label %q longer than 63 characters"}
	msgHostLabelHyphen  = i18n.Msg{ZH: "主机名 %q 的标签 %q 不能以连字符开头或结尾", EN: "hostname %q has a label %q that starts or ends with a hyphen"}
	msgHostBadChar      = i18n.Msg{ZH: "主机名 %q 含非法字符 %q", EN: "hostname %q contains the invalid character %q"}
	msgPortOutOfRange   = i18n.Msg{ZH: "%d 超出范围 1-65535", EN: "%d is out of range 1-65535"}
)
