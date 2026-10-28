package resolver

import "egress-proxy/internal/i18n"

// 本文件集中存放 resolver 面向用户的文案（解析错误会经 Refresh → Error(host)
// 暴露给 redirect-agent 的状态与日志）。
// 中文是默认语言且必须与改造前的措辞逐字一致，英文为等价翻译；
// 模板里直接写 fmt 动词，中英文动词个数与顺序保持一致。
var (
	// 查询成功但没有任何 IPv4 记录
	msgNoARecord = i18n.Msg{
		ZH: "域名 %s 没有 A 记录（IPv4）",
		EN: "domain %s has no A record (IPv4)",
	}
)
