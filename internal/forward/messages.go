package forward

import "egress-proxy/internal/i18n"

// 本文件集中存放 forward 面向用户的文案（Apply/ApplyTargets 的错误会经由
// tcp-forwarder 的日志与退出路径暴露给用户）。
// 中文是默认语言且必须与改造前的措辞逐字一致，英文为等价翻译；
// 模板里直接写 fmt 动词，中英文动词个数与顺序保持一致。
var (
	// 单个端口监听失败；多个端口失败时会拼进下面的汇总文案
	msgListenPortFailed = i18n.Msg{
		ZH: "监听 %s:%d 失败: %v",
		EN: "failed to listen on %s:%d: %v",
	}

	// 汇总：部分端口监听失败
	msgPartialListenFailed = i18n.Msg{
		ZH: "部分端口监听失败: %s",
		EN: "some listen ports failed: %s",
	}
)
