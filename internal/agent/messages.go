package agent

import "egress-proxy/internal/i18n"

// 这些错误会被上报给控制器并显示在 WebUI 的状态页上，所以要双语。
var (
	msgConfigNotLoaded   = i18n.Msg{ZH: "配置尚未加载", EN: "the configuration is not loaded yet"}
	msgPolicyNotLoaded   = i18n.Msg{ZH: "策略尚未加载", EN: "the policy is not loaded yet"}
	msgWaitConfigTimeout = i18n.Msg{ZH: "等待配置文件 %s 就绪超时: %v", EN: "timed out waiting for the config file %s: %v"}
)
