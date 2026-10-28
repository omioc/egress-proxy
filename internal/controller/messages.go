package controller

import (
	"errors"

	"egress-proxy/internal/i18n"
)

// 面向 API 客户端与 WebUI 的文案。日志保持中文（见 internal/i18n 的约定），
// 所以这里只收「会出现在响应体或界面上的句子」。
var (
	msgUnauthorized   = i18n.Msg{ZH: "缺少或错误的访问令牌", EN: "missing or invalid access token"}
	msgDecodeBody     = i18n.Msg{ZH: "请求体解析失败: %v", EN: "failed to decode the request body: %v"}
	msgPayloadWrap    = i18n.Msg{ZH: "负载 %q: %v", EN: "payload %q: %v"}
	msgGrantNeedsBoth = i18n.Msg{ZH: "payload 与 target 都不能为空", EN: "payload and target must not be empty"}
	msgNodeRequired   = i18n.Msg{ZH: "node 不能为空", EN: "node must not be empty"}

	msgPolicyEmpty     = i18n.Msg{ZH: "策略不能为空", EN: "policy must not be empty"}
	msgConflict        = i18n.Msg{ZH: "策略版本冲突，请刷新页面后重试", EN: "policy version conflict; refresh the page and try again"}
	msgConflictCurrent = i18n.Msg{ZH: "（当前 generation=%d）", EN: " (current generation=%d)"}
	msgInvalidMode     = i18n.Msg{ZH: "mode %q 无效，只能是 disabled / observe / enforce", EN: "invalid mode %q; must be one of disabled / observe / enforce"}
	msgNoGrantChange   = i18n.Msg{ZH: "没有可变更的授权（payload=%q target=%q allowed=%v）", EN: "no grant to change (payload=%q target=%q allowed=%v)"}
	msgSerializeFailed = i18n.Msg{ZH: "序列化策略失败: %v", EN: "failed to serialize the policy: %v"}
	msgPersistFailed   = i18n.Msg{ZH: "策略持久化失败（重启会丢失）: %v", EN: "failed to persist the policy (it will be lost on restart): %v"}

	// kube.go 里对上 apiserver 的失败
	msgReadNamespaceList = i18n.Msg{ZH: "读取命名空间失败: %v", EN: "failed to read namespaces: %v"}
	msgReadWorkloadList  = i18n.Msg{ZH: "读取工作负载失败: %v", EN: "failed to read workloads: %v"}
	msgAPICallFailed     = i18n.Msg{ZH: "%s %s 返回 %d: %s", EN: "%s %s returned %d: %s"}
	msgParsePodList      = i18n.Msg{ZH: "解析 Pod 列表失败: %v", EN: "failed to parse the Pod list: %v"}
	msgParseConfigMap    = i18n.Msg{ZH: "解析 ConfigMap 失败: %v", EN: "failed to parse the ConfigMap: %v"}
	msgWriteConfigMap    = i18n.Msg{ZH: "写入策略 ConfigMap 失败: %v", EN: "failed to write the policy ConfigMap: %v"}
	msgParseNamespace    = i18n.Msg{ZH: "解析命名空间列表失败: %v", EN: "failed to parse the namespace list: %v"}
	msgParseResourceList = i18n.Msg{ZH: "解析 %s 列表失败: %v", EN: "failed to parse the %s list: %v"}
	// 请求体为空与「未连 apiserver」都会直接回给客户端
	msgEmptyBody = i18n.Msg{ZH: "请求体为空", EN: "the request body is empty"}
	msgNoCluster = i18n.Msg{
		ZH: "控制器未连接 apiserver（未在集群内运行或缺少凭据），无法读取命名空间与工作负载，请手动填写",
		EN: "the controller is not connected to the apiserver (not running in a cluster, or credentials are missing), so namespaces and workloads cannot be read; fill them in manually",
	}
)

// localizedError 把「双语前缀 + 原始错误」存起来，语言留到渲染时再决定。
// 之所以不在出错处直接渲染，是因为同一个错误可能先被存进 Store（Pod 索引失败），
// 之后由不同语言的请求各自读取。
type localizedError struct {
	msg   i18n.Msg
	args  []any
	cause error
}

func (e *localizedError) Error() string { return e.S(i18n.ZH) }

// S 按语言渲染
func (e *localizedError) S(l i18n.Lang) string { return e.msg.S(l, e.args...) }

// Unwrap 保留原始错误，errors.Is / errors.As 照常可用
func (e *localizedError) Unwrap() error { return e.cause }

// locErr 用「前缀 + 原始错误」构造错误；模板里的 %v 由 cause 填充
func locErr(m i18n.Msg, cause error) error {
	return &localizedError{msg: m, args: []any{cause}, cause: cause}
}

// locErrArgs 用于模板里除原因外还有其它参数（原因始终是最后一个 %v）
func locErrArgs(m i18n.Msg, cause error, args ...any) error {
	return &localizedError{msg: m, args: append(append([]any{}, args...), cause), cause: cause}
}

// renderError 按语言渲染错误：实现了 S(i18n.Lang) 的错误会本地化，其余原样返回
func renderError(l i18n.Lang, err error) string {
	if err == nil {
		return ""
	}
	var l10n interface{ S(i18n.Lang) string }
	if errors.As(err, &l10n) {
		return l10n.S(l)
	}
	return err.Error()
}

// conflictError 表示乐观并发校验失败；携带当前 generation 便于客户端提示
type conflictError struct {
	current int64
}

func (e *conflictError) Error() string { return e.S(i18n.ZH) }

// S 按语言渲染
func (e *conflictError) S(l i18n.Lang) string {
	return msgConflict.S(l) + msgConflictCurrent.S(l, e.current)
}

// Unwrap 让 errors.Is(err, ErrConflict) 依旧成立
func (e *conflictError) Unwrap() error { return ErrConflict }

// persistIssue 是持久化失败的提示；语言在渲染时决定
type persistIssue struct {
	msg  i18n.Msg
	args []any
}

func (p *persistIssue) S(l i18n.Lang) string { return p.msg.S(l, p.args...) }
