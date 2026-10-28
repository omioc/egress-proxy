// Package i18n 为 WebUI/API 面向用户的文案提供中英两套模板与语言协商。
//
// 约定：
//   - 中文是默认语言：命令行工具、curl、未声明 Accept-Language 的客户端都拿到中文，
//     与改造前行为一致，现有测试断言的也是中文；
//   - 语言只影响「返回给客户端/界面的文案」，日志保持中文不变（日志是运维视角）；
//   - 文案以 Msg 结构集中放在各包的 messages.go 里，模板直接写 fmt 动词。
package i18n

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

// Lang 是受支持的语言
type Lang string

const (
	// ZH 中文（默认）
	ZH Lang = "zh"
	// EN 英文
	EN Lang = "en"
)

type ctxKey struct{}

// WithLang 把语言放进请求上下文
func WithLang(ctx context.Context, l Lang) context.Context {
	return context.WithValue(ctx, ctxKey{}, Normalize(l))
}

// FromContext 取上下文里的语言；未设置或非法时回退中文
func FromContext(ctx context.Context) Lang {
	if ctx != nil {
		if l, ok := ctx.Value(ctxKey{}).(Lang); ok {
			return Normalize(l)
		}
	}
	return ZH
}

// Normalize 只接受 zh / en 两个精确值，其余一律回退中文
func Normalize(l Lang) Lang {
	if l == EN {
		return EN
	}
	return ZH
}

// FromHeader 解析 Accept-Language：按 q 值取最高优先级的标签，zh* 用中文，其余用英文；
// 头部为空或全是通配符时用中文。
func FromHeader(header string) Lang {
	type item struct {
		tag string
		q   float64
	}
	var items []item
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		tag := part
		q := 1.0
		if i := strings.Index(part, ";"); i >= 0 {
			tag = strings.TrimSpace(part[:i])
			for _, p := range strings.Split(part[i+1:], ";") {
				p = strings.TrimSpace(p)
				if v, ok := strings.CutPrefix(p, "q="); ok {
					if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
						q = f
					}
				}
			}
		}
		if tag == "" || tag == "*" {
			continue
		}
		items = append(items, item{tag: strings.ToLower(tag), q: q})
	}
	if len(items) == 0 {
		return ZH
	}
	best := items[0]
	for _, it := range items[1:] {
		if it.q > best.q {
			best = it
		}
	}
	if strings.HasPrefix(best.tag, "zh") {
		return ZH
	}
	return EN
}

// Msg 是一条双语文案，可直接带 fmt 动词
type Msg struct {
	ZH string
	EN string
}

// S 按语言渲染文案；缺英文翻译时回退中文，绝不会渲染成空串
func (m Msg) S(l Lang, args ...any) string {
	tpl := m.ZH
	if Normalize(l) == EN && m.EN != "" {
		tpl = m.EN
	}
	if len(args) == 0 {
		return tpl
	}
	return fmt.Sprintf(tpl, args...)
}

// E 按语言渲染成 error
func (m Msg) E(l Lang, args ...any) error {
	return errors.New(m.S(l, args...))
}

// ---------------------------------------------------------------------------
// 进程级语言：日志与命令行帮助（请求级语言见 FromHeader / WithLang）
// ---------------------------------------------------------------------------

// EnvLang 是进程语言的环境变量名
const EnvLang = "EGRESS_LANG"

var (
	processMu   sync.RWMutex
	processLang = ZH
)

// SetProcessLang 设置进程语言（来自 -lang 或 EGRESS_LANG）
func SetProcessLang(l Lang) {
	processMu.Lock()
	processLang = Normalize(l)
	processMu.Unlock()
}

// ProcessLang 返回进程语言
func ProcessLang() Lang {
	processMu.RLock()
	defer processMu.RUnlock()
	return processLang
}

// ParseLang 解析 zh / en（大小写不敏感与常见变体），无法识别时返回 def
func ParseLang(s string, def Lang) Lang {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "zh", "zh-cn", "zh-hans", "cn", "chinese":
		return ZH
	case "en", "en-us", "en-gb", "english":
		return EN
	}
	return Normalize(def)
}

// LangFromEnv 读取 EGRESS_LANG，未设置或无法识别时返回 def
func LangFromEnv(def Lang) Lang {
	v, ok := os.LookupEnv(EnvLang)
	if !ok || strings.TrimSpace(v) == "" {
		return Normalize(def)
	}
	return ParseLang(v, def)
}

// Text 按进程语言翻译一条中文文案（日志、命令行帮助、配置解析错误）；
// 未收录时原样返回中文，绝不会返回空串。
func Text(zh string) string {
	if ProcessLang() != EN {
		return zh
	}
	if en, ok := logText[zh]; ok && en != "" {
		return en
	}
	return zh
}

// Coded 是带双语模板的错误：Error() 给中文，S(lang) 给指定语言。
// 节点把它上报给控制器时用 Bilingual 同时带上两种文本，界面按请求语言取用。
type Coded struct {
	msg  Msg
	args []any
}

// NewCoded 构造双语错误
func NewCoded(m Msg, args ...any) *Coded { return &Coded{msg: m, args: args} }

func (c *Coded) Error() string { return c.msg.S(ZH, c.args...) }

// S 按语言渲染
func (c *Coded) S(l Lang) string { return c.msg.S(l, c.args...) }

// Msg 返回原始双语模板（测试与调试用）
func (c *Coded) Raw() Msg { return c.msg }

// Bilingual 取错误的中英文本：实现了 S(Lang) 的错误会给出英文，其余英文为空串。
// 注意不要用 fmt.Errorf 包一层中文前缀再调用它——那会让前缀留在两种语言里；
// 需要前缀时请把整句写进 Msg 模板。
func Bilingual(err error) (zh string, en string) {
	if err == nil {
		return "", ""
	}
	var withLang interface{ S(Lang) string }
	if errors.As(err, &withLang) {
		return err.Error(), withLang.S(EN)
	}
	return err.Error(), ""
}

// SetProcessLangFromArgs 在定义命令行参数之前就确定语言：
// 先看 -lang / --lang（帮助文案在定义 flag 时就求值，所以必须提前知道），
// 再看 EGRESS_LANG，最后回退中文。
func SetProcessLangFromArgs(args []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		for _, p := range []string{"-lang=", "--lang="} {
			if strings.HasPrefix(a, p) {
				SetProcessLang(ParseLang(strings.TrimPrefix(a, p), LangFromEnv(ZH)))
				return
			}
		}
		if a == "-lang" || a == "--lang" {
			if i+1 < len(args) {
				SetProcessLang(ParseLang(args[i+1], LangFromEnv(ZH)))
				return
			}
		}
	}
	SetProcessLang(LangFromEnv(ZH))
}
