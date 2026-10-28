package i18n

import (
	"context"
	"testing"
)

func TestFromHeader(t *testing.T) {
	cases := []struct {
		header string
		want   Lang
	}{
		{"", ZH},
		{"zh-CN", ZH},
		{"zh-CN,zh;q=0.9,en;q=0.8", ZH},
		{"en-US,en;q=0.9", EN},
		{"en", EN},
		// q 值更高的排在后面也要选它
		{"en;q=0.4,zh-CN;q=0.9", ZH},
		{"zh;q=0.3,en-US;q=0.8", EN},
		// 通配符与非法项被忽略，剩下第一个有效标签
		{"*", ZH},
		{"*,en;q=0.5", EN},
		{"fr-FR,zh;q=0.6", EN},
	}
	for _, c := range cases {
		if got := FromHeader(c.header); got != c.want {
			t.Errorf("FromHeader(%q) = %q, 期望 %q", c.header, got, c.want)
		}
	}
}

func TestNormalize(t *testing.T) {
	if Normalize("") != ZH {
		t.Error("空语言应回退中文")
	}
	if Normalize("zh") != ZH || Normalize("en") != EN || Normalize("EN") != ZH {
		t.Error("只接受 zh / en 两个精确值，其余回退中文")
	}
}

func TestContextRoundTrip(t *testing.T) {
	if FromContext(context.Background()) != ZH {
		t.Error("未设置语言时应回退中文")
	}
	ctx := WithLang(context.Background(), EN)
	if FromContext(ctx) != EN {
		t.Error("上下文里应是英文")
	}
	if FromContext(WithLang(context.Background(), "fr")) != ZH {
		t.Error("非法语言应回退中文")
	}
}

func TestMsgRender(t *testing.T) {
	m := Msg{ZH: "策略不能为空", EN: "policy must not be empty"}
	if got := m.S(ZH); got != "策略不能为空" {
		t.Errorf("中文渲染 = %q", got)
	}
	if got := m.S(EN); got != "policy must not be empty" {
		t.Errorf("英文渲染 = %q", got)
	}
	p := Msg{ZH: "mode %q 无效", EN: "invalid mode %q"}
	if got := p.S(EN, "foo"); got != `invalid mode "foo"` {
		t.Errorf("带参数渲染 = %q", got)
	}
	// 缺英文翻译时回退中文，不能出现空串
	empty := Msg{ZH: "只有中文"}
	if got := empty.S(EN); got != "只有中文" {
		t.Errorf("缺翻译应回退中文，得到 %q", got)
	}
	if err := m.E(EN); err == nil || err.Error() != "policy must not be empty" {
		t.Errorf("E(EN) = %v", err)
	}
}
