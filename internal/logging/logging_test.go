package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"egress-proxy/internal/i18n"
)

// TestHandlerTranslatesMessages 校验日志在英文进程语言下会被词典翻译，
// 中文进程语言下保持原文（这就是「日志也全球化」的机制）。
func TestHandlerTranslatesMessages(t *testing.T) {
	defer i18n.SetProcessLang(i18n.ZH)

	var buf bytes.Buffer
	handler := localizedHandler{slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})}
	logger := slog.New(handler)

	i18n.SetProcessLang(i18n.EN)
	logger.Warn("配置文件暂不可用，稍后重试", "path", "/etc/egress-proxy/config.yaml")
	out := buf.String()
	if !strings.Contains(out, "config file not available yet, will retry") {
		t.Errorf("英文进程语言下日志未翻译: %s", out)
	}
	if strings.Contains(out, "配置文件暂不可用") {
		t.Errorf("英文日志里残留中文: %s", out)
	}
	if !strings.Contains(out, "path=/etc/egress-proxy/config.yaml") {
		t.Errorf("日志字段被改动了: %s", out)
	}

	buf.Reset()
	i18n.SetProcessLang(i18n.ZH)
	logger.Warn("配置文件暂不可用，稍后重试")
	if !strings.Contains(buf.String(), "配置文件暂不可用，稍后重试") {
		t.Errorf("中文进程语言下日志应保持原文: %s", buf.String())
	}
}

func TestParseLevelErrorIsBilingual(t *testing.T) {
	_, err := ParseLevel("verbose")
	if err == nil {
		t.Fatal("非法级别应返回错误")
	}
	defer i18n.SetProcessLang(i18n.ZH)
	i18n.SetProcessLang(i18n.EN)
	if got := err.(interface{ S(i18n.Lang) string }).S(i18n.EN); strings.Contains(got, "\u672a") {
		t.Errorf("英文错误文案里残留中文: %q", got)
	}
	i18n.SetProcessLang(i18n.ZH)
	if !strings.Contains(err.Error(), "未知的日志级别") {
		t.Errorf("中文错误文案不对: %q", err.Error())
	}
}
