// Package logging 提供三个可执行文件共用的日志构造逻辑
package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"egress-proxy/internal/i18n"
)

// Version 是构建版本号，由构建时的 ldflags 注入：
//
//	go build -ldflags "-X egress-proxy/internal/logging.Version=0.2.0" ./cmd/controller
//
// 启动日志会打印它，用于确认节点上运行的到底是不是最新镜像
// （排查「明明重新构建了镜像却还是老行为」这类问题）
var Version = "dev"

// VersionString 返回版本号
func VersionString() string { return Version }

// msgUnknownLevel 是未知日志级别的错误文案（按进程语言渲染）
var msgUnknownLevel = i18n.Msg{
	ZH: "未知的日志级别 %q（可选 debug|info|warn|error）",
	EN: "unknown log level %q (expected debug|info|warn|error)",
}

// ParseLevel 把 debug|info|warn|error 解析为 slog 级别
func ParseLevel(level string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, i18n.NewCoded(msgUnknownLevel, level)
	}
}

// localizedHandler 在写出前把日志文案换成进程语言。
// 这样几十处 logger.* 调用点不必逐个包 i18n.Text()：词典（i18n/logs.go）里有的就翻，
// 没有的保留中文，绝不会出现空文案。
type localizedHandler struct{ slog.Handler }

func (h localizedHandler) Handle(ctx context.Context, r slog.Record) error {
	if i18n.ProcessLang() == i18n.EN {
		localized := slog.NewRecord(r.Time, r.Level, i18n.Text(r.Message), r.PC)
		r.Attrs(func(a slog.Attr) bool {
			localized.AddAttrs(a)
			return true
		})
		r = localized
	}
	return h.Handler.Handle(ctx, r)
}

func (h localizedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return localizedHandler{h.Handler.WithAttrs(attrs)}
}

func (h localizedHandler) WithGroup(name string) slog.Handler {
	return localizedHandler{h.Handler.WithGroup(name)}
}

// New 创建写入标准错误的结构化日志器
func New(level string) (*slog.Logger, error) {
	lvl, err := ParseLevel(level)
	if err != nil {
		return nil, err
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(localizedHandler{handler}), nil
}
