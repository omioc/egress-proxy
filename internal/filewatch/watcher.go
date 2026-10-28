// Package filewatch 轮询监视文件内容变化
//
// Kuberbetes 的 ConfigMap 以卷（volume）方式挂载时，kubelet 会周期性把最新内容
// 原子地替换到挂载目录（通过 ..data 符号链接切换），因此这里读取路径并按内容
// SHA-256 去重，而不是依赖 mtime 或 inotify
package filewatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"os"
	"time"

	"egress-proxy/internal/i18n"
)

// DefaultInterval 是未指定轮询间隔时使用的默认值
const DefaultInterval = 2 * time.Second

// Watcher 周期性读取文件，内容变化时把最新内容推送给调用方
type Watcher struct {
	// Path 是文件路径
	Path string
	// Interval 是轮询间隔
	Interval time.Duration
	// Logger 用于输出读取失败等日志，可为 nil
	Logger *slog.Logger
}

// New 创建一个 Watcher
func New(path string, interval time.Duration, logger *slog.Logger) *Watcher {
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Watcher{Path: path, Interval: interval, Logger: logger}
}

// Watch 启动监视，返回的 channel 会在以下情况收到内容：
//   - 启动时立即推送一次当前内容（若可读）
//   - 之后每次内容哈希变化时推送
//
// ctx 结束时 channel 被关闭；文件暂时不可读（不存在、权限问题）只会记录日志并重试
func (w *Watcher) Watch(ctx context.Context) <-chan []byte {
	out := make(chan []byte)
	go func() {
		defer close(out)

		log := w.Logger
		if log == nil {
			log = slog.Default()
		}

		ticker := time.NewTicker(w.Interval)
		defer ticker.Stop()

		var lastHash string
		for {
			data, hash, err := readFile(w.Path)
			switch {
			case err != nil:
			case err != nil:
				log.Warn(i18n.Text("读取配置文件失败，稍后重试"), "path", w.Path, "err", err)
			case hash != lastHash:
				lastHash = hash
				select {
				case out <- data:
				case <-ctx.Done():
					return
				}
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return out
}

func readFile(path string) ([]byte, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}
