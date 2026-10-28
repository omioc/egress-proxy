package filewatch

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain 让测试期间的日志静默（文件缺失时 Watcher 会重试并打印告警）
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

const testInterval = 10 * time.Millisecond

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
}

func recv(t *testing.T, ch <-chan []byte) []byte {
	t.Helper()
	select {
	case data, ok := <-ch:
		if !ok {
			t.Fatal("channel 已关闭，未收到内容")
		}
		return data
	case <-time.After(3 * time.Second):
		t.Fatal("等待内容超时")
		return nil
	}
}

func TestWatchInitialAndChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	write(t, path, "first")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := New(path, testInterval, nil).Watch(ctx)

	if got := string(recv(t, ch)); got != "first" {
		t.Fatalf("初始内容 = %q, 期望 first", got)
	}

	// 内容未变化时不应重复推送
	select {
	case got := <-ch:
		t.Fatalf("内容未变化却收到推送: %q", got)
	case <-time.After(200 * time.Millisecond):
	}

	write(t, path, "second")
	if got := string(recv(t, ch)); got != "second" {
		t.Fatalf("更新后内容 = %q, 期望 second", got)
	}

	// 再次写入相同内容：不应推送
	write(t, path, "second")
	select {
	case got := <-ch:
		t.Fatalf("内容相同时不应推送: %q", got)
	case <-time.After(200 * time.Millisecond):
	}

	write(t, path, "third")
	if got := string(recv(t, ch)); got != "third" {
		t.Fatalf("第三次内容 = %q, 期望 third", got)
	}

	cancel()
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // channel 已关闭，符合预期
			}
		case <-deadline:
			t.Fatal("ctx 取消后 channel 未关闭")
		}
	}
}

func TestWatchSymlinkSwap(t *testing.T) {
	// 模拟 kubelet 的 ConfigMap 挂载：写入 ..data 目录并切换同名符号链接
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v1", "config.yaml"), []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "v1"), filepath.Join(dir, "..data")); err != nil {
		t.Skipf("当前平台不支持符号链接，跳过: %v", err)
	}
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(filepath.Join(dir, "..data", "config.yaml"), link); err != nil {
		t.Skipf("创建符号链接失败，跳过: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := New(link, testInterval, nil).Watch(ctx)

	if got := string(recv(t, ch)); got != "v1" {
		t.Fatalf("初始内容 = %q, 期望 v1", got)
	}

	// 切换 ..data 到 v2
	if err := os.Mkdir(filepath.Join(dir, "v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v2", "config.yaml"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	tmpLink := filepath.Join(dir, "..data_tmp")
	if err := os.Symlink(filepath.Join(dir, "v2"), tmpLink); err != nil {
		t.Fatal(err)
	}
	// kubelet 的做法是原子替换 ..data 符号链接；Windows 不允许 rename 覆盖已存在的
	// 符号链接，因此这里在必要时退化为「删除后重建」（Linux 上仍是单次 rename）
	if err := os.Rename(tmpLink, filepath.Join(dir, "..data")); err != nil {
		if removeErr := os.Remove(filepath.Join(dir, "..data")); removeErr != nil {
			t.Fatalf("替换 ..data 失败: rename=%v, remove=%v", err, removeErr)
		}
		if renameErr := os.Rename(tmpLink, filepath.Join(dir, "..data")); renameErr != nil {
			t.Fatalf("替换 ..data 失败: %v", renameErr)
		}
	}

	if got := string(recv(t, ch)); got != "v2" {
		t.Fatalf("符号链接切换后内容 = %q, 期望 v2", got)
	}
}

func TestWatchMissingFileThenCreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := New(path, testInterval, nil).Watch(ctx)

	select {
	case got := <-ch:
		t.Fatalf("文件不存在时不应有推送: %q", got)
	case <-time.After(200 * time.Millisecond):
	}

	write(t, path, "hello")
	if got := string(recv(t, ch)); got != "hello" {
		t.Fatalf("文件创建后内容 = %q, 期望 hello", got)
	}
}
