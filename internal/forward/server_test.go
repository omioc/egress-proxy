package forward

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"egress-proxy/config"
)

// TestMain 让测试期间的日志静默（转发过程中的 INFO/WARN 日志对测试无意义）
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// startBackend 启动一个测试用「外部服务」：连接建立后先回送 banner，然后回显收到的数据
func startBackend(t *testing.T, banner string) (host string, port int, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动测试后端失败: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner + "\n"))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, func() { _ = ln.Close() }
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func cfgYAML(host string, port, proxyPort int) string {
	return fmt.Sprintf(`proxy:
  address: 127.0.0.1
  listen: 127.0.0.1
targets:
  - host: %s
    port: %d
    proxyPort: %d
`, host, port, proxyPort)
}

func mustConfig(t *testing.T, yml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yml))
	if err != nil {
		t.Fatalf("解析测试配置失败: %v", err)
	}
	return cfg
}

// readBanner 通过代理读取 banner
func readBanner(t *testing.T, proxyPort int) (net.Conn, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("连接代理端口 %d 失败: %v", proxyPort, err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("读取 banner 失败: %v", err)
	}
	return conn, strings.TrimSpace(string(buf[:n]))
}

func TestApplyAndRelay(t *testing.T) {
	_, backendPort, stop := startBackend(t, "backend-A")
	defer stop()

	proxyPort := freePort(t)
	srv := New(2*time.Second, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	if err := srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", backendPort, proxyPort))); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}

	conn, banner := readBanner(t, proxyPort)
	defer conn.Close()
	if banner != "backend-A" {
		t.Fatalf("banner = %q，期望 backend-A", banner)
	}

	// 双向转发：写入的数据应被后端回显
	if _, err := conn.Write([]byte("ping\n")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	echo := make([]byte, 64)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(echo)
	if err != nil {
		t.Fatalf("读取回显失败: %v", err)
	}
	if got := strings.TrimSpace(string(echo[:n])); got != "ping" {
		t.Fatalf("回显内容 = %q，期望 ping", got)
	}

	stats := srv.Stats()
	if len(stats.Listeners) != 1 || stats.Listeners[0] != proxyPort {
		t.Errorf("Stats.Listeners = %v，期望 [%d]", stats.Listeners, proxyPort)
	}
	if stats.TotalConns < 1 {
		t.Errorf("TotalConns = %d，期望 >= 1", stats.TotalConns)
	}
	if stats.ConfigHash == "" {
		t.Error("ConfigHash 不应为空")
	}
	if stats.Targets[strconv.Itoa(proxyPort)] != net.JoinHostPort("127.0.0.1", strconv.Itoa(backendPort)) {
		t.Errorf("Stats.Targets = %v", stats.Targets)
	}
}

func TestDomainTargetResolvedByProxy(t *testing.T) {
	_, backendPort, stop := startBackend(t, "backend-domain")
	defer stop()

	proxyPort := freePort(t)
	srv := New(2*time.Second, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// 用 localhost 验证「域名型目标由代理节点自己解析」
	if err := srv.Apply(mustConfig(t, cfgYAML("localhost", backendPort, proxyPort))); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}

	conn, banner := readBanner(t, proxyPort)
	defer conn.Close()
	if banner != "backend-domain" {
		t.Fatalf("banner = %q，期望 backend-domain", banner)
	}
}

func TestReloadSwitchesTargetForNewConnections(t *testing.T) {
	_, portA, stopA := startBackend(t, "backend-A")
	defer stopA()
	_, portB, stopB := startBackend(t, "backend-B")
	defer stopB()

	proxyPort := freePort(t)
	srv := New(2*time.Second, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	if err := srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", portA, proxyPort))); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	oldConn, banner := readBanner(t, proxyPort)
	defer oldConn.Close()
	if banner != "backend-A" {
		t.Fatalf("banner = %q，期望 backend-A", banner)
	}

	// 切换同一 proxyPort 的转发目标
	if err := srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", portB, proxyPort))); err != nil {
		t.Fatalf("第二次 Apply 失败: %v", err)
	}

	newConn, banner := readBanner(t, proxyPort)
	defer newConn.Close()
	if banner != "backend-B" {
		t.Fatalf("重载后新连接 banner = %q，期望 backend-B", banner)
	}

	// 存量连接应继续可用（不受配置变更影响）
	if _, err := oldConn.Write([]byte("still-alive\n")); err != nil {
		t.Fatalf("存量连接写入失败: %v", err)
	}
	if err := oldConn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := oldConn.Read(buf)
	if err != nil {
		t.Fatalf("存量连接读取失败: %v", err)
	}
	if got := strings.TrimSpace(string(buf[:n])); got != "still-alive" {
		t.Fatalf("存量连接回显 = %q，期望 still-alive", got)
	}
}

func TestRemovedPortStopsListening(t *testing.T) {
	_, keepBackend, stopKeep := startBackend(t, "backend-keep")
	defer stopKeep()
	_, dropBackend, stopDrop := startBackend(t, "backend-drop")
	defer stopDrop()

	keepPort := freePort(t)
	dropPort := freePort(t)

	srv := New(2*time.Second, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// 两个不同的 host+port 组合，各分配一个代理端口
	two := fmt.Sprintf(`proxy:
  address: 127.0.0.1
  listen: 127.0.0.1
targets:
  - host: 127.0.0.1
    port: %d
    proxyPort: %d
  - host: 127.0.0.1
    port: %d
    proxyPort: %d
`, keepBackend, keepPort, dropBackend, dropPort)

	if err := srv.Apply(mustConfig(t, two)); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}
	conn, _ := readBanner(t, dropPort)
	_ = conn.Close()

	// 移除其中一个目标
	if err := srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", keepBackend, keepPort))); err != nil {
		t.Fatalf("第二次 Apply 失败: %v", err)
	}

	stats := srv.Stats()
	if len(stats.Listeners) != 1 || stats.Listeners[0] != keepPort {
		t.Fatalf("Stats.Listeners = %v，期望 [%d]", stats.Listeners, keepPort)
	}

	if conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(dropPort)), 500*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Errorf("端口 %d 已从配置中移除，不应再接受连接", dropPort)
	}
}

func TestApplyReportsListenFailure(t *testing.T) {
	// 占用一个端口，模拟端口冲突
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	busyPort := blocker.Addr().(*net.TCPAddr).Port

	srv := New(time.Second, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	err = srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", 9, busyPort)))
	if err == nil {
		t.Fatalf("端口被占用时 Apply 应返回错误")
	}
	if !strings.Contains(err.Error(), strconv.Itoa(busyPort)) {
		t.Errorf("错误信息应包含端口号 %d，实际 %v", busyPort, err)
	}
}

func TestShutdownGracefulAndTimeout(t *testing.T) {
	_, backendPort, stop := startBackend(t, "backend-A")
	defer stop()
	proxyPort := freePort(t)

	srv := New(2*time.Second, nil)
	if err := srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", backendPort, proxyPort))); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}

	conn, _ := readBanner(t, proxyPort)

	// 有活跃连接时，Shutdown 应等待到 ctx 超时
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := srv.Shutdown(ctxTimeout); err == nil {
		t.Error("存在活跃连接时 Shutdown 应因超时返回错误")
	}

	// 关闭连接后再次 Shutdown 应迅速返回
	_ = conn.Close()
	ctxOK, cancelOK := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelOK()
	if err := srv.Shutdown(ctxOK); err != nil {
		t.Errorf("存量连接结束后 Shutdown 应成功，实际 %v", err)
	}

	// 关闭后端口不再监听
	if c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), 500*time.Millisecond); err == nil {
		_ = c.Close()
		t.Error("Shutdown 后不应再接受连接")
	}
}

func TestHealthHandler(t *testing.T) {
	_, backendPort, stop := startBackend(t, "backend-A")
	defer stop()
	proxyPort := freePort(t)

	srv := New(time.Second, nil)
	defer func() { _ = srv.Shutdown(context.Background()) }()

	// 尚未 Apply：readyz 应返回 503
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/readyz 无监听端口时应为 503，实际 %d", rec.Code)
	}

	if err := srv.Apply(mustConfig(t, cfgYAML("127.0.0.1", backendPort, proxyPort))); err != nil {
		t.Fatalf("Apply 失败: %v", err)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz 状态码 = %d，期望 200", rec.Code)
	}
	var stats Stats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("解析 /healthz 响应失败: %v（body=%s）", err, rec.Body.String())
	}
	if stats.Status != "ok" || len(stats.Listeners) != 1 || stats.Listeners[0] != proxyPort {
		t.Errorf("/healthz 响应不符合预期: %+v", stats)
	}

	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/readyz 有监听端口时应为 200，实际 %d", rec.Code)
	}
}
