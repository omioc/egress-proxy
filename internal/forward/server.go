// Package forward 实现代理节点上的 TCP 转发服务
//
// 它按配置中的 proxyPort 建立监听端口，把接到的连接转发到该端口对应的原始目标
// （域名型目标由本服务自己解析，IP 型目标直接拨号），仅做 TCP 层双向透传，不解析
// 应用层协议；配置变化时动态增删监听端口、更新转发目标，存量连接不受影响
package forward

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"egress-proxy/config"
	"egress-proxy/internal/i18n"
)

// bufferSize 是双向转发使用的缓冲区大小
const bufferSize = 32 * 1024

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, bufferSize)
		return &b
	},
}

// Server 管理监听端口并按端口转发连接
type Server struct {
	log *slog.Logger

	dialTimeoutNanos atomic.Int64
	activeConns      atomic.Int64
	totalConns       atomic.Int64
	relayFailures    atomic.Int64
	configHash       atomic.Value // string
	startedAt        time.Time

	mu        sync.Mutex
	listen    string
	listeners map[int]*listener
}

// listener 是某个 proxyPort 上的监听器
type listener struct {
	port   int
	ln     net.Listener
	target atomic.Value // string，形如 host:port
	closed atomic.Bool
	wg     sync.WaitGroup
	server *Server
}

// New 创建转发服务
func New(dialTimeout time.Duration, logger *slog.Logger) *Server {
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		log:       logger,
		listeners: make(map[int]*listener),
		startedAt: time.Now(),
	}
	s.dialTimeoutNanos.Store(int64(dialTimeout))
	s.configHash.Store("")
	return s
}

// Stats 是健康检查暴露的运行状态
type Stats struct {
	Status        string            `json:"status"`
	ConfigHash    string            `json:"configHash"`
	Listeners     []int             `json:"listeners"`
	Targets       map[string]string `json:"targets"`
	ActiveConns   int64             `json:"activeConnections"`
	TotalConns    int64             `json:"totalConnections"`
	RelayFailures int64             `json:"relayFailures"`
	UptimeSeconds int64             `json:"uptimeSeconds"`
}

// Apply 使监听端口与转发目标与 cfg 一致
// 新增端口立即开始监听；移除端口关闭监听（存量连接自然排空）；同一端口的转发目标
// 变化只影响后续新建的连接
func (s *Server) Apply(cfg *config.Config) error {
	listen := cfg.Proxy.Listen
	if listen == "" {
		listen = config.DefaultListen
	}
	dialTimeout := cfg.Options.DialTimeout.D()
	if dialTimeout <= 0 {
		dialTimeout = config.DefaultDialTimeout
	}
	s.dialTimeoutNanos.Store(int64(dialTimeout))
	s.configHash.Store(cfg.Hash)

	desired := make(map[int]string, len(cfg.Targets))
	for _, t := range cfg.Targets {
		desired[t.ProxyPort] = t.Addr()
	}
	return s.applyListeners(listen, desired)
}

// SetDialTimeout 更新拨号超时（对后续新建连接生效）
func (s *Server) SetDialTimeout(d time.Duration) {
	if d <= 0 {
		d = config.DefaultDialTimeout
	}
	s.dialTimeoutNanos.Store(int64(d))
}

// ApplyTargets 直接按「proxyPort → 原始目标」的映射维护监听端口
// 启用四元组策略时，目标列表来自控制器而不是配置文件
func (s *Server) ApplyTargets(listen string, desired map[int]string) error {
	if listen == "" {
		listen = config.DefaultListen
	}
	return s.applyListeners(listen, desired)
}

// applyListeners 让监听端口集合与 desired 一致
func (s *Server) applyListeners(listen string, desired map[int]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 监听地址变化：重建全部监听器
	if s.listen != "" && s.listen != listen {
		s.log.Info(i18n.Text("监听地址变化，重建全部监听端口"), "previous", s.listen, "current", listen)
		for port, l := range s.listeners {
			l.close()
			delete(s.listeners, port)
		}
	}
	s.listen = listen

	// 关闭配置中已删除的端口
	for port, l := range s.listeners {
		if _, ok := desired[port]; !ok {
			l.close()
			delete(s.listeners, port)
			s.log.Info(i18n.Text("已停止监听（目标已从配置中移除）"), "proxyPort", port)
		}
	}

	var errs []i18n.Msg
	ports := make([]int, 0, len(desired))
	for port := range desired {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	for _, port := range ports {
		target := desired[port]
		if l, ok := s.listeners[port]; ok {
			if prev, _ := l.target.Load().(string); prev != target {
				l.target.Store(target)
				s.log.Info(i18n.Text("已更新转发目标"), "proxyPort", port, "previous", prev, "current", target)
			}
			continue
		}
		ln, err := net.Listen("tcp4", net.JoinHostPort(listen, strconv.Itoa(port)))
		if err != nil {
			errs = append(errs, i18n.Msg{
				ZH: msgListenPortFailed.S(i18n.ZH, listen, port, err),
				EN: msgListenPortFailed.S(i18n.EN, listen, port, err),
			})
			continue
		}
		l := &listener{port: port, ln: ln, server: s}
		l.target.Store(target)
		s.listeners[port] = l
		go l.serve()
		s.log.Info(i18n.Text("开始监听端口并转发"), "proxyPort", port, "target", target)
	}

	if len(errs) > 0 {
		zhParts := make([]string, 0, len(errs))
		enParts := make([]string, 0, len(errs))
		for _, e := range errs {
			zhParts = append(zhParts, e.ZH)
			enParts = append(enParts, e.EN)
		}
		return i18n.NewCoded(i18n.Msg{
			ZH: msgPartialListenFailed.S(i18n.ZH, strings.Join(zhParts, "; ")),
			EN: msgPartialListenFailed.S(i18n.EN, strings.Join(enParts, "; ")),
		})
	}
	return nil
}

// Shutdown 停止接受新连接，并等待存量连接结束或 ctx 超时
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	listeners := make([]*listener, 0, len(s.listeners))
	for port, l := range s.listeners {
		listeners = append(listeners, l)
		delete(s.listeners, port)
	}
	s.mu.Unlock()

	for _, l := range listeners {
		l.close()
	}

	done := make(chan struct{})
	go func() {
		for _, l := range listeners {
			l.wg.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.log.Warn(i18n.Text("等待存量连接排空超时，立即退出"), "activeConnections", s.activeConns.Load())
		return ctx.Err()
	}
}

// Stats 返回当前运行状态
func (s *Server) Stats() Stats {
	s.mu.Lock()
	ports := make([]int, 0, len(s.listeners))
	targets := make(map[string]string, len(s.listeners))
	for port, l := range s.listeners {
		ports = append(ports, port)
		target, _ := l.target.Load().(string)
		targets[strconv.Itoa(port)] = target
	}
	s.mu.Unlock()
	sort.Ints(ports)

	hash, _ := s.configHash.Load().(string)
	status := "ok"
	if len(ports) == 0 {
		status = "no-listeners"
	}
	return Stats{
		Status:        status,
		ConfigHash:    hash,
		Listeners:     ports,
		Targets:       targets,
		ActiveConns:   s.activeConns.Load(),
		TotalConns:    s.totalConns.Load(),
		RelayFailures: s.relayFailures.Load(),
		UptimeSeconds: int64(time.Since(s.startedAt).Seconds()),
	}
}

// Handler 返回 /healthz 与 /readyz 的 HTTP 处理器
func (s *Server) Handler() http.Handler {
	writeJSON := func(w http.ResponseWriter, status int, payload Stats) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(payload); err != nil {
			s.log.Warn(i18n.Text("写入健康检查响应失败"), "err", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.Stats())
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		stats := s.Stats()
		if len(stats.Listeners) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, stats)
			return
		}
		writeJSON(w, http.StatusOK, stats)
	})
	return mux
}

func (l *listener) serve() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			l.server.log.Warn(i18n.Text("接受连接失败，稍后重试"), "proxyPort", l.port, "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		l.wg.Add(1)
		go func() {
			defer l.wg.Done()
			l.handle(conn)
		}()
	}
}

// close 停止接受新连接；已在处理的连接继续转发直至结束
func (l *listener) close() {
	if l.closed.CompareAndSwap(false, true) {
		if err := l.ln.Close(); err != nil {
			l.server.log.Debug(i18n.Text("关闭监听器返回错误"), "proxyPort", l.port, "err", err)
		}
	}
}

func (l *listener) handle(client net.Conn) {
	s := l.server
	s.activeConns.Add(1)
	s.totalConns.Add(1)
	defer s.activeConns.Add(-1)
	defer client.Close()

	target, _ := l.target.Load().(string)
	if target == "" {
		s.log.Warn(i18n.Text("该端口没有配置转发目标，断开连接"), "proxyPort", l.port)
		return
	}

	dialer := net.Dialer{Timeout: time.Duration(s.dialTimeoutNanos.Load())}
	upstream, err := dialer.Dial("tcp4", target)
	if err != nil {
		s.relayFailures.Add(1)
		s.log.Warn(i18n.Text("连接原始目标失败"),
			"proxyPort", l.port, "target", target, "client", remoteAddr(client), "err", err)
		return
	}
	defer upstream.Close()

	s.log.Debug(i18n.Text("开始转发"), "proxyPort", l.port, "target", target, "client", remoteAddr(client))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		relay(upstream, client)
	}()
	go func() {
		defer wg.Done()
		relay(client, upstream)
	}()
	wg.Wait()

	s.log.Debug(i18n.Text("转发结束"), "proxyPort", l.port, "target", target, "client", remoteAddr(client))
}

// relay 把 src 的数据拷贝到 dst，并在拷贝结束后半关闭 dst 的写方向，
// 保证对端能收到 EOF（例如 TLS/HTTP 的正常收尾）
func relay(dst, src net.Conn) {
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)

	if _, err := io.CopyBuffer(dst, src, *buf); err != nil {
		// 对端复位或关闭时也会返回错误，属于常见情况，这里不打扰调用方
		_ = err
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func remoteAddr(c net.Conn) string {
	if c == nil || c.RemoteAddr() == nil {
		return ""
	}
	return c.RemoteAddr().String()
}
