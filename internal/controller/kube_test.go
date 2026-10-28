package controller

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAPIServer 模拟集群 apiserver：自签证书 + 校验 ServiceAccount token
func fakeAPIServer(t *testing.T, wantToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+wantToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/api/v1/pods":
			_, _ = w.Write([]byte(`{"items":[
				{"metadata":{"name":"p1","namespace":"ns1","labels":{"app":"x"}},
				 "spec":{"nodeName":"node-a"},
				 "status":{"phase":"Running","podIP":"10.244.1.1"}},
				{"metadata":{"name":"done","namespace":"ns1","labels":{}},
				 "spec":{"nodeName":"node-a"},
				 "status":{"phase":"Succeeded","podIP":""}}
			]}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/namespaces/egress-proxy/configmaps"):
			switch r.Method {
			case http.MethodGet:
				_, _ = w.Write([]byte(`{"data":{"policy.json":"{\"generation\":3}"}}`))
			case http.MethodPatch, http.MethodPost:
				_, _ = w.Write([]byte(`{}`))
			default:
				http.NotFound(w, r)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// writeCreds 把 token 与服务端证书写成 in-cluster 凭据目录里的两个文件
func writeCreds(t *testing.T, srv *httptest.Server) (tokenPath, caPath string) {
	t.Helper()
	dir := t.TempDir()
	tokenPath = filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token\n"), 0o600); err != nil {
		t.Fatalf("写 token 失败: %v", err)
	}
	caPath = filepath.Join(dir, "ca.crt")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caPath, pemBytes, 0o600); err != nil {
		t.Fatalf("写 ca.crt 失败: %v", err)
	}
	return tokenPath, caPath
}

// TestInClusterUsesClusterCA 是本 bug 的回归测试：
// 必须显式加载 ca.crt，否则会报 x509: certificate signed by unknown authority
func TestInClusterUsesClusterCA(t *testing.T) {
	srv := fakeAPIServer(t, "sa-token")
	tokenPath, caPath := writeCreds(t, srv)

	client, err := newInCluster(InClusterOptions{
		BaseURL:       srv.URL,
		TokenPath:     tokenPath,
		CAPath:        caPath,
		Namespace:     "egress-proxy",
		ConfigMapName: "egress-proxy-policy",
	})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}

	pods, err := client.ListPods(context.Background())
	if err != nil {
		t.Fatalf("列取 Pod 失败（多半是没有加载集群 CA）: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("应过滤掉 Succeeded 的 Pod，实际 %+v", pods)
	}
	if pods[0].Namespace != "ns1" || pods[0].NodeName != "node-a" || pods[0].IP != "10.244.1.1" {
		t.Fatalf("Pod 解析结果不对: %+v", pods[0])
	}

	raw, err := client.LoadPolicy(context.Background())
	if err != nil {
		t.Fatalf("读取策略失败: %v", err)
	}
	if string(raw) != `{"generation":3}` {
		t.Fatalf("策略内容不对: %s", raw)
	}

	if err := client.SavePolicy(context.Background(), []byte(`{"generation":4}`)); err != nil {
		t.Fatalf("保存策略失败: %v", err)
	}
	if desc := client.Describe(); desc != "configmap" {
		t.Fatalf("Describe = %q", desc)
	}
}

func TestInClusterWithoutCAFails(t *testing.T) {
	srv := fakeAPIServer(t, "sa-token")
	tokenPath, _ := writeCreds(t, srv)

	// 用系统信任库（等价于忘记加载 ca.crt）应该失败——证明这个测试真的能抓到问题
	client := &InCluster{
		baseURL:       srv.URL,
		token:         "sa-token",
		namespace:     "egress-proxy",
		configMapName: "egress-proxy-policy",
		client:        &http.Client{},
	}
	if _, err := client.ListPods(context.Background()); err == nil {
		t.Fatal("不信任集群 CA 时应失败")
	}
	_ = tokenPath
}

func TestNewInClusterRejectsInvalidCA(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("CA 文件不存在", func(t *testing.T) {
		_, err := newInCluster(InClusterOptions{
			BaseURL: "https://127.0.0.1:1", TokenPath: tokenPath,
			CAPath: filepath.Join(dir, "missing.crt"),
		})
		if err == nil {
			t.Fatal("CA 缺失时应报错")
		}
		if !strings.Contains(err.Error(), "集群 CA") {
			t.Fatalf("错误信息应指明是 CA 问题: %v", err)
		}
	})

	t.Run("CA 内容非法", func(t *testing.T) {
		caPath := filepath.Join(dir, "bad.crt")
		if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := newInCluster(InClusterOptions{
			BaseURL: "https://127.0.0.1:1", TokenPath: tokenPath, CAPath: caPath,
		}); err == nil {
			t.Fatal("非法 CA 内容应报错")
		}
	})

	t.Run("token 不存在", func(t *testing.T) {
		caPath := filepath.Join(dir, "ca.crt")
		if err := os.WriteFile(caPath, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := newInCluster(InClusterOptions{
			BaseURL: "https://127.0.0.1:1", TokenPath: filepath.Join(dir, "missing-token"), CAPath: caPath,
		}); err == nil {
			t.Fatal("token 缺失时应报错")
		}
	})
}

// TestSavePolicyOnlyCreatesOn404 保证 403 之类的错误不会被误当成「ConfigMap 不存在」
func TestSavePolicyOnlyCreatesOn404(t *testing.T) {
	var created bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			http.Error(w, "forbidden", http.StatusForbidden)
		case http.MethodPost:
			created = true
			_, _ = w.Write([]byte(`{}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	tokenPath, caPath := writeCreds(t, srv)
	client, err := newInCluster(InClusterOptions{
		BaseURL: srv.URL, TokenPath: tokenPath, CAPath: caPath,
		Namespace: "egress-proxy", ConfigMapName: "egress-proxy-policy",
	})
	if err != nil {
		t.Fatalf("构造客户端失败: %v", err)
	}

	if err := client.SavePolicy(context.Background(), []byte(`{}`)); err == nil {
		t.Fatal("403 应报错")
	}
	if created {
		t.Fatal("只有 404 才应该退化为创建 ConfigMap")
	}
}
