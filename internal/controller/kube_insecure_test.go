package controller

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestInClusterInsecureSkipVerify 覆盖默认行为：跳过 apiserver 证书校验
// 此时不应该去读 ca.crt，也不应该因为证书是自签而失败
func TestInClusterInsecureSkipVerify(t *testing.T) {
	srv := fakeAPIServer(t, "sa-token")

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("sa-token"), 0o600); err != nil {
		t.Fatalf("写 token 失败: %v", err)
	}

	client, err := newInCluster(InClusterOptions{
		BaseURL:   srv.URL,
		TokenPath: tokenPath,
		// 故意指向一个不存在的路径：跳过校验时代码不应该读它
		CAPath:             filepath.Join(dir, "nonexistent.crt"),
		Namespace:          "egress-proxy",
		ConfigMapName:      "egress-proxy-policy",
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("跳过校验时不应要求 CA 文件: %v", err)
	}

	pods, err := client.ListPods(context.Background())
	if err != nil {
		t.Fatalf("跳过校验时自签证书应能连通: %v", err)
	}
	if len(pods) != 1 {
		t.Fatalf("Pod 解析结果不对: %+v", pods)
	}

	if err := client.SavePolicy(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("保存策略失败: %v", err)
	}
}
