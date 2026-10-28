package controller

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"egress-proxy/internal/i18n"
	"egress-proxy/internal/policymodel"
)

const (
	// serviceAccountDir 是 in-cluster 凭据目录
	serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	// podListPageSize 是单次列取 Pod 的页大小
	podListPageSize = 500
	// metaListPageSize 是单次列取命名空间 / 工作负载的页大小
	metaListPageSize = 500
)

// PodLister 抽象 Pod 列表来源，便于测试与本地运行
type PodLister interface {
	ListPods(ctx context.Context) ([]policymodel.Pod, error)
}

// ClusterReader 提供 WebUI 表单下拉所需的集群元数据
// 与 Pod 列表不同，这部分只在打开表单时按需拉取（API 层带短缓存），不进后台轮询
type ClusterReader interface {
	ListNamespaces(ctx context.Context) ([]string, error)
	ListWorkloads(ctx context.Context, namespace string) ([]policymodel.Workload, error)
}

var _ ClusterReader = (*InCluster)(nil)

// PolicyStorage 抽象策略持久化，便于测试与内存模式
type PolicyStorage interface {
	// LoadPolicy 返回上一次保存的策略 JSON；不存在时返回 nil, nil
	LoadPolicy(ctx context.Context) ([]byte, error)
	// SavePolicy 覆盖保存策略 JSON
	SavePolicy(ctx context.Context, data []byte) error
	// Describe 返回存储位置描述（用于 WebUI 展示）
	Describe() string
}

// InClusterOptions 是构造 in-cluster 客户端的参数
type InClusterOptions struct {
	BaseURL       string
	TokenPath     string
	CAPath        string
	Namespace     string
	ConfigMapName string
	// InsecureSkipVerify 为 true 时不校验 apiserver 证书（默认行为，省去 CA 配置）
	InsecureSkipVerify bool
	// HTTPClient 仅用于测试注入；为空时按上面的 TLS 配置构造
	HTTPClient *http.Client
}

// InCluster 是最小化的 in-cluster REST 客户端：
// 只用标准库实现「列出 Pod」与「读写一个 ConfigMap」，不引入 client-go
type InCluster struct {
	baseURL       string
	token         string
	namespace     string
	configMapName string
	client        *http.Client
}

// NewInCluster 读取 ServiceAccount 凭据与集群 CA 并创建客户端
//
// 注意：必须显式加载 ca.crt —— 集群 apiserver 的证书由集群内部 CA 签发，
// 不在 alpine 等基础镜像的系统信任库里，否则会报
// "x509: certificate signed by unknown authority"
func NewInCluster(namespace, configMapName string, insecureSkipVerify bool) (*InCluster, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if host == "" {
		return nil, fmt.Errorf(i18n.Text("未找到 KUBERNETES_SERVICE_HOST，请确认运行在集群内（或使用 -in-cluster=false）"))
	}
	if port == "" {
		port = "443"
	}
	return newInCluster(InClusterOptions{
		BaseURL:            "https://" + host + ":" + port,
		TokenPath:          serviceAccountDir + "/token",
		CAPath:             serviceAccountDir + "/ca.crt",
		Namespace:          namespace,
		ConfigMapName:      configMapName,
		InsecureSkipVerify: insecureSkipVerify,
	})
}

// newInCluster 按显式路径构造客户端（便于测试注入自签 CA）
func newInCluster(opts InClusterOptions) (*InCluster, error) {
	token, err := os.ReadFile(opts.TokenPath)
	if err != nil {
		return nil, fmt.Errorf(i18n.Text("读取 ServiceAccount token（%s）失败: %w"), opts.TokenPath, err)
	}

	client := opts.HTTPClient
	if client == nil {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if opts.InsecureSkipVerify {
			// 默认行为：跳过 apiserver 证书校验
			// 理由：apiserver 证书由集群内部 CA 签发，在容器里加载 ca.crt 容易配错；
			// 访问链路本身是集群内网 + ServiceAccount token
			// 需要严格校验时把 -insecure-skip-verify 设为 false（会改用 CAPath 里的集群 CA）
			tlsConfig.InsecureSkipVerify = true
		} else {
			caPEM, err := os.ReadFile(opts.CAPath)
			if err != nil {
				return nil, fmt.Errorf(i18n.Text("读取集群 CA（%s）失败: %w"), opts.CAPath, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf(i18n.Text("集群 CA（%s）内容无效，无法用于校验 apiserver 证书"), opts.CAPath)
			}
			tlsConfig.RootCAs = pool
		}
		client = &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		}
	}

	return &InCluster{
		baseURL:       strings.TrimSuffix(opts.BaseURL, "/"),
		token:         strings.TrimSpace(string(token)),
		namespace:     opts.Namespace,
		configMapName: opts.ConfigMapName,
		client:        client,
	}, nil
}

// Describe 实现 PolicyStorage
func (c *InCluster) Describe() string { return "configmap" }

func (c *InCluster) do(ctx context.Context, method, path string, body []byte, contentType string) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode >= 300 {
		return data, resp.StatusCode, &localizedError{
			msg:  msgAPICallFailed,
			args: []any{method, path, resp.StatusCode, strings.TrimSpace(string(data))},
		}
	}
	return data, resp.StatusCode, nil
}

// podListResponse 是 Pod 列表的最小反序列化结构
type podListResponse struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Name      string            `json:"name"`
			Namespace string            `json:"namespace"`
			Labels    map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			Phase string `json:"phase"`
			PodIP string `json:"podIP"`
		} `json:"status"`
	} `json:"items"`
}

// ListPods 列取全部命名空间的 Pod（分页拉取）
func (c *InCluster) ListPods(ctx context.Context) ([]policymodel.Pod, error) {
	var out []policymodel.Pod
	token := ""
	for page := 0; page < 200; page++ {
		query := url.Values{}
		query.Set("limit", fmt.Sprintf("%d", podListPageSize))
		if token != "" {
			query.Set("continue", token)
		}
		data, _, err := c.do(ctx, http.MethodGet, "/api/v1/pods?"+query.Encode(), nil, "")
		if err != nil {
			return nil, err
		}
		var parsed podListResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, locErr(msgParsePodList, err)
		}
		for _, item := range parsed.Items {
			phase := item.Status.Phase
			if phase == "Succeeded" || phase == "Failed" {
				continue
			}
			out = append(out, policymodel.Pod{
				Namespace: item.Metadata.Namespace,
				Name:      item.Metadata.Name,
				NodeName:  item.Spec.NodeName,
				IP:        item.Status.PodIP,
				Labels:    item.Metadata.Labels,
			})
		}
		token = parsed.Metadata.Continue
		if token == "" {
			break
		}
	}
	return out, nil
}

// LoadPolicy 从 ConfigMap 读取策略 JSON
func (c *InCluster) LoadPolicy(ctx context.Context) ([]byte, error) {
	data, status, err := c.do(ctx, http.MethodGet, c.configMapPath(), nil, "")
	if err != nil {
		if status == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}
	var cm struct {
		Data map[string]string `json:"data"`
	}
	if err := json.Unmarshal(data, &cm); err != nil {
		return nil, locErr(msgParseConfigMap, err)
	}
	if cm.Data == nil {
		return nil, nil
	}
	raw, ok := cm.Data[policyDataKey]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return []byte(raw), nil
}

// SavePolicy 用 merge patch 写入 ConfigMap（避免 resourceVersion 冲突）
func (c *InCluster) SavePolicy(ctx context.Context, data []byte) error {
	patch := map[string]interface{}{
		"data": map[string]string{policyDataKey: string(data)},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	_, status, patchErr := c.do(ctx, http.MethodPatch, c.configMapPath(), body, "application/merge-patch+json")
	if patchErr == nil {
		return nil
	}
	if status != http.StatusNotFound {
		// 只有当 ConfigMap 不存在时才退化为创建；其他错误（403/409/TLS 等）必须原样报出
		return locErr(msgWriteConfigMap, patchErr)
	}
	// ConfigMap 不存在时创建
	create := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]interface{}{
			"name":      c.configMapName,
			"namespace": c.namespace,
			"labels":    map[string]string{"app.kubernetes.io/part-of": "egress-proxy"},
		},
		"data": map[string]string{policyDataKey: string(data)},
	}
	createBody, err := json.Marshal(create)
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, http.MethodPost,
		"/api/v1/namespaces/"+url.PathEscape(c.namespace)+"/configmaps", createBody, "application/json")
	return err
}

func (c *InCluster) configMapPath() string {
	return "/api/v1/namespaces/" + url.PathEscape(c.namespace) + "/configmaps/" + url.PathEscape(c.configMapName)
}

// MemoryStorage 是内存实现（本地开发 / 无集群时使用）
type MemoryStorage struct {
	mu   sync.Mutex
	data []byte
}

// LoadPolicy 实现 PolicyStorage
func (m *MemoryStorage) LoadPolicy(context.Context) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data, nil
}

// SavePolicy 实现 PolicyStorage
func (m *MemoryStorage) SavePolicy(_ context.Context, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = append([]byte(nil), data...)
	return nil
}

// Describe 实现 PolicyStorage
func (m *MemoryStorage) Describe() string { return "memory" }

// namespaceListResponse 是命名空间列表的最小反序列化结构
type namespaceListResponse struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
	} `json:"items"`
}

// ListNamespaces 列取全部命名空间（按名称排序），供 WebUI 下拉使用
func (c *InCluster) ListNamespaces(ctx context.Context) ([]string, error) {
	out := make([]string, 0, 32)
	token := ""
	for page := 0; page < 40; page++ {
		query := url.Values{}
		query.Set("limit", fmt.Sprintf("%d", metaListPageSize))
		if token != "" {
			query.Set("continue", token)
		}
		data, _, err := c.do(ctx, http.MethodGet, "/api/v1/namespaces?"+query.Encode(), nil, "")
		if err != nil {
			return nil, err
		}
		var parsed namespaceListResponse
		if err := json.Unmarshal(data, &parsed); err != nil {
			return nil, locErr(msgParseNamespace, err)
		}
		for _, item := range parsed.Items {
			if name := strings.TrimSpace(item.Metadata.Name); name != "" {
				out = append(out, name)
			}
		}
		token = parsed.Metadata.Continue
		if token == "" {
			break
		}
	}
	sort.Strings(out)
	return out, nil
}

// workloadListResponse 是 apps/v1 工作负载列表的最小反序列化结构
type workloadListResponse struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
		} `json:"metadata"`
		Spec struct {
			Selector struct {
				MatchLabels map[string]string `json:"matchLabels"`
			} `json:"selector"`
		} `json:"spec"`
		Status struct {
			Replicas      int `json:"replicas"`
			ReadyReplicas int `json:"readyReplicas"`
			NumberReady   int `json:"numberReady"`
			Desired       int `json:"desiredNumberScheduled"`
		} `json:"status"`
	} `json:"items"`
}

// ListWorkloads 列取 Deployment / StatefulSet / DaemonSet（namespace 为空表示全部命名空间）
//
// 只取 metadata.name 与 spec.selector.matchLabels：前者给 WebUI 下拉，后者用来把
// 「按工作负载名」的 payload 解析成标签选择器；matchExpressions 不在支持范围（极少见），
// 这类工作负载的 selector 会是空的，保存策略时会被明确报错，而不是静默匹配整个命名空间
func (c *InCluster) ListWorkloads(ctx context.Context, namespace string) ([]policymodel.Workload, error) {
	kinds := []string{"deployments", "statefulsets", "daemonsets"}
	out := make([]policymodel.Workload, 0, 32)
	for _, kind := range kinds {
		path := "/apis/apps/v1/"
		if namespace != "" {
			path += "namespaces/" + url.PathEscape(namespace) + "/"
		}
		path += kind
		token := ""
		for page := 0; page < 40; page++ {
			query := url.Values{}
			query.Set("limit", fmt.Sprintf("%d", metaListPageSize))
			if token != "" {
				query.Set("continue", token)
			}
			data, _, err := c.do(ctx, http.MethodGet, path+"?"+query.Encode(), nil, "")
			if err != nil {
				return nil, err
			}
			var parsed workloadListResponse
			if err := json.Unmarshal(data, &parsed); err != nil {
				return nil, locErrArgs(msgParseResourceList, err, kind)
			}
			for _, item := range parsed.Items {
				name := strings.TrimSpace(item.Metadata.Name)
				if name == "" {
					continue
				}
				selector := make(map[string]string, len(item.Spec.Selector.MatchLabels))
				for k, v := range item.Spec.Selector.MatchLabels {
					selector[k] = v
				}
				out = append(out, policymodel.Workload{
					Kind:      workloadKindOf(kind),
					Namespace: item.Metadata.Namespace,
					Name:      name,
					Selector:  selector,
					Ready: readyString(kind, item.Status.Replicas, item.Status.ReadyReplicas,
						item.Status.NumberReady, item.Status.Desired),
				})
			}
			token = parsed.Metadata.Continue
			if token == "" {
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// workloadKindOf 把 REST 资源名还原成 Kubernetes 的 Kind
func workloadKindOf(resource string) string {
	switch resource {
	case "deployments":
		return string(policymodel.WorkloadDeployment)
	case "statefulsets":
		return string(policymodel.WorkloadStatefulSet)
	case "daemonsets":
		return string(policymodel.WorkloadDaemonSet)
	}
	return resource
}

// readyString 生成「就绪/期望」描述，仅用于 WebUI 展示
func readyString(resource string, replicas, readyReplicas, numberReady, desired int) string {
	if resource == "daemonsets" {
		return fmt.Sprintf("%d/%d", numberReady, desired)
	}
	want := replicas
	if want == 0 {
		want = readyReplicas
	}
	return fmt.Sprintf("%d/%d", readyReplicas, want)
}
