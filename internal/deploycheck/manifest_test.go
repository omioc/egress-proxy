// 本文件守住 base 层清单（deploy/base/*.yaml）的一致性：清单可解析、
// 以及工作负载的关键字段（hostNetwork、探针端口、挂载路径、环境变量）与代码约定一致。
package deploycheck

import (
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"egress-proxy/config"
)

const (
	configMountDir   = "/etc/egress-proxy"
	configMountPath  = configMountDir + "/" + configKey
	proxyNodeLabel   = "egress-proxy"
	healthPath       = "/healthz"
	readyPath        = "/readyz"
	serviceAccountNS = "egress-proxy"
	// configMapRefName 是 base 清单里挂载的 ConfigMap 名称（与 kustomization 生成的一致）
	configMapRefName = configMapName
)

type manifest struct {
	Kind     string `yaml:"kind"`
	Metadata struct {
		Name      string `yaml:"name"`
		Namespace string `yaml:"namespace"`
	} `yaml:"metadata"`
	Data map[string]string `yaml:"data"`
	Spec struct {
		Replicas *int `yaml:"replicas"`
		Template struct {
			Spec struct {
				HostNetwork  bool              `yaml:"hostNetwork"`
				DNSPolicy    string            `yaml:"dnsPolicy"`
				NodeSelector map[string]string `yaml:"nodeSelector"`
				Containers   []struct {
					Name  string   `yaml:"name"`
					Image string   `yaml:"image"`
					Args  []string `yaml:"args"`
					Env   []struct {
						Name      string `yaml:"name"`
						ValueFrom struct {
							FieldRef struct {
								FieldPath string `yaml:"fieldPath"`
							} `yaml:"fieldRef"`
						} `yaml:"valueFrom"`
					} `yaml:"env"`
					VolumeMounts []struct {
						Name      string `yaml:"name"`
						MountPath string `yaml:"mountPath"`
						ReadOnly  bool   `yaml:"readOnly"`
					} `yaml:"volumeMounts"`
					LivenessProbe struct {
						HTTPGet struct {
							Path string `yaml:"path"`
							Port int    `yaml:"port"`
						} `yaml:"httpGet"`
					} `yaml:"livenessProbe"`
					ReadinessProbe struct {
						HTTPGet struct {
							Path string `yaml:"path"`
							Port int    `yaml:"port"`
						} `yaml:"httpGet"`
					} `yaml:"readinessProbe"`
				} `yaml:"containers"`
				Volumes []struct {
					Name      string `yaml:"name"`
					ConfigMap struct {
						Name string `yaml:"name"`
					} `yaml:"configMap"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

// loadManifests 解析清单文件中的所有文档
func loadManifests(t *testing.T, path string) []manifest {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("打开 %s 失败: %v", path, err)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	var docs []manifest
	for {
		var doc manifest
		err := decoder.Decode(&doc)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("解析 %s 失败: %v", path, err)
		}
		if doc.Kind == "" {
			continue // 空文档
		}
		docs = append(docs, doc)
	}
	if len(docs) == 0 {
		t.Fatalf("%s 中没有有效的 Kubernetes 文档", path)
	}
	return docs
}

func findKind(t *testing.T, path, kind string) manifest {
	t.Helper()
	for _, doc := range loadManifests(t, path) {
		if doc.Kind == kind {
			return doc
		}
	}
	t.Fatalf("%s 中未找到 kind: %s", path, kind)
	return manifest{}
}

func TestManifestsAreParsable(t *testing.T) {
	kinds := map[string][]string{
		namespaceManifest:  {"Namespace"},
		daemonSetManifest:  {"DaemonSet"},
		deploymentManifest: {"Deployment"},
	}
	for file, wantKinds := range kinds {
		docs := loadManifests(t, file)
		found := make(map[string]bool, len(docs))
		for _, doc := range docs {
			found[doc.Kind] = true
			if doc.Metadata.Name == "" {
				t.Errorf("%s 中 %s 缺少 metadata.name", file, doc.Kind)
			}
			if doc.Kind != "Namespace" && doc.Metadata.Namespace != serviceAccountNS {
				t.Errorf("%s 中 %s 的 namespace = %q，期望 %q", file, doc.Kind, doc.Metadata.Namespace, serviceAccountNS)
			}
		}
		for _, want := range wantKinds {
			if !found[want] {
				t.Errorf("%s 缺少 kind %s", file, want)
			}
		}
	}
}

func TestDaemonSetMatchesCodeConventions(t *testing.T) {
	ds := findKind(t, daemonSetManifest, "DaemonSet")
	if !ds.Spec.Template.Spec.HostNetwork {
		t.Error("DaemonSet 必须使用 hostNetwork 才能操作宿主机 iptables")
	}
	if ds.Spec.Template.Spec.DNSPolicy != "ClusterFirstWithHostNet" {
		t.Errorf("dnsPolicy = %q，期望 ClusterFirstWithHostNet", ds.Spec.Template.Spec.DNSPolicy)
	}
	if len(ds.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("期望 1 个容器，实际 %d 个", len(ds.Spec.Template.Spec.Containers))
	}
	c := ds.Spec.Template.Spec.Containers[0]

	if !hasArg(c.Args, "-config="+configMountPath) {
		t.Errorf("容器 args = %v，应包含 -config=%s", c.Args, configMountPath)
	}
	if !hasEnvFieldRef(c.Env, "HOST_IP", "status.hostIP") {
		t.Error("应通过 Downward API 注入 HOST_IP = status.hostIP")
	}
	if !hasConfigMount(c.VolumeMounts, configMountDir) {
		t.Errorf("应把配置只读挂载到 %s", configMountPath)
	}
	if !hasConfigMapVolume(ds.Spec.Template.Spec.Volumes, configMapRefName) {
		t.Errorf("应挂载名为 %s 的 ConfigMap", configMapRefName)
	}
	if !strings.Contains(c.Image, "redirect-agent") {
		t.Errorf("镜像 %q 应指向 redirect-agent", c.Image)
	}
}

func TestDeploymentMatchesCodeConventions(t *testing.T) {
	dep := findKind(t, deploymentManifest, "Deployment")
	if !dep.Spec.Template.Spec.HostNetwork {
		t.Error("Deployment 必须使用 hostNetwork 才能让工作节点 DNAT 到本节点端口")
	}
	if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 1 {
		t.Error("代理节点为单点，replicas 应为 1")
	}
	if got := dep.Spec.Template.Spec.NodeSelector[proxyNodeLabel]; got != "true" {
		t.Errorf("nodeSelector[%s] = %q，期望 \"true\"", proxyNodeLabel, got)
	}
	if len(dep.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("期望 1 个容器，实际 %d 个", len(dep.Spec.Template.Spec.Containers))
	}
	c := dep.Spec.Template.Spec.Containers[0]

	if !hasArg(c.Args, "-config="+configMountPath) {
		t.Errorf("容器 args = %v，应包含 -config=%s", c.Args, configMountPath)
	}
	if !hasEnvFieldRef(c.Env, "HOST_IP", "status.hostIP") {
		t.Error("应通过 Downward API 注入 HOST_IP = status.hostIP")
	}
	if !hasConfigMount(c.VolumeMounts, configMountDir) {
		t.Errorf("应把配置只读挂载到 %s", configMountPath)
	}
	if !hasConfigMapVolume(dep.Spec.Template.Spec.Volumes, configMapRefName) {
		t.Errorf("应挂载名为 %s 的 ConfigMap", configMapRefName)
	}
	if !strings.Contains(c.Image, "tcp-forwarder") {
		t.Errorf("镜像 %q 应指向 tcp-forwarder", c.Image)
	}

	// 探针端口必须与程序默认 healthPort 一致（ConfigMap 未覆盖 options 时）
	if c.LivenessProbe.HTTPGet.Port != config.DefaultHealthPort {
		t.Errorf("livenessProbe 端口 = %d，期望 %d", c.LivenessProbe.HTTPGet.Port, config.DefaultHealthPort)
	}
	if c.LivenessProbe.HTTPGet.Path != healthPath {
		t.Errorf("livenessProbe 路径 = %q，期望 %q", c.LivenessProbe.HTTPGet.Path, healthPath)
	}
	if c.ReadinessProbe.HTTPGet.Port != config.DefaultHealthPort {
		t.Errorf("readinessProbe 端口 = %d，期望 %d", c.ReadinessProbe.HTTPGet.Port, config.DefaultHealthPort)
	}
	if c.ReadinessProbe.HTTPGet.Path != readyPath {
		t.Errorf("readinessProbe 路径 = %q，期望 %q", c.ReadinessProbe.HTTPGet.Path, readyPath)
	}
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func hasEnvFieldRef(env []struct {
	Name      string `yaml:"name"`
	ValueFrom struct {
		FieldRef struct {
			FieldPath string `yaml:"fieldPath"`
		} `yaml:"fieldRef"`
	} `yaml:"valueFrom"`
}, name, fieldPath string) bool {
	for _, e := range env {
		if e.Name == name && e.ValueFrom.FieldRef.FieldPath == fieldPath {
			return true
		}
	}
	return false
}

func hasConfigMount(mounts []struct {
	Name      string `yaml:"name"`
	MountPath string `yaml:"mountPath"`
	ReadOnly  bool   `yaml:"readOnly"`
}, path string) bool {
	for _, m := range mounts {
		if m.MountPath == path && m.ReadOnly {
			return true
		}
	}
	return false
}

func hasConfigMapVolume(volumes []struct {
	Name      string `yaml:"name"`
	ConfigMap struct {
		Name string `yaml:"name"`
	} `yaml:"configMap"`
}, name string) bool {
	for _, v := range volumes {
		if v.ConfigMap.Name == name {
			return true
		}
	}
	return false
}

// TestHealthPortInManifestsIsNumeric 保证探针端口是数字（避免 YAML 把端口写成字符串导致探针失效）
func TestHealthPortInManifestsIsNumeric(t *testing.T) {
	raw, err := os.ReadFile(deploymentManifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "port: "+strconv.Itoa(config.DefaultHealthPort)) {
		t.Errorf("清单中应使用数字端口 %d", config.DefaultHealthPort)
	}
}
