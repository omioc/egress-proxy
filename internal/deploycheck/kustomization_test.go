// 本文件守住 Kustomize 入口：images 段与 base 清单里的占位镜像名必须双向对应，
// 并且 configMapGenerator / namespace 与工作负载的引用方式一致。
package deploycheck

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"egress-proxy/config"
)

// imageNamePattern 抓取 base 清单里的容器 image 值
var imageNamePattern = regexp.MustCompile(`(?m)^\s*image:\s*(\S+)\s*$`)

// tagPattern 与脚本、Docker 的 tag 规则一致
var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

type kustomization struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Resources  []string `yaml:"resources"`
	Images     []struct {
		Name    string `yaml:"name"`
		NewName string `yaml:"newName"`
		NewTag  string `yaml:"newTag"`
	} `yaml:"images"`
}

func loadKustomization(t *testing.T) kustomization {
	t.Helper()

	raw, err := os.ReadFile(kustomizationFile)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", kustomizationFile, err)
	}
	var k kustomization
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatalf("解析 %s 失败: %v", kustomizationFile, err)
	}
	return k
}

// imagesInManifest 返回某个 base 清单里出现的所有镜像引用（原样，含 tag）
func imagesInManifest(t *testing.T, path string) []string {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	var images []string
	for _, match := range imageNamePattern.FindAllStringSubmatch(string(raw), -1) {
		images = append(images, match[1])
	}
	if len(images) == 0 {
		t.Fatalf("%s 中没有找到任何 image 字段", path)
	}
	return images
}

// stripTag 去掉镜像引用里的 tag/digest，得到 kustomize 用来匹配的镜像名
// 例：harbor:5000/library/app:1.0 -> harbor:5000/library/app
func stripTag(ref string) string {
	if at := strings.Index(ref, "@"); at >= 0 {
		ref = ref[:at]
	}
	colon := strings.LastIndex(ref, ":")
	if colon < 0 {
		return ref
	}
	// 冒号后面含 "/" 说明那是 registry 的端口号，不是 tag
	if strings.Contains(ref[colon+1:], "/") {
		return ref
	}
	return ref[:colon]
}

func TestKustomizationBasics(t *testing.T) {
	k := loadKustomization(t)

	if k.APIVersion != "kustomize.config.k8s.io/v1beta1" {
		t.Errorf("apiVersion = %q，期望 kustomize.config.k8s.io/v1beta1", k.APIVersion)
	}
	if k.Kind != "Kustomization" {
		t.Errorf("kind = %q，期望 Kustomization", k.Kind)
	}
	if len(k.Images) == 0 {
		t.Fatal("images 段不能为空：镜像地址必须在这里统一维护")
	}
}

func TestKustomizationListsAllBaseManifests(t *testing.T) {
	k := loadKustomization(t)

	want := map[string]bool{
		namespaceManifest:  false,
		daemonSetManifest:  false,
		controllerManifest: false,
		deploymentManifest: false,
	}
	for _, resource := range k.Resources {
		// kustomization 里的 resources 相对 deploy/ 目录书写（如 base/10-daemonset.yaml）
		full := deployDir + "/" + resource
		if _, ok := want[full]; ok {
			want[full] = true
		} else {
			t.Errorf("resources 中出现未预期的条目 %q", resource)
		}
	}
	for file, seen := range want {
		if !seen {
			t.Errorf("resources 缺少 %q（否则 kubectl apply -k deploy/ 会漏掉它）", strings.TrimPrefix(file, deployDir+"/"))
		}
		if _, err := os.Stat(file); err != nil {
			t.Errorf("resources 引用的文件不存在: %s", file)
		}
	}
}

// TestKustomizationImagesCoverBaseImages 是本文件的核心：
// base 清单里出现的每个镜像名都必须有对应的 images 条目（否则改 kustomization 不起作用），
// 反之 images 里的每个 name 也必须在 base 清单里真实出现（否则那条配置是死配置）
func TestKustomizationImagesCoverBaseImages(t *testing.T) {
	k := loadKustomization(t)
	baseImages := map[string]string{} // 镜像名 → 首次出现的位置（便于报错）
	for _, manifest := range []string{daemonSetManifest, deploymentManifest, controllerManifest} {
		for _, ref := range imagesInManifest(t, manifest) {
			baseImages[stripTag(ref)] = manifest
		}
	}

	entries := map[string]bool{}
	for _, entry := range k.Images {
		if entry.Name == "" {
			t.Error("images 条目缺少 name")
			continue
		}
		if entry.NewName == "" {
			t.Errorf("images[%s] 缺少 newName", entry.Name)
		}
		if !tagPattern.MatchString(entry.NewTag) {
			t.Errorf("images[%s].newTag = %q 不是合法 tag", entry.Name, entry.NewTag)
		}
		if _, ok := baseImages[entry.Name]; !ok {
			t.Errorf("images 段里的 %q 在 base 清单中不存在，该条目不会生效（检查占位镜像名是否被改动）", entry.Name)
		}
		entries[entry.Name] = true
	}

	for name, manifest := range baseImages {
		if !entries[name] {
			t.Errorf("base 清单 %s 中的镜像 %q 没有对应的 images 条目，kustomize 不会改写它", manifest, name)
		}
	}
}

// TestBaseManifestsUseBarePlaceholderImages 保证 base 清单里的镜像名是 kustomize 能匹配的占位名，
// 并且已经带了 tag（避免 :latest 带来的隐式拉取行为）
func TestBaseManifestsUseBarePlaceholderImages(t *testing.T) {
	for _, manifest := range []string{daemonSetManifest, deploymentManifest} {
		for _, ref := range imagesInManifest(t, manifest) {
			name := stripTag(ref)
			if strings.Contains(name, "/") {
				t.Errorf("%s 中的镜像 %q 带仓库路径，请使用占位短名（镜像地址统一由 kustomization.yaml 指定）", manifest, ref)
			}
			if !strings.Contains(ref, ":") {
				t.Errorf("%s 中的镜像 %q 没有 tag", manifest, ref)
			}
			if strings.HasSuffix(ref, ":latest") {
				t.Errorf("%s 中的镜像 %q 使用了 :latest，请写明版本 tag", manifest, ref)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 运行配置（deploy/config.yaml）与其生成的 ConfigMap 之间的一致性
// ---------------------------------------------------------------------------

// configMapVolumePattern 抓取 workload 里 configMap 卷引用的名称（YAML 换行写法）
var configMapVolumePattern = regexp.MustCompile(`configMap:\s*\n\s*name:\s*(\S+)`)

// kustomizationFull 是 kustomization.yaml 的完整视图（含 namespace 与 configMapGenerator）
type kustomizationFull struct {
	Namespace          string   `yaml:"namespace"`
	Resources          []string `yaml:"resources"`
	ConfigMapGenerator []struct {
		Name    string   `yaml:"name"`
		Files   []string `yaml:"files"`
		Options struct {
			DisableNameSuffixHash bool              `yaml:"disableNameSuffixHash"`
			Labels                map[string]string `yaml:"labels"`
		} `yaml:"options"`
	} `yaml:"configMapGenerator"`
}

func loadFullKustomization(t *testing.T) kustomizationFull {
	t.Helper()

	raw, err := os.ReadFile(kustomizationFile)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", kustomizationFile, err)
	}
	var k kustomizationFull
	if err := yaml.Unmarshal(raw, &k); err != nil {
		t.Fatalf("解析 %s 失败: %v", kustomizationFile, err)
	}
	return k
}

// TestConfigFilePassesProgramValidation 保证「日常要改的那个文件」本身是程序能接受的配置
func TestConfigFilePassesProgramValidation(t *testing.T) {
	raw, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", configFile, err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("%s 未通过程序配置校验: %v", configRel, err)
	}
	if cfg.ProxyIP() == nil {
		t.Errorf("%s 的 proxy.address = %q 不是合法 IPv4", configRel, cfg.Proxy.Address)
	}
	// targets 允许为空（见 config.Parse 的注释）：启用四元组管控后 targets 由控制器下发
	// 只有退回「按本文件 targets 全量直通代理」的旧行为时，才要求这里配出实际目标
	if cfg.Options.PolicyURL == "" && len(cfg.Targets) == 0 {
		t.Fatalf("%s 未启用 options.policyUrl 时至少要有一条 target", configRel)
	}
	if cfg.Options.HealthPort != config.DefaultHealthPort {
		t.Errorf("healthPort = %d，期望默认 %d", cfg.Options.HealthPort, config.DefaultHealthPort)
	}
	if cfg.Options.ChainName != config.DefaultChainName {
		t.Errorf("chainName = %q，期望默认 %q", cfg.Options.ChainName, config.DefaultChainName)
	}
	if cfg.Options.ConfigInterval.D() != config.DefaultConfigInterval {
		t.Errorf("configInterval = %s，期望默认 %s", cfg.Options.ConfigInterval, config.DefaultConfigInterval)
	}
	// proxyPort 的唯一性/范围由 config.Parse 校验；这里只提示是否落在示例端口段内
	for _, target := range cfg.Targets {
		if target.ProxyPort < 20000 {
			t.Logf("提示：target %s 的 proxyPort %d 不在示例约定的 20000+ 段内", target.Key(), target.ProxyPort)
		}
	}
}

// TestConfigMapIsGeneratedFromConfigFile 保证 ConfigMap 确实由 deploy/config.yaml 生成，
// 并且名称、data key 与工作负载的引用方式一致
func TestConfigMapIsGeneratedFromConfigFile(t *testing.T) {
	k := loadFullKustomization(t)

	if len(k.ConfigMapGenerator) != 1 {
		t.Fatalf("configMapGenerator 应恰好 1 个（从 %s 生成 ConfigMap），实际 %d 个",
			configRel, len(k.ConfigMapGenerator))
	}
	generator := k.ConfigMapGenerator[0]

	if generator.Name != configMapName {
		t.Errorf("ConfigMap 名称 = %q，期望 %q（base 清单按此名称挂载）", generator.Name, configMapName)
	}
	if len(generator.Files) != 1 || generator.Files[0] != configKey {
		t.Fatalf("configMapGenerator.files = %v，期望只引用 %q", generator.Files, configKey)
	}
	// 没有 "key=" 前缀时，key 取文件名，正好是程序读取的 config.yaml
	if strings.Contains(generator.Files[0], "=") {
		t.Errorf("files[0] = %q 带了 key= 前缀，请确认 ConfigMap 的 key 仍是 %q", generator.Files[0], configKey)
	}
	if !generator.Options.DisableNameSuffixHash {
		t.Error("必须 disableNameSuffixHash: true，否则 ConfigMap 会带内容 hash 后缀，base 清单按名字引用会挂载失败")
	}
	if _, err := os.Stat(configFile); err != nil {
		t.Errorf("生成源文件不存在: %s", configFile)
	}
	if k.Namespace != "egress-proxy" {
		t.Errorf("kustomization 的 namespace = %q，期望 egress-proxy（否则生成的 ConfigMap 会落到 default 命名空间）", k.Namespace)
	}
}

// TestWorkloadsReferenceGeneratedConfigMap 保证 daemonset/deployment 挂载的 ConfigMap 名称与命名空间，
// 与 configMapGenerator 生成的完全一致
func TestWorkloadsReferenceGeneratedConfigMap(t *testing.T) {
	k := loadFullKustomization(t)
	if len(k.ConfigMapGenerator) != 1 {
		t.Fatalf("configMapGenerator 数量 = %d，期望 1", len(k.ConfigMapGenerator))
	}
	generatedName := k.ConfigMapGenerator[0].Name

	for _, manifest := range []string{daemonSetManifest, deploymentManifest} {
		raw, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", manifest, err)
		}
		matches := configMapVolumePattern.FindAllStringSubmatch(string(raw), -1)
		if len(matches) == 0 {
			t.Errorf("%s 中没有找到 configMap 卷引用", manifest)
			continue
		}
		for _, match := range matches {
			if match[1] != generatedName {
				t.Errorf("%s 挂载的 ConfigMap 名称 = %q，与 kustomization 生成的 %q 不一致",
					manifest, match[1], generatedName)
			}
		}
		if !strings.Contains(string(raw), "namespace: "+k.Namespace) {
			t.Errorf("%s 的 namespace 与 kustomization 的 %q 不一致", manifest, k.Namespace)
		}
	}
}
