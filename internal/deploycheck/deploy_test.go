// Package deploycheck 校验 deploy/ 目录下的 Kustomize 入口、base 层清单与运行配置三者一致：
//   - 日常只需改 deploy/config.yaml（proxy.address + targets）与 deploy/kustomization.yaml（镜像地址）
//   - kustomize 的 images 变换在 name 对不上时不会报错、只会静默不替换，必须用测试守住
//   - ConfigMap 由 configMapGenerator 生成，其名称 / data key / 命名空间必须与工作负载的引用一致
//
// deploy/ 目录只保留镜像 tar 包、Kubernetes 清单与运行配置，不放 Go 代码；
// 校验逻辑集中在本包（原本是 deploy 与 deploy/base 下的 _test.go）。
// 下面的路径都相对本包目录，go test 会以包目录作为工作目录。
package deploycheck

const (
	// deployDir 是仓库里的部署目录
	deployDir = "../../deploy"
	// baseDir 是 base 层清单目录
	baseDir = deployDir + "/base"

	// kustomizationFile 是 Kustomize 入口
	kustomizationFile = deployDir + "/kustomization.yaml"
	// configFile 是日常要改的运行配置（ConfigMap 的生成源文件）
	configFile = deployDir + "/config.yaml"

	namespaceManifest  = baseDir + "/00-namespace.yaml"
	daemonSetManifest  = baseDir + "/10-daemonset.yaml"
	deploymentManifest = baseDir + "/20-proxy-deployment.yaml"
	controllerManifest = baseDir + "/30-controller.yaml"

	// 生成的 ConfigMap 名称与 data key（程序固定读取 /etc/egress-proxy/config.yaml）
	configMapName = "egress-proxy-config"
	configKey     = "config.yaml"

	// configRel 只用于报错文案，避免错误信息里出现 ../../ 前缀
	configRel = "deploy/config.yaml"
)
