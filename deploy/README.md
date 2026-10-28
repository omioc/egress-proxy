**中文** | [English](README.en.md)

# 部署与运维手册

本文是 `deploy/` 目录的详细说明：部署前准备、镜像准备、配置字段、四元组管控与 WebUI、
上线验收、日常运维、回滚卸载、已知限制与故障排查。

项目简介、架构图与组件职责见仓库根目录的 `README.md`。

> 文档中的镜像名统一写作 `<registry>/egress-proxy/redirect-agent:0.1.6` 的形式，
> **请把 `<registry>` 替换成你自己的镜像仓库地址**（例如 `harbor.example.com`）。

---

## 1. 部署前准备

| 项 | 要求 |
| --- | --- |
| 代理节点 | 必须是**工作节点**（该节点上的 Pod 要能正常出网），IP 稳定，并打上标签 `egress-proxy=true` |
| 节点网络 | `redirect-agent` 与 `tcp-forwarder` 都使用 `hostNetwork`；代理节点需要能被所有工作节点访问到 `proxyPort` 段 |
| 端口规划 | 每个 target 在代理节点上占用一个**独享** `proxyPort`（示例用 20001-20006）；`options.healthPort` 默认 18081；controller 对外 18082 |
| iptables 后端 | `options.iptablesBinary` 必须与节点 kube-proxy 实际使用的后端一致（legacy 后端要填 `iptables-legacy`），否则规则写入的表不对，表现为规则存在但流量不被重定向 |
| 防火墙 / NetworkPolicy | 放行 `Pod CIDR → 代理节点IP : proxyPort 段`（如 20001-20010），以及各工作节点 → 代理节点该端口段；否则 DNAT 后连接超时 |
| 集群内权限 | DaemonSet 需要 `NET_ADMIN`、`NET_RAW`，`/run` 为可写 `emptyDir`（清单里已配置） |

```bash
# 给代理节点打标签（顺序重要：必须在 apply 之前）
kubectl label node <node> egress-proxy=true
```

## 2. 镜像准备

### 2.1 直接构建并推送

```bash
docker build -f Dockerfile.agent -t <registry>/egress-proxy/redirect-agent:0.1.6 .
docker build -f Dockerfile.proxy -t <registry>/egress-proxy/tcp-forwarder:0.1.6 .
docker build -f Dockerfile.controller -t <registry>/egress-proxy/controller:0.1.6 .
docker push <registry>/egress-proxy/redirect-agent:0.1.6
docker push <registry>/egress-proxy/tcp-forwarder:0.1.6
docker push <registry>/egress-proxy/controller:0.1.6
```

依赖按 `go.sum` 通过 `GOPROXY` 拉取（仓库不含 `vendor/`），Dockerfile 默认
`ARG GOPROXY=https://goproxy.cn,direct`，可用 `--build-arg GOPROXY=...` 覆盖；
构建阶段先 `COPY go.mod go.sum` 再 `go mod download`，依赖层可命中构建缓存。

### 2.2 离线打包（Windows / PowerShell 7）

```bash
# 构建并导出三个 tar 包到 deploy/（镜像名不带仓库前缀）
pwsh ./scripts/build-images.ps1 -Tag 0.1.6
# 可选参数：-OutputDir <目录>、-Platform linux/arm64、-NoCache、-GoProxy <模块代理>、-SkipBuild（只导出已有镜像）
```

把 tar 包拷到节点后导入（镜像名不带前缀，默认已在 `deploy/kustomization.yaml` 的 `images` 段指定）：

```bash
docker load -i redirect-agent-0.1.6.tar      # Docker 运行时
ctr -n k8s.io images import redirect-agent-0.1.6.tar   # containerd 运行时
nerdctl -n k8s.io load -i redirect-agent-0.1.6.tar     # nerdctl 亦可
```

## 3. 部署：实际只需改两个文件

| 要改的文件 | 改什么 |
| --- | --- |
| `deploy/config.yaml` | 运行配置：`proxy.address`（代理节点 IP）+ `targets`（外部目标列表）；它由 kustomization 的 `configMapGenerator` 打包成 ConfigMap `egress-proxy-config` 的 `data["config.yaml"]`，挂载到 Pod 的 `/etc/egress-proxy/config.yaml` —— 你改的内容与 Pod 内文件完全一致 |
| `deploy/kustomization.yaml` | 镜像地址：`images` 段的 `newName` / `newTag`，改这一处同时作用于 DaemonSet 与 Deployment |

改完只需要一条命令（无需重启 Pod，两个组件按 `options.configInterval` 轮询挂载文件热加载）：

```bash
kubectl apply -k deploy/        # 渲染并应用
kubectl kustomize deploy/       # 只渲染不应用，确认最终生效的清单
kubectl delete -k deploy/       # 反向删除
kubectl -n egress-proxy get ds,deploy,pod -o wide
```

`images` 段示例（`name` 必须与 `deploy/base/*.yaml` 里的占位镜像名完全一致，否则 kustomize 会**静默不替换**，
`internal/deploycheck/kustomization_test.go` 专门守这条）：

```yaml
images:
  - name: redirect-agent
    newName: harbor.example.com/egress-proxy/redirect-agent   # 用 tar 导入的本地镜像就写 redirect-agent
    newTag: "0.1.0"
  - name: tcp-forwarder
    newName: harbor.example.com/egress-proxy/tcp-forwarder
    newTag: "0.1.0"
  - name: controller
    newName: harbor.example.com/egress-proxy/controller
    newTag: "0.1.0"
```

背景：Kubernetes 原生 YAML **不支持**变量或引用（`kubectl apply -f` 只做文本解析），
「配置只写一处」依赖 kubectl 自带的 kustomize；如果你要「一个变量同时驱动多个镜像」这类模板能力，
应改用 Helm；旧路径 `kubectl apply -f deploy/base/` 仍可用，但那样不会生成 ConfigMap、用的也是占位镜像名，不推荐。

部署顺序很重要：**先打标签、再改 `proxy.address`、最后 apply**；否则 forwarder 可能因为
`nodeSelector` 找不到节点而一直 Pending，或 DNAT 指向一个没有监听服务的 IP。

## 4. 配置字段说明

`proxy` 段：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `proxy.address` | string | 无（必填） | 代理节点 IP（IPv4），即 DNAT 的 `--to-destination` 主机，必须是打了 `egress-proxy=true` 标签的节点 IP |
| `proxy.listen` | string | `0.0.0.0` | `tcp-forwarder` 监听地址；建议保持 `0.0.0.0`，否则工作节点 DNAT 过来的流量可能连不上 |

`targets` 段（数组，每项一条映射；同一个 host 的多个端口要拆成多条）：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `targets[].host` | string | 无（必填） | 目标域名或 IPv4 字面量（仅 IPv4 生效） |
| `targets[].port` | int | 无（必填） | 原始目标端口，也是 forwarder 转发时拨号的端口 |
| `targets[].proxyPort` | int | 无（必填） | 代理节点上的**唯一**监听端口，不能重复、不能与节点已有服务冲突 |

`options` 段（全部可省略，省略即用默认值）：

| 字段 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `options.resolveInterval` | duration | `30s` | 域名重解析周期，解析结果变化后重建 DNAT 规则 |
| `options.configInterval` | duration | `2s` | 配置文件轮询间隔（ConfigMap 热加载依赖它） |
| `options.syncInterval` | duration | `60s` | 规则漂移自检周期，检测到被外部改动会修复 |
| `options.dialTimeout` | duration | `5s` | `tcp-forwarder` 拨号原始目标的超时 |
| `options.maxIPsPerHost` | int | `8` | 单个域名最多维护的规则 IP 数（防止 DNS 轮询导致规则爆炸） |
| `options.iptablesBinary` | string | `iptables` | 使用的 iptables 前端，可为 `iptables-legacy`；必须与节点 kube-proxy 后端一致 |
| `options.chainName` | string | `EGRESS-PROXY` | 专属链名，agent 只在本链内增删规则 |
| `options.healthPort` | int | `18081` | `tcp-forwarder` 的 `/healthz`、`/readyz` 端口，需与探针端口一致 |
| `options.dnsServers` | []string | `[]`（用系统 DNS） | 覆盖默认 DNS 服务器，例如 `["10.96.0.10"]` |
| `options.excludeCIDRs` | []string | `[]` | 需要排除的网段（如集群 Pod/Service CIDR），命中者不生成规则 |
| `options.policyUrl` | string | `""` | 控制器地址；填上即启用四元组管控，留空则保持「按本文件 `targets` 全量直通」的旧行为 |
| `options.policyInterval` | duration | `2s` | 从控制器拉取策略的周期（四元组模式） |

## 5. 四元组流量管控（payload 级授权 + WebUI）

启用后，一条规则从「目标 + 目标端口 + 代理端口」变成
「**payload** + 目标 + 目标端口 + 代理端口」，且**未授权的 payload 会被直接拒绝**（不会退回直连）。

```yaml
# deploy/config.yaml：填上控制器地址即启用；留空则保持旧的全量直通行为
options:
  policyUrl: http://egress-proxy-controller.egress-proxy.svc:18082
  policyInterval: 2s
```

启用后 `targets` 可以整段留空（`targets: []`），目标与授权全部在 WebUI 里配置，
agent 与 forwarder 会按 `policyInterval` 从控制器拉取。

| 组件 | 在四元组模式下的作用 |
| --- | --- |
| `egress-proxy-controller` | 新增：策略存储（ConfigMap `egress-proxy-policy`）、Pod 解析、按节点编译、REST API + 内置 WebUI |
| `redirect-agent` | 拉取编译结果，用**源地址匹配**生成 DNAT 与拒绝规则 |
| `tcp-forwarder` | 拉取目标列表，维护 `proxyPort` → `host:port` 监听 |

### 5.1 打开 WebUI

**方式 1：在能访问集群的机器上 port-forward（最安全）**

```bash
kubectl -n egress-proxy port-forward svc/egress-proxy-controller 18082:18082
# 然后在这台机器上访问 http://localhost:18082
```

**方式 2：从你自己的笔记本直接访问节点 IP**

`kubectl port-forward` 默认只监听 `127.0.0.1`（日志里是 `Forwarding from 127.0.0.1:18082`），
所以从别的机器访问 `http://<节点IP>:18082` 会 `ERR_CONNECTION_REFUSED`；加 `--address 0.0.0.0`：

```bash
kubectl -n egress-proxy port-forward --address 0.0.0.0 svc/egress-proxy-controller 18082:18082
# 然后访问 http://<该节点IP>:18082（节点防火墙需放行）
```

**方式 3：改成 NodePort（长期使用，一次配置不用一直开 port-forward）**

```bash
kubectl -n egress-proxy patch svc egress-proxy-controller -p \
  '{"spec":{"type":"NodePort","ports":[{"name":"http","port":18082,"targetPort":"http","nodePort":30082}]}}'
# 然后访问 http://<任意节点IP>:30082
```

> controller 是普通 Pod（ClusterIP），**不会**监听在节点 IP 上，所以直接访问 `<节点IP>:18082` 一定是拒连。
> 把 WebUI 暴露到节点网络之前，请先创建令牌 Secret（见 5.4），否则同网段任何人都能改出网策略。

**界面语言与主题**（自动检测，也可手动覆盖）：

- **语言**：首次打开按浏览器语言自动选择——`zh` / `zh-*` 显示中文，其他语言显示英文；顶栏右侧的 `中` / `EN` 按钮可随时切换，选择记在浏览器 localStorage（`egp_lang`）
- **主题**：默认**跟随系统**（`prefers-color-scheme`），系统切换深/浅色时页面立即跟随；顶栏的太阳/月亮按钮按「跟随系统 → 浅色 → 深色」循环，手动选择后记在 localStorage（`egp_theme`）
- **临时覆盖**（便于分享链接或截图）：`?lang=zh|en`、`?theme=auto|light|dark`，例如 `http://localhost:18082/?lang=en&theme=dark`；URL 参数会写入 localStorage，下次打开沿用
- **API 文案**：控制器按请求头 `Accept-Language` 返回校验错误与告警（`zh*` → 中文，其他 → 英文，缺省中文）；WebUI 会随当前界面语言自动带上该请求头，`curl` 不带头时拿到中文
- **日志与命令行**：`-lang zh|en` 或环境变量 `EGRESS_LANG` 控制日志、`-h` 帮助与配置文件解析错误的语言（缺省中文）；DaemonSet / Deployment 想换语言时加这个环境变量再滚动更新即可

### 5.2 页面上要做的事

分布在三个标签页（顺序固定：外部服务 → 授权矩阵 → 运行状态）：

- **外部服务**：维护 `host` / `port` / `proxyPort`，并看到每个服务被几个负载引用、实际生效的源地址
- **授权矩阵**：左边选负载，右边勾选它能访问的外部服务；负载有两种选法——按工作负载名（下拉选
  `Deployment` / `StatefulSet` / `DaemonSet`，控制器用只读权限读取它的 `spec.selector.matchLabels`），
  或按标签选择器（手填 `k=v`）；命名空间同样是下拉选择；勾选即刻生效，无需保存
- **运行状态**：切换执行模式（`disabled` / `observe` / `enforce`）、查看每台节点 agent 的应用与同步状态、
  策略告警、控制器连通性；页面支持浅色 / 深色主题，顶栏显示「刷新于 N 秒前」

### 5.3 语义速查

- **payload** = 某个命名空间里、命中一组标签的 Pod 的 IP 集合；标签来自「选中的工作负载」或手填的标签选择器；
  两者在保存时都会解析成具体的 `matchLabels` 写进策略，因此读取时不再依赖 apiserver
- **没有任何授权的目标 = 谁都不通**（默认拒绝），不是"谁都能连"
- **策略变更只改子链内容**，规则结构不变；生效时间 ≈ `policyInterval`（默认 2s）
- **控制器不可用**：agent 沿用最后一次成功结果；重启后从 `/run/egress-proxy/policy-cache.json` 恢复
- **首次启动就拿不到策略**：退回配置文件里的 `targets` 全量直通并告警，避免一次 RBAC 配错打死全集群出网

### 5.4 安全：给 WebUI 加令牌

WebUI 能直接改出网策略，生产环境请注入令牌（未配置时接口不校验，日志会 WARN）：

```bash
kubectl -n egress-proxy create secret generic egress-proxy-controller-token \
  --from-literal=token="$(head -c 24 /dev/urandom | base64)"
kubectl -n egress-proxy rollout restart deploy/egress-proxy-controller
```

令牌会同时注入 controller、DaemonSet 与 forwarder，三者自动握手，无需额外配置。

## 6. 上线验收清单

| # | 检查项 | 命令 / 判定标准 |
| --- | --- | --- |
| a | apply 后节点上的规则符合预期 | 在任意工作节点执行 `iptables -t nat -S EGRESS-PROXY`，每条 target 应有 `-d <目标IP> -p tcp --dport <port> -j DNAT --to-destination <代理节点IP>:<proxyPort>`，条数与解析出的 IP 数一致 |
| b | 测试 Pod 访问目标成功且代理节点可见连接 | 测试 Pod 内 `curl -v https://a.example.com`（或 `nc -zv <目标IP> <port>`）成功；同时 `kubectl logs -n egress-proxy deploy/egress-proxy-tcp-forwarder` 中能看到对应 proxyPort 的连接记录，`ss -tnp \| grep 20001` 能看到 ESTABLISHED |
| c | 未触碰其他链 | 与部署前对比：`iptables-save -t nat > /tmp/nat-after.txt`，`diff` 后除新增的 `EGRESS-PROXY` 链与其 jump 规则外无其他差异（`-A PREROUTING/-A OUTPUT` 之外的内置链内容必须保持一致） |
| d | 增删 target 后规则与监听端口按周期更新 | 在 ConfigMap 中增/删一条 target，等待 `resolveInterval`/`configInterval`（默认 30s/2s）后，`iptables -t nat -S EGRESS-PROXY` 与代理节点 `ss -lntp \| grep <proxyPort>` 同步变化 |
| e | 网络策略/防火墙放行 | 放行 `Pod CIDR → 代理节点IP : proxyPort 段（如 20001-20010）`，以及各工作节点 → 代理节点该端口段；否则 DNAT 后连接会超时 |
| f | 删除 DaemonSet 后链被清理 | `kubectl delete -f deploy/base/10-daemonset.yaml`（用 kustomize 时可 `kubectl delete -k deploy/`，会连同 ConfigMap 与 Deployment 一起删除），等 Pod Terminating 完成后在节点上执行 `iptables -t nat -S EGRESS-PROXY`，应提示链不存在；同时业务直连上游恢复正常 |
| g | 代理节点上也运行 agent，且角色判定正确 | 代理节点上 `iptables -t nat -S PREROUTING \| grep EGRESS-PROXY` 应有跳转（本节点 Pod 仍需被重定向），但 `iptables -t nat -S OUTPUT \| grep EGRESS-PROXY` 应为**空**（agent 在代理节点上主动摘除 OUTPUT 跳转，避免 forwarder 自身出站被再次 DNAT 成环）；普通工作节点上两条跳转都存在。`kubectl -n egress-proxy get pod -o wide` 应看到代理节点上同时运行 redirect-agent 与 tcp-forwarder 两个 Pod |

## 7. 日常运维

```bash
# 查看节点上的 DNAT 规则（默认链名 EGRESS-PROXY，按 options.chainName 调整）
iptables -t nat -S EGRESS-PROXY
iptables -t nat -L EGRESS-PROXY -n -v --line-numbers

# 查看 redirect-agent 日志（每个节点一个 Pod）
kubectl logs -n egress-proxy ds/egress-proxy-redirect-agent
kubectl logs -n egress-proxy ds/egress-proxy-redirect-agent --tail=200

# 查看转发服务日志（连接建立、拨号失败都在这里）
kubectl logs -n egress-proxy deploy/egress-proxy-tcp-forwarder

# 健康检查（在代理节点上执行；hostNetwork，因此直接访问节点 IP:18081）
curl -sS http://<代理节点IP>:18081/healthz
curl -sS http://<代理节点IP>:18081/readyz

# 查看当前生效配置
kubectl -n egress-proxy get cm egress-proxy-config -o go-template='{{ index .data "config.yaml" }}'

# 新增目标：编辑 ConfigMap 的 config.yaml，追加一条 target（分配一个未被占用的 proxyPort）
kubectl -n egress-proxy edit cm egress-proxy-config
# 之后：forwarder 监听新端口（configInterval，默认 2s）、agent 生成新规则（configInterval + resolveInterval）
iptables -t nat -S EGRESS-PROXY | grep 20007          # 在新端口生效后确认（示例端口）

# 删除目标：从 ConfigMap 删掉对应 target，规则与监听端口会自动回收
# 注意：已建立的连接依赖 conntrack 继续可用；新建连接会改为直连目标
#      （若企业防火墙只放行代理节点出口，删除目标后将无法直连，请在低峰期操作）
```

ConfigMap 热加载链路：`kubectl apply/edit` → kubelet 同步到 Pod 内文件（**数秒 ~ 1 分钟**）
→ 两个组件按 `options.configInterval`（默认 2s）读取新内容并生效；**无需重启 Pod**。

## 8. 回滚与卸载

```bash
# 1) 摘掉重定向：删除 DaemonSet 即可，agent 收到 SIGTERM 后清理自己创建的规则与链
kubectl delete -f deploy/base/10-daemonset.yaml
# 或只回滚某几个节点：
kubectl -n egress-proxy delete pod <redirect-agent-pod>

# 2) 确认节点上规则已消失（链不存在 = 已清理干净）
iptables -t nat -S EGRESS-PROXY     # 期望：No chain/target/match by that name

# 3) 彻底卸载（代理服务与配置一起删掉）
kubectl delete -k deploy/
```

删除 DaemonSet 后流量立刻恢复**直连**上游，业务无需改配置；若节点上残留了规则
（例如进程被 `kill -9`、或被 `--force --grace-period=0` 强删而跳过了优雅退出），
可按下面顺序在对应节点手工清理（**只动专属链**）：先删跳转规则再删链——
链仍被引用时 `-X` 会报错，所以顺序不能反：

```bash
iptables -t nat -D PREROUTING -m comment --comment "egress-proxy" -j EGRESS-PROXY 2>/dev/null || true
iptables -t nat -D OUTPUT -m comment --comment "egress-proxy" -j EGRESS-PROXY 2>/dev/null || true
iptables -t nat -F EGRESS-PROXY && iptables -t nat -X EGRESS-PROXY
iptables -t nat -S EGRESS-PROXY            # 期望：No chain/target/match by that name
```

## 9. 已知限制

- **仅支持 IPv4 + TCP**：IPv6、UDP、ICMP 不会被重定向
- **代理节点是单点**：`tcp-forwarder` 只有 1 副本且绑定固定节点，该节点故障会导致所有
  被代理的流量中断；如需高可用，请自行扩展为多代理节点 + 客户端侧分流（当前版本不支持）
- **解析时间差**：Pod 内业务自己做的 DNS 解析与节点上 agent 的解析结果可能存在秒级差异，
  目标域名使用 GeoDNS / 多 IP 轮询时，Pod 可能连到尚未被代理的 IP
- **代理节点上的 hostNetwork Pod 出站不经代理**：agent 在「本节点即代理节点」时会跳过
  自身规则，代理节点上以 hostNetwork 运行的 Pod 直连外部目标，不受本方案影响
- **kube-proxy legacy 后端**：节点上 kube-proxy 使用 legacy 后端时，必须把
  `options.iptablesBinary` 设为 `iptables-legacy`，否则规则写入的 nft 表与 kube-proxy
  实际使用的表不一致，表现为 Pod 白名单放行异常或规则不生效
- **端口规划**：每个 target 需要一个代理节点上的独占 `proxyPort`，目标很多时请预先规划端口段
  （示例使用 20001-20006）
- **四元组的授权粒度是「IP + 端口」**：域名只是生成 IP 的输入；DNS 多 A 记录 / GeoDNS 下，
  Pod 可能连到规则未覆盖的 IP（与改造前的限制同源，但影响更大，因为现在是默认拒绝）
- **「默认拒绝」是 target 维度，不是 pod 维度**：只有**在策略里登记过的 target**
  （`host + port`）才会被纳入管控——未登记的地址/端口完全不经过我们的链，
  等同于本组件不存在（能否连通取决于集群网络与 NetworkPolicy）。
  如果要「某个 Pod 只能访问白名单、其余全禁」，请用 NetworkPolicy 做总体出站白名单，
  不要指望四元组策略承担全量防火墙职责
- **直连 `代理节点IP:proxyPort` 可绕过 payload 判定**：`tcp-forwarder` 不校验客户端身份。
  建议用 NetworkPolicy 限制「Pod → 代理节点 20001-20099」的来源，或在 forwarder 增加二次校验（后续版本）
- **Pod IP 复用窗口**：删除的 Pod 的 IP 可能在下一轮 Pod 索引刷新（`-pod-interval`，默认 5s）
  之前就被新 Pod 复用，该窗口内新 Pod 会继承旧授权
- **hostNetwork Pod**：源地址就是节点 IP，按标签仍能被 payload 选中，但授权会随之放大成「这个节点 IP 可访问」——
  同一节点上的其他 hostNetwork 进程也会跟着被放行
- **存量连接不受策略变更影响**：conntrack 优先于 nat/filter，收回授权不会断开已建立的连接

## 10. 故障排查

| 现象 | 排查方向 |
| --- | --- |
| **日志里没有 `version=` 字段，或 `version=dev`** | 节点上跑的是旧镜像；镜像 tag 没变时（`imagePullPolicy: IfNotPresent`）kubelet 不会重新拉取，`kubectl apply` 也不会滚动更新 Pod；**必须换 tag**（`deploy/kustomization.yaml` 的 `newTag`）或 `kubectl -n egress-proxy rollout restart` 并确认节点上已导入新镜像 |
| **controller 报 `x509: certificate signed by unknown authority`** | 旧版本没有加载集群 CA；新版本默认 `-insecure-skip-verify=true`（跳过校验）；启动日志可见 `insecureSkipVerify=true` |
| **forwarder/agent 卡在「等待配置文件」且报 `targets 不能为空`** | 旧版本把 targets 当必填；新版本允许 `targets: []`（四元组模式下目标由控制器下发），启动日志会打印 `targets=0 policyUrl=...` |
| `iptables -t nat -S EGRESS-PROXY` 有规则，但 Pod 仍直连 | 检查 iptables 后端是否一致：节点上 `iptables -V`、`iptables-legacy -V`、`update-alternatives --list iptables`，以及 kube-proxy 日志中使用的后端；若 kube-proxy 是 legacy，请把 `options.iptablesBinary` 改为 `iptables-legacy`；另外确认目标 IP 是否落在 `options.excludeCIDRs` 或 Pod/Service CIDR 内 |
| 规则存在，连接超时 | 检查 DNAT 目标 `proxy.address` 是否就是运行 `tcp-forwarder` 的代理节点 IP；`kubectl -n egress-proxy get pod -o wide` 看 forwarder 落在哪台节点；检查该节点上端口段是否被放行（见第 1 节与验收清单 e） |
| 代理节点端口被占用（Pod CrashLoop，日志报 address already in use） | 代理节点上 `ss -lntp \| grep <proxyPort>` 找出占用者；给每条 target 换一个空闲 `proxyPort`，并同步修改 ConfigMap 与该端口冲突的业务 |
| Pod 与节点 DNS 解析结果不一致 | 目标域名多 A 记录 / 智能解析时属正常现象，可调小 `options.resolveInterval`、调大 `options.maxIPsPerHost`，或把目标直接写成固定 IPv4（多写几条 target 覆盖各个 IP） |
| agent 无法创建规则（权限/xtables 相关报错） | 看 `kubectl logs -n egress-proxy ds/egress-proxy-redirect-agent`；确认 Pod 已获得 `NET_ADMIN`/`NET_RAW`、`/run` 为可写 emptyDir；仍失败时可在 `deploy/base/10-daemonset.yaml` 中把容器 `securityContext` 退回 `privileged: true` |
| 规则被其他工具改掉 | agent 会在 `options.syncInterval`（默认 60s）内自检并修复；如持续被覆盖，检查节点上是否有其他 iptables 管理组件在清理自定义链 |
