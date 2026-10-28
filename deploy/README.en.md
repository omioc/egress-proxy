**English** | [中文](README.md)

# Deployment and operations manual

This document is the detailed guide to the `deploy/` directory: pre-deployment preparation, image
preparation, configuration fields, 4-tuple enforcement and the WebUI, go-live acceptance, day-to-day
operations, rollback and uninstall, known limitations, and troubleshooting.

See `README.md` (Chinese) or `README.en.md` in the repository root for the project overview, architecture diagram and component responsibilities.

> Image names in this document are always written as `<registry>/egress-proxy/redirect-agent:0.1.6`.
> **Replace `<registry>` with your own image registry address** (for example `harbor.example.com`).

---

## 1. Pre-deployment preparation

| Item | Requirement |
| --- | --- |
| Proxy node | Must be a **worker node** (Pods on that node must be able to reach the internet normally), with a stable IP, and labeled `egress-proxy=true` |
| Node networking | Both `redirect-agent` and `tcp-forwarder` use `hostNetwork`; the proxy node must be reachable from all worker nodes on the `proxyPort` range |
| Port planning | Each target occupies a **dedicated** `proxyPort` on the proxy node (20001-20006 in the examples); `options.healthPort` defaults to 18081; the controller is exposed on 18082 |
| iptables backend | `options.iptablesBinary` must match the backend actually used by kube-proxy on the node (use `iptables-legacy` for the legacy backend), otherwise rules are written to the wrong table and appear to exist while traffic is not redirected |
| Firewall / NetworkPolicy | Allow `Pod CIDR → proxy-node-ip : proxyPort range` (for example 20001-20010), and each worker node → the proxy node on that port range; otherwise connections time out after DNAT |
| In-cluster permissions | The DaemonSet needs `NET_ADMIN` and `NET_RAW`, and `/run` must be a writable `emptyDir` (already configured in the manifest) |

```bash
# label the proxy node (order matters: must be before apply)
kubectl label node <node> egress-proxy=true
```

## 2. Image preparation

### 2.1 Build and push directly

```bash
docker build -f Dockerfile.agent -t <registry>/egress-proxy/redirect-agent:0.1.6 .
docker build -f Dockerfile.proxy -t <registry>/egress-proxy/tcp-forwarder:0.1.6 .
docker build -f Dockerfile.controller -t <registry>/egress-proxy/controller:0.1.6 .
docker push <registry>/egress-proxy/redirect-agent:0.1.6
docker push <registry>/egress-proxy/tcp-forwarder:0.1.6
docker push <registry>/egress-proxy/controller:0.1.6
```

Dependencies are fetched from `GOPROXY` according to `go.sum` (the repository has no `vendor/`); the
Dockerfile defaults to `ARG GOPROXY=https://goproxy.cn,direct`, which you can override with
`--build-arg GOPROXY=...`. The build stage runs `COPY go.mod go.sum` before `go mod download`, so the
dependency layer hits the build cache.

### 2.2 Offline packaging (Windows / PowerShell 7)

```bash
# build and export the three tar files into deploy/ (image names carry no registry prefix)
pwsh ./scripts/build-images.ps1 -Tag 0.1.6
# optional flags: -OutputDir <dir>, -Platform linux/arm64, -NoCache, -GoProxy <module proxy>, -SkipBuild (export existing images only)
```

Copy the tar files to the node and import them (image names carry no prefix; the prefix is already
specified in the `images` section of `deploy/kustomization.yaml`):

```bash
docker load -i redirect-agent-0.1.6.tar      # Docker runtime
ctr -n k8s.io images import redirect-agent-0.1.6.tar   # containerd runtime
nerdctl -n k8s.io load -i redirect-agent-0.1.6.tar     # nerdctl works too
```

## 3. Deployment: realistically only two files need changing

| File to change | What to change |
| --- | --- |
| `deploy/config.yaml` | Runtime configuration: `proxy.address` (proxy node IP) + `targets` (list of external targets); the kustomization `configMapGenerator` packages it into `data["config.yaml"]` of ConfigMap `egress-proxy-config`, mounted into the Pod at `/etc/egress-proxy/config.yaml` — what you edit is exactly what the Pod sees |
| `deploy/kustomization.yaml` | Image addresses: `newName` / `newTag` in the `images` section; this single place applies to both the DaemonSet and the Deployment |

After editing, a single command is enough (no Pod restart needed — both components hot-reload the
mounted file by polling at `options.configInterval`):

```bash
kubectl apply -k deploy/        # render and apply
kubectl kustomize deploy/       # render only, no apply; confirm the final effective manifest
kubectl delete -k deploy/       # delete in reverse
kubectl -n egress-proxy get ds,deploy,pod -o wide
```

Example `images` section (`name` must exactly match the placeholder image name in `deploy/base/*.yaml`,
otherwise kustomize **silently skips the replacement** — `internal/deploycheck/kustomization_test.go`
guards this specific rule):

```yaml
images:
  - name: redirect-agent
    newName: harbor.example.com/egress-proxy/redirect-agent   # for the image imported from tar, just write redirect-agent
    newTag: "0.1.0"
  - name: tcp-forwarder
    newName: harbor.example.com/egress-proxy/tcp-forwarder
    newTag: "0.1.0"
  - name: controller
    newName: harbor.example.com/egress-proxy/controller
    newTag: "0.1.0"
```

Background: native Kubernetes YAML **does not support** variables or references (`kubectl apply -f`
only parses text), so "configure in one place only" relies on the kustomize built into kubectl. If you
need template features such as "one variable driving multiple images", use Helm instead. The old path
`kubectl apply -f deploy/base/` still works, but it does not generate the ConfigMap and uses the
placeholder image names, so it is not recommended.

Deployment order matters: **label first, then change `proxy.address`, then apply**; otherwise the
forwarder may stay Pending because `nodeSelector` cannot find a node, or DNAT may point at an IP with
no listening service.

## 4. Configuration fields

`proxy` section:

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `proxy.address` | string | none (required) | Proxy node IP (IPv4), i.e. the `--to-destination` host of the DNAT; must be the IP of a node labeled `egress-proxy=true` |
| `proxy.listen` | string | `0.0.0.0` | `tcp-forwarder` listen address; keep `0.0.0.0`, otherwise DNAT'd traffic from worker nodes may fail to connect |

`targets` section (an array, one mapping per entry; multiple ports on the same host must be split into
separate entries):

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `targets[].host` | string | none (required) | Target domain name or IPv4 literal (only IPv4 takes effect) |
| `targets[].port` | int | none (required) | Original target port, also the port the forwarder dials when forwarding |
| `targets[].proxyPort` | int | none (required) | **Unique** listen port on the proxy node; must not repeat and must not conflict with existing services on the node |

`options` section (all optional; omit to use the defaults):

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `options.resolveInterval` | duration | `30s` | Domain re-resolution period; DNAT rules are rebuilt when the resolution result changes |
| `options.configInterval` | duration | `2s` | Configuration file polling interval (the ConfigMap hot reload depends on it) |
| `options.syncInterval` | duration | `60s` | Rule drift self-check period; externally detected changes are repaired |
| `options.dialTimeout` | duration | `5s` | Timeout for `tcp-forwarder` dialing the original target |
| `options.maxIPsPerHost` | int | `8` | Maximum number of rule IPs maintained per domain (prevents rule explosion from DNS round-robin) |
| `options.iptablesBinary` | string | `iptables` | iptables frontend to use; may be `iptables-legacy`; must match the node's kube-proxy backend |
| `options.chainName` | string | `EGRESS-PROXY` | Dedicated chain name; the agent only adds and removes rules within this chain |
| `options.healthPort` | int | `18081` | Port for `tcp-forwarder` `/healthz` and `/readyz`; must match the probe port |
| `options.dnsServers` | []string | `[]` (use system DNS) | Override the default DNS servers, for example `["10.96.0.10"]` |
| `options.excludeCIDRs` | []string | `[]` | CIDRs to exclude (such as the cluster Pod/Service CIDRs); matches generate no rules |
| `options.policyUrl` | string | `""` | Controller address; filling it in enables 4-tuple enforcement, leaving it empty keeps the legacy "pass everything listed in this file's `targets`" behavior |
| `options.policyInterval` | duration | `2s` | Period for pulling policy from the controller (4-tuple mode) |

## 5. 4-tuple traffic enforcement (payload-level authorization + WebUI)

Once enabled, a rule changes from "target + target port + proxy port" to
"**payload** + target + target port + proxy port", and **unauthorized payloads are rejected outright**
(they do not fall back to a direct connection).

```yaml
# deploy/config.yaml: set the controller address to enable; leave empty to keep the old pass-everything behavior
options:
  policyUrl: http://egress-proxy-controller.egress-proxy.svc:18082
  policyInterval: 2s
```

Once enabled, `targets` may be left entirely empty (`targets: []`); targets and authorizations are all
configured in the WebUI, and the agent and forwarder pull them from the controller at
`policyInterval`.

| Component | Role in 4-tuple mode |
| --- | --- |
| `egress-proxy-controller` | New: policy storage (ConfigMap `egress-proxy-policy`), Pod resolution, per-node compilation, REST API + built-in WebUI |
| `redirect-agent` | Pulls the compiled result and generates DNAT and reject rules using **source address matching** |
| `tcp-forwarder` | Pulls the target list and maintains `proxyPort` → `host:port` listeners |

### 5.1 Opening the WebUI

**Option 1: port-forward from a machine that can reach the cluster (safest)**

```bash
kubectl -n egress-proxy port-forward svc/egress-proxy-controller 18082:18082
# then open http://localhost:18082 on this machine
```

**Option 2: access the node IP directly from your own laptop**

`kubectl port-forward` listens only on `127.0.0.1` by default (the log shows
`Forwarding from 127.0.0.1:18082`), so accessing `http://<node-ip>:18082` from another machine gives
`ERR_CONNECTION_REFUSED`; add `--address 0.0.0.0`:

```bash
kubectl -n egress-proxy port-forward --address 0.0.0.0 svc/egress-proxy-controller 18082:18082
# then open http://<that-node-ip>:18082 (the node firewall must allow it)
```

**Option 3: switch to NodePort (for long-term use — configure once, no permanent port-forward)**

```bash
kubectl -n egress-proxy patch svc egress-proxy-controller -p \
  '{"spec":{"type":"NodePort","ports":[{"name":"http","port":18082,"targetPort":"http","nodePort":30082}]}}'
# then open http://<any-node-ip>:30082
```

> The controller is an ordinary Pod (ClusterIP) and will **not** listen on a node IP, so accessing
> `<node-ip>:18082` directly always fails with connection refused.
> Before exposing the WebUI to the node network, create the token Secret first (see 5.4), otherwise
> anyone on the same network can change the egress policy.

**UI language and theme** (auto-detected, and overridable):

- **Language**: chosen from the browser language on first load — `zh` / `zh-*` renders Chinese, anything else renders English; the `中` / `EN` button in the top-right switches at any time, and the choice is stored in browser localStorage (`egp_lang`)
- **Theme**: **follows the system** by default (`prefers-color-scheme`) and updates immediately when the OS switches between light and dark; the sun/moon button cycles through follow-system → light → dark, and a manual choice is stored in localStorage (`egp_theme`)
- **Temporary override** (handy for shared links or screenshots): `?lang=zh|en` and `?theme=auto|light|dark`, e.g. `http://localhost:18082/?lang=en&theme=dark`; a URL parameter is written to localStorage and reused on the next visit
- **API messages**: validation errors and warnings follow the `Accept-Language` request header (`zh*` → Chinese, anything else → English, Chinese by default); the WebUI sends it with the current UI language, while plain `curl` without the header gets Chinese
- **Logs and CLI**: `-lang zh|en` or the `EGRESS_LANG` environment variable sets the language of logs, `-h` help and config-file parsing errors (Chinese by default); add the variable to the DaemonSet / Deployment and roll it out to switch

### 5.2 What to do on the page

Spread across three tabs (fixed order: external services → authorization matrix → runtime status):

- **External services**: maintain `host` / `port` / `proxyPort`, and see how many workloads reference
  each service plus the effective source addresses
- **Authorization matrix**: select a workload on the left, check the external services it may access on
  the right; there are two ways to select a workload — by workload name (pick a `Deployment` /
  `StatefulSet` / `DaemonSet` from the dropdown; the controller reads its
  `spec.selector.matchLabels` with read-only permissions), or by label selector (type `k=v` manually);
  the namespace is likewise a dropdown; checking takes effect immediately, no save required
- **Runtime status**: switch the enforcement mode (`disabled` / `observe` / `enforce`), view the apply
  and sync status of the agent on each node, policy alerts, and controller connectivity; the page
  supports light / dark themes, and the top bar shows "refreshed N seconds ago"

### 5.3 Semantics quick reference

- **payload** = the set of IPs of Pods in a given namespace that match a set of labels; the labels come
  from the "selected workload" or a manually entered label selector; both are resolved into concrete
  `matchLabels` and written into the policy when saved, so reads no longer depend on the apiserver
- **A target with no authorization = nobody can reach it** (default deny), not "anyone can connect"
- **Policy changes only modify the contents of the sub-chain**; the rule structure stays the same; the
  effective time is ≈ `policyInterval` (2s by default)
- **Controller unavailable**: the agent keeps using the last successful result; after a restart it
  recovers from `/run/egress-proxy/policy-cache.json`
- **No policy available on first start**: fall back to passing everything listed in the configuration
  file's `targets` and raise an alert, so one RBAC misconfiguration does not kill egress for the whole
  cluster

### 5.4 Security: adding a token to the WebUI

The WebUI can change the egress policy directly, so inject a token in production (when unset the API
performs no checks and the log emits a WARN):

```bash
kubectl -n egress-proxy create secret generic egress-proxy-controller-token \
  --from-literal=token="$(head -c 24 /dev/urandom | base64)"
kubectl -n egress-proxy rollout restart deploy/egress-proxy-controller
```

The token is injected into the controller, the DaemonSet and the forwarder alike; the three handshake
automatically, with no extra configuration.

## 6. Go-live acceptance checklist

| # | Check | Command / pass criteria |
| --- | --- | --- |
| a | Rules on the node match expectations after apply | On any worker node run `iptables -t nat -S EGRESS-PROXY`; each target should have `-d <target-ip> -p tcp --dport <port> -j DNAT --to-destination <proxy-node-ip>:<proxyPort>`, and the count should match the number of resolved IPs |
| b | A test Pod reaches the target and the proxy node shows the connection | Inside the test Pod `curl -v https://a.example.com` (or `nc -zv <target-ip> <port>`) succeeds; at the same time `kubectl logs -n egress-proxy deploy/egress-proxy-tcp-forwarder` shows a connection record for the corresponding proxyPort, and `ss -tnp \| grep 20001` shows ESTABLISHED |
| c | No other chains were touched | Compare with pre-deployment state: `iptables-save -t nat > /tmp/nat-after.txt`; after `diff` there should be no differences other than the newly added `EGRESS-PROXY` chain and its jump rules (the contents of built-in chains other than `-A PREROUTING/-A OUTPUT` must stay identical) |
| d | Rules and listen ports update on schedule after adding or removing a target | Add/remove a target in the ConfigMap; after waiting `resolveInterval`/`configInterval` (30s/2s by default), `iptables -t nat -S EGRESS-PROXY` and `ss -lntp \| grep <proxyPort>` on the proxy node change in sync |
| e | Network policy / firewall allows the traffic | Allow `Pod CIDR → proxy-node-ip : proxyPort range (e.g. 20001-20010)`, and each worker node → the proxy node on that port range; otherwise connections time out after DNAT |
| f | The chain is cleaned up after deleting the DaemonSet | `kubectl delete -f deploy/base/10-daemonset.yaml` (with kustomize you can use `kubectl delete -k deploy/`, which also deletes the ConfigMap and the Deployment); once the Pods finish Terminating, run `iptables -t nat -S EGRESS-PROXY` on the node and it should report the chain does not exist; application traffic to upstream directly should also recover |
| g | The agent also runs on the proxy node, with the correct role detection | On the proxy node, `iptables -t nat -S PREROUTING \| grep EGRESS-PROXY` should show a jump (Pods on this node still need redirection), but `iptables -t nat -S OUTPUT \| grep EGRESS-PROXY` should be **empty** (the agent removes the OUTPUT jump on the proxy node so the forwarder's own egress is not DNAT'd again into a loop); on ordinary worker nodes both jumps exist. `kubectl -n egress-proxy get pod -o wide` should show both the redirect-agent and tcp-forwarder Pods running on the proxy node |

## 7. Day-to-day operations

```bash
# view the DNAT rules on the node (default chain EGRESS-PROXY, adjust per options.chainName)
iptables -t nat -S EGRESS-PROXY
iptables -t nat -L EGRESS-PROXY -n -v --line-numbers

# view redirect-agent logs (one Pod per node)
kubectl logs -n egress-proxy ds/egress-proxy-redirect-agent
kubectl logs -n egress-proxy ds/egress-proxy-redirect-agent --tail=200

# view forwarder logs (connection setup and dial failures are all here)
kubectl logs -n egress-proxy deploy/egress-proxy-tcp-forwarder

# health check (run on the proxy node; hostNetwork, so hit the node IP:18081 directly)
curl -sS http://<proxy-node-ip>:18081/healthz
curl -sS http://<proxy-node-ip>:18081/readyz

# view the currently effective configuration
kubectl -n egress-proxy get cm egress-proxy-config -o go-template='{{ index .data "config.yaml" }}'

# add a target: edit config.yaml in the ConfigMap and append one target (assign an unused proxyPort)
kubectl -n egress-proxy edit cm egress-proxy-config
# afterwards: the forwarder listens on the new port (configInterval, 2s default) and the agent generates new rules (configInterval + resolveInterval)
iptables -t nat -S EGRESS-PROXY | grep 20007          # confirm once the new port takes effect (example port)

# remove a target: delete the corresponding target from the ConfigMap; rules and listen ports are reclaimed automatically
# note: established connections keep working via conntrack; new connections will go directly to the target
#      (if the corporate firewall only allows egress via the proxy node, direct connections will fail after removing the target; do this off-peak)
```

ConfigMap hot-reload path: `kubectl apply/edit` → kubelet syncs the file into the Pod (**a few seconds
to ~1 minute**) → both components read the new content at `options.configInterval` (2s by default) and
apply it; **no Pod restart required**.

## 8. Rollback and uninstall

```bash
# 1) remove redirection: deleting the DaemonSet is enough; on SIGTERM the agent cleans up the rules and chain it created
kubectl delete -f deploy/base/10-daemonset.yaml
# or roll back only a few nodes:
kubectl -n egress-proxy delete pod <redirect-agent-pod>

# 2) confirm the rules are gone from the node (chain missing = cleaned up)
iptables -t nat -S EGRESS-PROXY     # expected: No chain/target/match by that name

# 3) full uninstall (delete the proxy service together with its configuration)
kubectl delete -k deploy/
```

After deleting the DaemonSet, traffic immediately reverts to connecting **directly** to upstream, with
no application configuration changes needed. If rules are left behind on a node (for example the
process was `kill -9`ed, or force-deleted with `--force --grace-period=0` so the graceful shutdown was
skipped), clean them up manually on the affected node in the following order (**touch only the
dedicated chain**): delete the jump rules first, then the chain — `-X` errors while the chain is still
referenced, so the order cannot be reversed:

```bash
iptables -t nat -D PREROUTING -m comment --comment "egress-proxy" -j EGRESS-PROXY 2>/dev/null || true
iptables -t nat -D OUTPUT -m comment --comment "egress-proxy" -j EGRESS-PROXY 2>/dev/null || true
iptables -t nat -F EGRESS-PROXY && iptables -t nat -X EGRESS-PROXY
iptables -t nat -S EGRESS-PROXY            # expected: No chain/target/match by that name
```

## 9. Known limitations

- **IPv4 + TCP only**: IPv6, UDP and ICMP are not redirected
- **The proxy node is a single point of failure**: `tcp-forwarder` has only one replica bound to a fixed
  node; if that node fails, all proxied traffic is interrupted. For high availability, extend to
  multiple proxy nodes plus client-side sharding (not supported in the current version)
- **Resolution time skew**: DNS resolution performed by applications inside the Pod and by the agent on
  the node may differ by seconds; when the target domain uses GeoDNS / multiple-IP round-robin, a Pod
  may connect to an IP that is not yet proxied
- **hostNetwork Pods on the proxy node do not egress through the proxy**: when the agent sees that "this
  node is the proxy node" it skips its own rules; Pods running with hostNetwork on the proxy node
  connect directly to external targets and are not affected by this solution
- **kube-proxy legacy backend**: when kube-proxy on the node uses the legacy backend, you must set
  `options.iptablesBinary` to `iptables-legacy`; otherwise rules are written to the nft table while
  kube-proxy actually uses a different table, which shows up as Pod allowlist rules failing or rules
  not taking effect
- **Port planning**: each target needs an exclusive `proxyPort` on the proxy node; plan port ranges in
  advance when there are many targets (the examples use 20001-20006)
- **4-tuple authorization granularity is "IP + port"**: the domain name is only an input for generating
  IPs; with DNS multiple A records / GeoDNS, a Pod may connect to an IP not covered by the rules (the
  same root cause as the limitation before the change, but with greater impact since the default is now
  deny)
- **"Default deny" operates at the target dimension, not the pod dimension**: only **targets registered
  in the policy** (`host + port`) are subject to enforcement — unregistered addresses/ports bypass our
  chain entirely and behave as if this component did not exist (connectivity then depends on cluster
  networking and NetworkPolicy). If you want "a given Pod may only reach an allowlist, everything else
  is blocked", use NetworkPolicy for the overall egress allowlist; do not expect 4-tuple policy to take
  on the role of a full firewall
- **Connecting directly to `proxy-node-ip:proxyPort` bypasses payload evaluation**: `tcp-forwarder` does
  not verify client identity. Use NetworkPolicy to restrict "Pod → proxy node 20001-20099" by source, or
  add secondary verification in the forwarder (future version)
- **Pod IP reuse window**: the IP of a deleted Pod may be reused by a new Pod before the next Pod index
  refresh (`-pod-interval`, 5s by default); within that window the new Pod inherits the old
  authorization
- **hostNetwork Pods**: the source address is the node IP; they can still be selected by payload via
  labels, but the authorization is then magnified into "this node IP can access it" — other hostNetwork
  processes on the same node are allowed along with it
- **Existing connections are unaffected by policy changes**: conntrack takes precedence over nat/filter;
  revoking authorization does not tear down established connections

## 10. Troubleshooting

| Symptom | What to check |
| --- | --- |
| **No `version=` field in the log, or `version=dev`** | An old image is running on the node; when the image tag is unchanged (`imagePullPolicy: IfNotPresent`) kubelet does not re-pull and `kubectl apply` does not roll the Pods, so **you must change the tag** (`newTag` in `deploy/kustomization.yaml`) or run `kubectl -n egress-proxy rollout restart`, and confirm the new image has been imported on the node |
| **controller reports `x509: certificate signed by unknown authority`** | Older versions did not load the cluster CA; newer versions default to `-insecure-skip-verify=true` (skip verification) and the startup log shows `insecureSkipVerify=true` |
| **forwarder/agent is stuck at "waiting for configuration file" and reports that `targets` must not be empty** | Older versions treated targets as required; newer versions allow `targets: []` (in 4-tuple mode targets come from the controller), and the startup log prints `targets=0 policyUrl=...` |
| `iptables -t nat -S EGRESS-PROXY` has rules, but Pods still connect directly | Check whether the iptables backend matches: `iptables -V`, `iptables-legacy -V`, `update-alternatives --list iptables` on the node, and the backend used in the kube-proxy log; if kube-proxy uses legacy, change `options.iptablesBinary` to `iptables-legacy`; also confirm the target IP does not fall inside `options.excludeCIDRs` or the Pod/Service CIDRs |
| Rules exist but connections time out | Check whether the DNAT target `proxy.address` is the proxy node IP actually running `tcp-forwarder`; use `kubectl -n egress-proxy get pod -o wide` to see which node the forwarder is on; check that the port range is allowed on that node (see section 1 and acceptance check e) |
| Port on the proxy node is occupied (Pod CrashLoop, log reports address already in use) | Find the occupier on the proxy node with `ss -lntp \| grep <proxyPort>`; assign a free `proxyPort` to each target and update the ConfigMap as well as the conflicting service |
| Pod and node DNS resolution results differ | Normal behavior with multiple A records / smart DNS for the target domain; reduce `options.resolveInterval`, increase `options.maxIPsPerHost`, or write the target as fixed IPv4 directly (add several targets to cover individual IPs) |
| agent cannot create rules (permission/xtables related errors) | Check `kubectl logs -n egress-proxy ds/egress-proxy-redirect-agent`; confirm the Pod has `NET_ADMIN`/`NET_RAW` and that `/run` is a writable emptyDir; if it still fails you can set the container `securityContext` in `deploy/base/10-daemonset.yaml` back to `privileged: true` |
| Rules are changed by other tools | The agent self-checks and repairs within `options.syncInterval` (60s by default); if they keep being overwritten, check whether another iptables management component on the node is cleaning up custom chains |
