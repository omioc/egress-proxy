#!/usr/bin/env bash
# =============================================================================
# egress-proxy 本机端到端冒烟测试（非集群环境，Linux + Go 工具链）
#
# 做三件事：
#   1) 编译 redirect-agent 与 tcp-forwarder 到临时目录；
#   2) 用 python3 -m http.server 模拟「外部目标」，启动 tcp-forwarder，
#      并通过代理端口访问该目标，验证「按端口转发到原始目标」成立；
#   3) 若当前是 root 且 iptables 可用，再把 redirect-agent 跑 3 秒，
#      检查专属链里出现 DNAT 规则，并在 SIGTERM 后确认链被自动清理
#
# 用法：
#   bash scripts/smoke-local.sh
#
# 可覆盖的环境变量：
#   SMOKE_CHAIN=EGRESS-PROXY-SMOKE   冒烟用专属链名
#   PROXY_PORT=20001                 代理监听端口（redirect-agent DNAT 目标端口）
#   HEALTH_PORT=18081                tcp-forwarder 健康检查端口
#   TARGET_PORT=18099                模拟外部目标端口（被占用时自动换随机端口）
#   SMOKE_AGENT_HOST_IP=127.0.0.1    跑 redirect-agent 时注入的 HOST_IP
#                                    （若实现会在「本节点即代理节点」时跳过装规则，
#                                     可改成 127.0.0.2 再试）
#
# 注意：脚本只操作 ${SMOKE_CHAIN} 这一条链，结束时用 -F/-X 兜底清理，
#       不会触碰节点上其他 iptables 链
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

SMOKE_CHAIN="${SMOKE_CHAIN:-EGRESS-PROXY-SMOKE}"
PROXY_PORT="${PROXY_PORT:-20001}"
HEALTH_PORT="${HEALTH_PORT:-18081}"
TARGET_PORT="${TARGET_PORT:-18099}"
AGENT_HOST_IP="${SMOKE_AGENT_HOST_IP:-127.0.0.1}"
SMOKE_BODY="egress-proxy-smoke-ok"

WORK_DIR=""
TARGET_PID=""
FORWARDER_PID=""
AGENT_PID=""

log() { echo "==> $*"; }
die() { echo "!!! $*" >&2; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- iptables 辅助
iptables_available() {
  have_cmd iptables || return 1
  iptables -t nat -S >/dev/null 2>&1
}

dump_smoke_chain() {
  iptables -t nat -S "${SMOKE_CHAIN}" 2>/dev/null || true
}

smoke_chain_exists() {
  iptables -t nat -L "${SMOKE_CHAIN}" -n >/dev/null 2>&1
}

remove_smoke_chain() {
  iptables_available || return 0
  iptables -t nat -F "${SMOKE_CHAIN}" 2>/dev/null || true
  iptables -t nat -X "${SMOKE_CHAIN}" 2>/dev/null || true
}

# ------------------------------------------------------------------- 通用工具
pick_free_port() {
  # 优先用 $1，若被占用则退化为内核分配的随机端口
  python3 - "$1" <<'PY'
import socket
import sys

preferred = int(sys.argv[1])
for port in (preferred, 0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError:
        s.close()
        continue
    print(s.getsockname()[1])
    s.close()
    sys.exit(0)
sys.exit(1)
PY
}

wait_for_http() {
  # wait_for_http <url> <名字> [最大尝试次数]
  local url="$1" name="$2" tries="${3:-40}" i
  for ((i = 1; i <= tries; i++)); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  echo "    等待 ${name} 就绪超时（${url}）" >&2
  return 1
}

cleanup() {
  local rc=$?
  echo
  echo "==> [清理] 停止后台进程、删除临时目录、兜底清理 iptables 链 ${SMOKE_CHAIN}"
  local pid
  for pid in "${AGENT_PID}" "${FORWARDER_PID}" "${TARGET_PID}"; do
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  remove_smoke_chain
  if [ -n "${WORK_DIR}" ] && [ -d "${WORK_DIR}" ]; then
    rm -rf "${WORK_DIR}"
  fi
  echo "==> [清理] 完成"
  exit "${rc}"
}
trap cleanup EXIT
# INT/TERM 时先设置退出码，再交由 EXIT 钩子统一清理一次（避免重复清理）
trap 'exit 130' INT TERM

# --------------------------------------------------------------------- 主流程
log "[1/6] 检查依赖：go / python3 / curl"
have_cmd go || die "未找到 go，请先安装 Go 工具链"
have_cmd python3 || die "未找到 python3"
have_cmd curl || die "未找到 curl"
log "    依赖检查通过：$(go version)"

log "[2/6] 编译两个二进制到临时目录"
WORK_DIR="$(mktemp -d)"
mkdir -p "${WORK_DIR}/bin" "${WORK_DIR}/www"
(cd "${PROJECT_DIR}" && go build -o "${WORK_DIR}/bin/redirect-agent" ./cmd/redirect-agent)
(cd "${PROJECT_DIR}" && go build -o "${WORK_DIR}/bin/tcp-forwarder" ./cmd/tcp-forwarder)
log "    redirect-agent: ${WORK_DIR}/bin/redirect-agent"
log "    tcp-forwarder : ${WORK_DIR}/bin/tcp-forwarder"

TARGET_PORT="$(pick_free_port "${TARGET_PORT}")" || die "无法分配模拟外部目标端口"
if [ "${TARGET_PORT}" != "18099" ]; then
  log "    注意：18099 被占用，模拟外部目标改用端口 ${TARGET_PORT}"
fi

log "[3/6] 启动模拟「外部目标」：python3 http.server 127.0.0.1:${TARGET_PORT}"
printf '%s\n' "${SMOKE_BODY}" >"${WORK_DIR}/www/smoke.txt"
python3 -m http.server "${TARGET_PORT}" --bind 127.0.0.1 \
  --directory "${WORK_DIR}/www" >"${WORK_DIR}/target.log" 2>&1 &
TARGET_PID=$!
if ! wait_for_http "http://127.0.0.1:${TARGET_PORT}/smoke.txt" "模拟外部目标" 20; then
  cat "${WORK_DIR}/target.log" || true
  die "模拟外部目标未启动成功"
fi

CONFIG_FILE="${WORK_DIR}/config.yaml"
cat >"${CONFIG_FILE}" <<EOF
# 本文件由 scripts/smoke-local.sh 自动生成，仅用于本机冒烟测试
proxy:
  address: "127.0.0.1"
  listen: "127.0.0.1"
targets:
  - host: 127.0.0.1
    port: ${TARGET_PORT}
    proxyPort: ${PROXY_PORT}
options:
  chainName: ${SMOKE_CHAIN}
  healthPort: ${HEALTH_PORT}
  resolveInterval: 5s
  configInterval: 1s
  syncInterval: 10s
  dialTimeout: 3s
  iptablesBinary: iptables
EOF
log "    临时配置：${CONFIG_FILE}"

log "[4/6] 启动 tcp-forwarder（HOST_IP=127.0.0.1），等待 /healthz、/readyz 就绪"
HOST_IP=127.0.0.1 "${WORK_DIR}/bin/tcp-forwarder" \
  -config "${CONFIG_FILE}" -log-level debug >"${WORK_DIR}/forwarder.log" 2>&1 &
FORWARDER_PID=$!
if ! wait_for_http "http://127.0.0.1:${HEALTH_PORT}/healthz" "tcp-forwarder /healthz"; then
  cat "${WORK_DIR}/forwarder.log" || true
  die "tcp-forwarder /healthz 未就绪"
fi
wait_for_http "http://127.0.0.1:${HEALTH_PORT}/readyz" "tcp-forwarder /readyz" 20 || {
  cat "${WORK_DIR}/forwarder.log" || true
  die "tcp-forwarder /readyz 未就绪"
}
log "    /healthz: $(curl -fsS "http://127.0.0.1:${HEALTH_PORT}/healthz")"
log "    /readyz : $(curl -fsS "http://127.0.0.1:${HEALTH_PORT}/readyz")"

log "[5/6] 通过代理端口 127.0.0.1:${PROXY_PORT} 访问外部目标，验证按端口转发"
BODY="$(curl -fsS --max-time 5 "http://127.0.0.1:${PROXY_PORT}/smoke.txt")" || {
  cat "${WORK_DIR}/forwarder.log" || true
  die "经由 ${PROXY_PORT} 访问失败"
}
if [ "${BODY}" != "${SMOKE_BODY}" ]; then
  die "转发返回内容不符合预期：期望 '${SMOKE_BODY}'，实际 '${BODY}'"
fi
if ! grep -q 'GET /smoke.txt' "${WORK_DIR}/target.log" 2>/dev/null; then
  echo "    （提示）未在模拟目标访问日志中看到 GET /smoke.txt，请人工确认转发链路"
fi
log "    转发验证通过（127.0.0.1:${PROXY_PORT} -> 127.0.0.1:${TARGET_PORT}）"

log "[6/6] iptables 部分"
if [ "$(id -u)" -eq 0 ] && iptables_available; then
  remove_smoke_chain
  log "    以 root 启动 redirect-agent 3 秒（HOST_IP=${AGENT_HOST_IP}，只操作链 ${SMOKE_CHAIN}）"
  HOST_IP="${AGENT_HOST_IP}" "${WORK_DIR}/bin/redirect-agent" \
    -config "${CONFIG_FILE}" -log-level debug >"${WORK_DIR}/agent.log" 2>&1 &
  AGENT_PID=$!
  sleep 3

  RULES="$(dump_smoke_chain)"
  echo "--- iptables -t nat -S ${SMOKE_CHAIN} ---"
  if [ -n "${RULES}" ]; then echo "${RULES}"; else echo "<空>"; fi
  echo "-----------------------------------------"
  if echo "${RULES}" | grep -q 'DNAT' && echo "${RULES}" | grep -q -- "${PROXY_PORT}"; then
    log "    规则检查通过：链中存在 DNAT，且指向代理端口 ${PROXY_PORT}"
  else
    echo "--- redirect-agent 日志 ---"
    cat "${WORK_DIR}/agent.log" || true
    die "未在链 ${SMOKE_CHAIN} 中找到预期的 DNAT 规则；若日志显示因「本节点即代理节点」而跳过，请用 SMOKE_AGENT_HOST_IP=127.0.0.2 重跑"
  fi

  log "    发送 SIGTERM，检查 agent 退出后是否自动清理链"
  kill -TERM "${AGENT_PID}" 2>/dev/null || true
  wait "${AGENT_PID}" 2>/dev/null || true
  AGENT_PID=""
  sleep 1
  if smoke_chain_exists; then
    echo "--- 残留规则 ---"
    dump_smoke_chain
    echo "--- redirect-agent 日志 ---"
    cat "${WORK_DIR}/agent.log" || true
    die "SIGTERM 后链 ${SMOKE_CHAIN} 仍然存在，未自动清理"
  fi
  log "    链 ${SMOKE_CHAIN} 已被清理，iptables 部分通过"
else
  log "    跳过 iptables 部分（需 root）"
fi

log "冒烟测试全部通过 ✅  （tcp-forwarder 转发链路已验证；iptables 部分见上方输出）"
