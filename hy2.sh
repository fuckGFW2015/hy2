#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全增强版部署脚本 v2.3
# 作者：stephchow
# 更新: 2026-01-08 | 修复自检误报 & 权限逻辑

set -euo pipefail

# ========== 日志函数 ==========
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2; }
error() { log "❌ ERROR: $*" >&2; exit 1; }
success() { log "✅ SUCCESS: $*"; }

# ========== 基础配置 ==========
HYSTERIA_RELEASE_TAG="app/v2.6.5"
DEFAULT_PORT=29999
SNI="www.cloudflare.com"
ALPN="h3"
CERT_FILE="cert.pem"
KEY_FILE="key.pem"
CONFIG_FILE="server.yaml"
SERVICE_NAME="hysteria2.service"
USER_NAME="hysteria2"
INSTALL_DIR="/etc/hysteria2"

# 检测架构
arch=$(uname -m)
case "$arch" in
    x86_64)        bin_arch="amd64" ;;
    aarch64|arm64) bin_arch="arm64" ;;
    *) error "不支持的架构: $arch" ;;
esac
BIN_NAME="hysteria-linux-$bin_arch"

# ========== 依赖检查 ==========
for cmd in curl openssl sha256sum awk sudo; do
    if ! command -v "$cmd" &> /dev/null; then
        error "缺少必要命令: $cmd"
    fi
done

SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port) SERVER_PORT="$2"; shift 2 ;;
        --service) INSTALL_AS_SERVICE=true; shift ;;
        *) shift ;;
    esac
done

# ========== 功能函数 ==========

tune_kernel() {
    log "正在优化网络内核参数..."
    local conf_file="/etc/sysctl.d/99-hysteria.conf"
    cat <<EOF | sudo tee "$conf_file" > /dev/null
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
    sudo sysctl --system >/dev/null 2>&1 || true
}

download_binary() {
    log "正在下载二进制文件..."
    curl -fL -o "${BIN_NAME}" "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_RELEASE_TAG}/${BIN_NAME}"
    chmod +x "${BIN_NAME}"
}

setup_cert() {
    log "生成自签名证书..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=${SNI}" >/dev/null 2>&1
}

write_config() {
    AUTH_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-24)
    cat > "$CONFIG_FILE" <<EOF
server:
  listen: ":${SERVER_PORT}"
tls:
  cert: "${INSTALL_DIR}/${CERT_FILE}"
  key: "${INSTALL_DIR}/${KEY_FILE}"
  alpn: ["${ALPN}"]
auth:
  type: password
  password: "${AUTH_PASSWORD}"
quic:
  max_idle_timeout: "120s"
  keepalive_interval: "15s"
log:
  level: warn
EOF
    echo "$AUTH_PASSWORD" > "password.txt"
    success "配置文件已生成"
}

install_service() {
    if [[ "$INSTALL_AS_SERVICE" == false ]]; then return; fi
    
    log "安装服务并配置权限..."
    if ! id "$USER_NAME" &>/dev/null; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    fi

    sudo mkdir -p "$INSTALL_DIR"
    
    # 授权特权端口 (如 443)
    if (( SERVER_PORT < 1024 )); then
        sudo setcap 'cap_net_bind_service=+ep' "${BIN_NAME}"
    fi

    # 移动文件并设置归属
    sudo mv "${BIN_NAME}" "$CERT_FILE" "$KEY_FILE" "$CONFIG_FILE" "password.txt" "$INSTALL_DIR/"
    sudo chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"
    sudo chmod -R 755 "$INSTALL_DIR"

    # 生成 Systemd 配置
    sudo tee "/etc/systemd/system/${SERVICE_NAME}" > /dev/null <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
User=${USER_NAME}
Group=${USER_NAME}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/${BIN_NAME} server -c ${INSTALL_DIR}/${CONFIG_FILE}
Restart=on-failure
RestartSec=3s
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl restart "${SERVICE_NAME}"
    sudo systemctl enable "${SERVICE_NAME}"
}

health_check() {
    if [[ "$INSTALL_AS_SERVICE" == false ]]; then return; fi
    log "🔍 正在执行运行状态自检..."
    sleep 5
    
    # 优先信任 systemctl 状态
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        success "✅ Hysteria2 服务已在后台平稳运行"
    else
        error "❌ 服务启动失败。请手动检查: journalctl -u $SERVICE_NAME"
    fi
}

# ========== 主流程 ==========
# 清理旧残留
sudo systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

download_binary
setup_cert
write_config
install_service
tune_kernel
health_check

# 获取输出信息
IP=$(curl -s https://api.ipify.org || echo "YOUR_IP")
PWD=$(sudo cat "${INSTALL_DIR}/password.txt" 2>/dev/null || echo "check_file")

echo -e "\n-------------------------------------------"
echo -e "🎉 Hysteria2 部署成功！"
echo -e "🔑 密码: ${PWD}"
echo -e "🔗 链接: hysteria2://${PWD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Server"
echo -e "-------------------------------------------"
echo -e "\n⚠️  注意：若您使用云服务器，请务必在云商控制台安全组/防火墙中"
echo -e "    同时放行 ${SERVER_PORT}/TCP 和 ${SERVER_PORT}/UDP 协议！"
