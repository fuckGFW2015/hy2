#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全增强部署脚本 v2.9.1
# 更新: 2026-01-08 | 修复: 特权端口授权 & 增加安全组放行提示

set -euo pipefail

# ========== 日志函数 ==========
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2; }
error() { log "❌ ERROR: $*" >&2; exit 1; }
warn() { log "⚠️ WARNING: $*" >&2; }
success() { log "✅ SUCCESS: $*"; }

# ========== 基础配置 ==========
HYSTERIA_RELEASE_TAG="app/v2.6.5"
DEFAULT_PORT=29999
SNI="www.cloudflare.com"
ALPN="h3"
CERT_FILE="cert.pem"
KEY_FILE="key.pem"
CONFIG_FILE="server.yaml"
SERVICE_NAME="hysteria2"
USER_NAME="hysteria2"
INSTALL_DIR="/etc/hysteria2"

# 架构检测
arch=$(uname -m)
case "$arch" in
    x86_64)        bin_arch="amd64" ;;
    aarch64|arm64) bin_arch="arm64" ;;
    *) error "不支持的 CPU 架构: $arch" ;;
esac
BIN_NAME="hysteria-linux-$bin_arch"

# ========== 依赖检查 ==========
for cmd in curl openssl sha256sum awk sudo grep; do
    command -v "$cmd" >/dev/null 2>&1 || error "缺少必要命令: $cmd"
done

# ========== 参数解析 ==========
SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=false

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            if [ "$2" -eq "$2" ] 2>/dev/null && [ "$2" -ge 1 ] && [ "$2" -le 65535 ]; then
                SERVER_PORT="$2"; shift 2
            else
                error "端口无效"
            fi ;;
        --service) INSTALL_AS_SERVICE=true; shift ;;
        *) shift ;;
    esac
done

# ========== 功能函数 ==========

download_binary() {
    local tmp_dir="/tmp/hy2-install-$$"
    mkdir -p "$tmp_dir"
    local bin_path="$tmp_dir/${BIN_NAME}"
    
    log "正在下载 Hysteria2 二进制 (${bin_arch})..."
    curl -fL --retry 3 -o "$bin_path" \
        "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_RELEASE_TAG}/${BIN_NAME}" || error "下载失败"

    log "正在进行 SHA256 完整性校验..."
    local tag_encoded="${HYSTERIA_RELEASE_TAG//\//%2F}"
    local hash_url="https://github.com/apernet/hysteria/releases/download/${tag_encoded}/hashes.txt"
    
    local expected_sha
    expected_sha=$(curl -fsSL "$hash_url" | grep "$BIN_NAME" | awk '{print $1}' | head -n 1)
    
    if [ -n "$expected_sha" ]; then
        local actual_sha
        actual_sha=$(sha256sum "$bin_path" | awk '{print $1}')
        if [ "$actual_sha" = "$expected_sha" ]; then
            success "SHA256 校验通过"
        else
            error "SHA256 校验失败"
        fi
    fi

    chmod +x "$bin_path"
    echo "$bin_path"
}

setup_cert() {
    local tmp_dir="/tmp/hy2-cert-$$"
    mkdir -p "$tmp_dir"
    log "生成自签名证书 (SNI: $SNI)..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$tmp_dir/$KEY_FILE" -out "$tmp_dir/$CERT_FILE" \
        -subj "/CN=${SNI}" >/dev/null 2>&1 || error "证书生成失败"
    echo "$tmp_dir"
}

write_config() {
    local tmp_dir="/tmp/hy2-config-$$"
    mkdir -p "$tmp_dir"
    local pwd_str
    pwd_str=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-24)
    cat > "$tmp_dir/$CONFIG_FILE" <<EOF
server:
  listen: ":${SERVER_PORT}"
tls:
  cert: "${INSTALL_DIR}/${CERT_FILE}"
  key: "${INSTALL_DIR}/${KEY_FILE}"
  alpn: ["${ALPN}"]
auth:
  type: password
  password: "${pwd_str}"
quic:
  max_idle_timeout: 120s
  keepalive_interval: 15s
log:
  level: warn
EOF
    echo "$pwd_str" > "$tmp_dir/password.txt"
    echo "$tmp_dir"
}

install_service() {
    if [ "$INSTALL_AS_SERVICE" = false ]; then return; fi

    log "安装 systemd 服务并处理特权端口权限..."
    if ! id "$USER_NAME" >/dev/null 2>&1; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    fi

    sudo mkdir -p "$INSTALL_DIR"

    # 1. 先复制文件
    sudo cp "$BIN_PATH" "$INSTALL_DIR/${BIN_NAME}"
    sudo cp "$CERT_DIR/$CERT_FILE" "$INSTALL_DIR/"
    sudo cp "$CERT_DIR/$KEY_FILE" "$INSTALL_DIR/"
    sudo cp "$CONF_DIR/$CONFIG_FILE" "$INSTALL_DIR/"
    sudo cp "$CONF_DIR/password.txt" "$INSTALL_DIR/"

    # 2. 赋予 Capability (必须在 cp 之后执行)
    if [ "$SERVER_PORT" -lt 1024 ]; then
        log "检测到特权端口 ${SERVER_PORT}，正在执行 setcap..."
        sudo setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/${BIN_NAME}"
    fi

    # 3. 设置权限
    sudo chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"
    sudo chmod 600 "$INSTALL_DIR"/*.pem "$INSTALL_DIR"/*.txt "$INSTALL_DIR"/*.yaml
    sudo chmod +x "$INSTALL_DIR/${BIN_NAME}"

    # 4. 生成 systemd 配置
    sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null <<EOF
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
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable "${SERVICE_NAME}.service" --quiet
    sudo systemctl restart "${SERVICE_NAME}.service"
}

tune_kernel() {
    log "优化网络内核参数..."
    local conf_file="/etc/sysctl.d/99-hysteria.conf"
    cat <<EOF | sudo tee "$conf_file" > /dev/null
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
    sudo sysctl --system >/dev/null 2>&1 || true
}

health_check() {
    if [ "$INSTALL_AS_SERVICE" = false ]; then return; fi
    log "🔍 执行运行状态自检..."
    sleep 5
    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        success "✅ Hysteria2 服务已在后台平稳运行"
    else
        error "服务异常。报错日志如下：\n$(sudo journalctl -u ${SERVICE_NAME}.service -n 5 --no-pager)"
    fi
}

cleanup() {
    rm -rf /tmp/hy2-*
}

# ========== 主流程 ==========
trap cleanup EXIT
BIN_PATH=$(download_binary)
CERT_DIR=$(setup_cert)
CONF_DIR=$(write_config)

sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true

install_service
tune_kernel
health_check

# 获取结果
FINAL_PWD=$(cat "$CONF_DIR/password.txt")

log "正在获取公网 IP..."
# 尝试多个 API 确保 100% 获取成功
IP=$(curl -s --max-time 3 https://api.ipify.org || \
     curl -s --max-time 3 https://ifconfig.me/ip || \
     curl -s --max-time 3 https://checkip.amazonaws.com || \
     curl -s --max-time 3 https://ip.sb || \
     echo "YOUR_PUBLIC_IP")

# 如果最后还是拿不到（极其少见），提醒手动替换
if [ "$IP" = "YOUR_PUBLIC_IP" ]; then
    warn "未能自动获取到公网 IP，请在客户端手动将 YOUR_PUBLIC_IP 替换为服务器实际 IP"
fi

echo -e "\n-------------------------------------------"
echo -e "🎉 Hysteria2 部署成功！"
echo -e "🔑 密码: ${FINAL_PWD}"
echo -e "🔗 链接: hysteria2://${FINAL_PWD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Server"
echo -e "-------------------------------------------"
echo -e "\n⚠️  重要提示："
echo -e "   1. 请在云服务器控制台放行 ${SERVER_PORT}/TCP 和 ${SERVER_PORT}/UDP"
echo -e "   2. 客户端连接请务必开启 '允许不安全证书 (Insecure)'"
