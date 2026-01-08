#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全增强部署脚本 v2.4 (兼容 POSIX)
# 融合简洁性 + 健壮性 | 作者：stephchow
# 更新: 2026-01-09 | 移除 [[ =～ ]] 以兼容 dash/旧 shell

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
for cmd in curl openssl sha256sum awk sudo; do
    command -v "$cmd" >/dev/null 2>&1 || error "缺少必要命令: $cmd"
done

# ========== 参数解析 ==========
SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=false

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            # 使用 POSIX 兼容方式校验端口是否为 1-65535 的整数
            if [ "$2" -eq "$2" ] 2>/dev/null && [ "$2" -ge 1 ] && [ "$2" -le 65535 ]; then
                SERVER_PORT="$2"
                shift 2
            else
                error "端口必须是 1-65535 之间的整数"
            fi
            ;;
        --service)
            INSTALL_AS_SERVICE=true
            shift
            ;;
        *)
            shift
            ;;
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
    sudo sysctl --system >/dev/null 2>&1 || warn "sysctl 优化未完全生效（非致命）"
}

download_binary() {
    local tmp_dir="/tmp/hy2-install-$$"
    mkdir -p "$tmp_dir"
    local bin_path="$tmp_dir/${BIN_NAME}"
    
    log "正在下载 Hysteria2 二进制..."
    if ! curl -fL --retry 3 -o "$bin_path" \
        "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_RELEASE_TAG}/${BIN_NAME}"; then
        error "下载失败，请检查网络或 GitHub 可达性"
    fi

    # 尝试 SHA256 校验（可选）
    if hash_url=$(curl -fsSL "https://github.com/apernet/hysteria/releases/download/${HYSTERIA_RELEASE_TAG//\//%2F}/hashes.txt" 2>/dev/null); then
        expected_sha=$(echo "$hash_url" | grep "$BIN_NAME" | awk '{print $1}' | head -n1)
        if [ -n "$expected_sha" ]; then
            actual_sha=$(sha256sum "$bin_path" | awk '{print $1}')
            if [ "$actual_sha" = "$expected_sha" ]; then
                success "✅ 二进制校验通过"
            else
                error "SHA256 校验失败！文件可能被篡改或损坏"
            fi
        fi
    else
        warn "无法获取哈希表，跳过校验（不影响功能）"
    fi

    chmod +x "$bin_path"
    echo "$bin_path"
}

setup_cert() {
    local tmp_dir="/tmp/hy2-cert-$$"
    mkdir -p "$tmp_dir"
    cd "$tmp_dir"
    
    log "生成自签名证书 (SNI: $SNI)..."
    if ! openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=${SNI}" >/dev/null 2>&1; then
        error "证书生成失败，请检查 OpenSSL 是否正常"
    fi
    
    pwd
}

write_config() {
    local tmp_dir="/tmp/hy2-config-$$"
    mkdir -p "$tmp_dir"
    cd "$tmp_dir"
    
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
    pwd
}

install_service() {
    if [ "$INSTALL_AS_SERVICE" = false ]; then return; fi

    log "安装 systemd 服务..."
    
    if ! id "$USER_NAME" >/dev/null 2>&1; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    fi

    sudo mkdir -p "$INSTALL_DIR"

    # 处理低端口
    if [ "$SERVER_PORT" -lt 1024 ]; then
        log "授予 CAP_NET_BIND_SERVICE 能力（用于绑定低端口）..."
        if ! sudo setcap 'cap_net_bind_service=+ep' "$BIN_PATH"; then
            error "❌ setcap 失败！请改用高端口（如 29999）或检查 /tmp 分区挂载选项"
        fi
        if ! getcap "$BIN_PATH" | grep -q "cap_net_bind_service"; then
            error "❌ CAP_NET_BIND_SERVICE 未生效！"
        fi
    fi

    # 安全复制文件
    sudo cp "$BIN_PATH" "$CERT_DIR/$CERT_FILE" "$CERT_DIR/$KEY_FILE" \
              "$CONF_DIR/$CONFIG_FILE" "$CONF_DIR/password.txt" "$INSTALL_DIR/"

    sudo chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"
    sudo chmod 700 "$INSTALL_DIR"
    sudo chmod 600 "$INSTALL_DIR"/*.pem "$INSTALL_DIR"/password.txt

    # 生成 systemd 单元
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
$( [ "$SERVER_PORT" -lt 1024 ] && echo "AmbientCapabilities=CAP_NET_BIND_SERVICE" )
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl restart "${SERVICE_NAME}.service"
    sudo systemctl enable "${SERVICE_NAME}.service" --quiet
    success "✅ Systemd 服务已启动"
}

health_check() {
    if [ "$INSTALL_AS_SERVICE" = false ]; then return; fi
    log "🔍 执行服务健康检查..."
    sleep 5
    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        success "✅ Hysteria2 服务运行正常"
    else
        warn "服务状态异常，请手动检查: sudo journalctl -u ${SERVICE_NAME}.service -n 30"
    fi
}

cleanup() {
    rm -rf /tmp/hy2-*
}

# ========== 主流程 ==========
trap cleanup EXIT

# 准备文件
BIN_PATH=$(download_binary)
CERT_DIR=$(setup_cert)
CONF_DIR=$(write_config)

# 停止旧服务
sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true

# 安装
install_service
tune_kernel
health_check

# 获取结果
FINAL_PWD=$(cat "$CONF_DIR/password.txt")
IP=$(curl -s --max-time 5 https://api.ipify.org || curl -s --max-time 5 https://ifconfig.me/ip || echo "YOUR_PUBLIC_IP")

# 输出
echo -e "\n-------------------------------------------"
echo -e "🎉 Hysteria2 部署成功！"
echo -e "🔑 密码: ${FINAL_PWD}"
echo -e "🔗 链接: hysteria2://${FINAL_PWD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Server"
echo -e "📁 安装路径: ${INSTALL_DIR}"
echo -e "-------------------------------------------"
echo -e "\n⚠️  重要提示："
echo -e "   1. 请在云服务器控制台放行 ${SERVER_PORT}/TCP 和 ${SERVER_PORT}/UDP"
echo -e "   2. 私钥和密码文件权限为 600，仅 hysteria2 用户可读"
