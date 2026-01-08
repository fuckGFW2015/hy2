#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全增强版部署脚本 v2.1
# 作者: stephchow
# 更新: 2026-01-08 | 修复路径权限逻辑 & 内核优化

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
# 固定的安装目录，解决 root 权限死锁
INSTALL_DIR="/etc/hysteria2"

# 检测并映射 CPU 架构
arch=$(uname -m)
case "$arch" in
    x86_64)        bin_arch="amd64" ;;
    aarch64|arm64) bin_arch="arm64" ;;
    *) error "不支持的 CPU 架构: $arch。Hysteria2 官方仅提供 amd64 和 arm64 版本。" ;;
esac
BIN_NAME="hysteria-linux-$bin_arch"

# ========== 依赖检查 ==========
for cmd in curl openssl sha256sum awk sudo; do
    if ! command -v "$cmd" &> /dev/null; then
        error "缺少必要命令: $cmd，请先安装"
    fi
done

# ========== 参数解析 ==========
SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=false

show_help() {
    echo "用法: $0 [-p PORT] [--service]"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            if [[ "$2" =~ ^[0-9]+$ ]] && (( $2 >= 1 && $2 <= 65535 )); then
                SERVER_PORT="$2"; shift 2
            else
                error "端口无效"; fi ;;
        --service) INSTALL_AS_SERVICE=true; shift ;;
        -h|--help) show_help ;;
        *) error "未知参数: $1" ;;
    esac
done

# ========== 功能函数 ==========

tune_kernel() {
    log "正在深度优化网络内核参数..."
    local conf_file="/etc/sysctl.d/99-hysteria.conf"
    cat <<EOF | sudo tee "$conf_file" > /dev/null
# Hysteria2 优化配置
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152
net.core.netdev_max_backlog = 10000
# 针对高并发 UDP 的优化
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
EOF
    sudo sysctl --system >/dev/null 2>&1 || log "⚠️ sysctl 应用受限，跳过"
}

download_binary() {
    local tmp_bin="/tmp/${BIN_NAME}"
    local url="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_RELEASE_TAG}/${BIN_NAME}"
    
    log "正在下载二进制文件..."
    curl -fL --retry 3 -o "$tmp_bin" "$url" || error "下载失败"
    
    log "正在进行 SHA256 校验..."
    local tag_encoded="${HYSTERIA_RELEASE_TAG//\//%2F}"
    local hash_url="https://github.com/apernet/hysteria/releases/download/${tag_encoded}/hashes.txt"
    local expected_sha
    expected_sha=$(curl -fsSL "$hash_url" | grep "$BIN_NAME" | awk '{print $1}' | head -n 1)
    
    if [[ -z "$expected_sha" ]]; then
        error "哈希表中未找到该版本记录"
    fi
    
    actual_sha=$(sha256sum "$tmp_bin" | awk '{print $1}')
    [[ "$expected_sha" != "$actual_sha" ]] && error "校验失败！"
    
    chmod +x "$tmp_bin"
    mv "$tmp_bin" "./${BIN_NAME}"
    success "二进制下载并校验通过"
}

setup_cert() {
    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then return; fi
    log "生成自签名证书 (SNI: $SNI)..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=${SNI}" >/dev/null 2>&1
}

write_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")"
    
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
bandwidth:
  up: "100 mbps"
  down: "100 mbps"
quic:
  max_idle_timeout: "120s"
  keepalive_interval: "15s"
log:
  level: warn
EOF

    chmod 600 "$CONFIG_FILE"
    echo "$AUTH_PASSWORD" > "password.txt"
    chmod 600 "password.txt"
    
    success "✅ 配置文件和密码已保存（权限 600）"
}

install_service() {
    # 1. 检查是否需要安装服务
    if [[ "$INSTALL_AS_SERVICE" == false ]]; then return; fi

    # 2. 确保所有必要文件都已生成（防止空跑）
    for file in "${BIN_NAME}" "$CERT_FILE" "$KEY_FILE" "$CONFIG_FILE" "password.txt"; do
        if [[ ! -f "$file" ]]; then
            error "服务模式所需文件缺失: $file"
        fi
    done
    
    # 3. 准备环境：创建目录和系统用户
    log "准备安装目录: $INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR"
    
    if ! id "$USER_NAME" &>/dev/null; then
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    fi

    # 4. 迁移文件并设置基本权限
    log "正在将文件迁移至系统目录..."
    sudo mv "${BIN_NAME}" "$CERT_FILE" "$KEY_FILE" "$CONFIG_FILE" "password.txt" "$INSTALL_DIR/"
    sudo chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"
    sudo chmod 700 "$INSTALL_DIR"

    # 5. 核心修复：针对低位端口 (如 443) 授予特权
    if (( SERVER_PORT < 1024 )); then
        log "检测到特权端口 $SERVER_PORT，正在授予二进制文件监听权限..."
        sudo setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/${BIN_NAME}"
    fi

    # 6. 生成 systemd 服务文件
    log "配置 systemd 服务..."
    # 注意：确保变量 SERVICE_NAME 不带 .service 后缀，或者下方 tee 路径不重复加后缀
    sudo tee "/etc/systemd/system/${SERVICE_NAME}" > /dev/null <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/${BIN_NAME} server -c ${INSTALL_DIR}/${CONFIG_FILE}
Restart=on-failure
RestartSec=5s

$( (( SERVER_PORT < 1024 )) && echo "AmbientCapabilities=CAP_NET_BIND_SERVICE" )

NoNewPrivileges=true
ProtectSystem=full
# 增加安全性限制
PrivateTmp=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

    # 7. 启动并激活服务
    sudo systemctl daemon-reload
    sudo systemctl enable --now "${SERVICE_NAME}"
    success "Systemd 服务已安装并尝试启动"
}
setup_firewall() {
    log "配置防火墙端口: $SERVER_PORT"
    if command -v ufw &>/dev/null; then
        sudo ufw allow "$SERVER_PORT/tcp" && sudo ufw allow "$SERVER_PORT/udp"
    elif command -v firewall-cmd &>/dev/null; then
        sudo firewall-cmd --permanent --add-port="$SERVER_PORT/tcp"
        sudo firewall-cmd --permanent --add-port="$SERVER_PORT/udp"
        sudo firewall-cmd --reload
    fi
}

get_ip() {
    # 尝试两个可靠的外部服务获取公网 IP
    for service in "https://api.ipify.org" "https://ifconfig.me/ip"; do
        ip=$(curl -s --max-time 5 "$service" 2>/dev/null)
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done

    # 最后回退到本地路由源 IP（在 RACKNERD 等直连公网 VPS 上即为公网 IP）
    local fallback_ip
    fallback_ip=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}')
    echo "${fallback_ip:-YOUR_PUBLIC_IP}"
}

health_check() {
    log "🔍 正在执行运行状态自检 (等待服务就绪)..."
    
    # 1. 给服务一点启动时间，避免瞬时检测失败
    sleep 3

    if [[ "$INSTALL_AS_SERVICE" == true ]]; then
        if ! sudo systemctl is-active --quiet "$SERVICE_NAME"; then
            log "⚠️ 服务启动稍慢，尝试重启..."
            sudo systemctl restart "$SERVICE_NAME"
            sleep 2
        fi
    fi

    # 2. 增加重试循环，检测端口是否监听
    local max_retries=5
    local count=0
    local tcp_listening=0
    local udp_listening=0

    while [ $count -lt $max_retries ]; do
        if command -v ss >/dev/null; then
            tcp_listening=$(ss -tuln | grep -c ":${SERVER_PORT}.*LISTEN") || true
            udp_listening=$(ss -uln | grep -c ":${SERVER_PORT}.*UNCONN") || true
        else
            tcp_listening=$(netstat -tuln | grep -c ":${SERVER_PORT}.*LISTEN") || true
            udp_listening=$(netstat -uln | grep -c ":${SERVER_PORT} ") || true
        fi

        if (( tcp_listening > 0 && udp_listening > 0 )); then
            success "✅ Hysteria2 正在监听端口 ${SERVER_PORT}"
            return 0
        fi
        
        count=$((count + 1))
        log "⏳ 端口尚未就绪，等待中 ($count/$max_retries)..."
        sleep 2
    done

    error "❌ 端口 ${SERVER_PORT} 自检失败。请运行 'sudo journalctl -u $SERVICE_NAME' 查看具体错误。"
}

# ========== 主流程 ==========
download_binary
setup_cert
write_config
install_service
tune_kernel
setup_firewall

# 仅在服务模式下做健康检查（因为只有这时服务才在运行）
if [[ "$INSTALL_AS_SERVICE" == true ]]; then
    health_check
fi

IP=$(get_ip)
# 从安装目录读取密码以防变量丢失
FINAL_PWD=$(sudo cat "${INSTALL_DIR}/password.txt" 2>/dev/null || echo "$AUTH_PASSWORD")

echo -e "\n🎉 部署成功！"
echo "🔑 密码: $FINAL_PWD"
echo "📱 节点链接: hysteria2://${FINAL_PWD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Server"
echo -e "\n注意：已自动安装至 $INSTALL_DIR 目录以增强安全性。"
echo "⚠️  注意：若您使用云服务器，请在安全组中放行 ${SERVER_PORT}/TCP 和 ${SERVER_PORT}/UDP"
