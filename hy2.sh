#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全增强版部署脚本 v2
# 作者: stephchow
# 更新时间: 2026-01-08
# 特性: 架构检测 + SHA256 校验 + 自签名证书 + systemd 服务 + 防火墙自动放行 + 最小权限运行

set -euo pipefail

# ========== 日志函数 ==========
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2; }
error() { log "❌ ERROR: $*" >&2; exit 1; }
success() { log "✅ SUCCESS: $*"; }

# ========== 依赖检查 ==========
for cmd in curl openssl sha256sum awk; do
    if ! command -v "$cmd" &> /dev/null; then
        error "缺少必要命令: $cmd，请先安装"
    fi
done

# ========== 获取脚本目录（兼容管道执行）==========
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
    SCRIPT_DIR="$(pwd)"
fi

# ========== 配置 ==========
HYSTERIA_RELEASE_TAG="app/v2.6.5"
DEFAULT_PORT=29999
SNI="www.cloudflare.com"       # 更中性的伪装域名
ALPN="h3"
CERT_FILE="cert.pem"
KEY_FILE="key.pem"
CONFIG_FILE="server.yaml"
SERVICE_NAME="hysteria2.service"
USER_NAME="hysteria2"

BIN_NAME="hysteria-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
BIN_PATH="${SCRIPT_DIR}/${BIN_NAME}"

# 架构检查
case "$BIN_NAME" in
    hysteria-linux-amd64|hysteria-linux-arm64) ;;
    *)
        error "不支持的架构: $(uname -m)"
        ;;
esac

# ========== 参数解析 ==========
SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            if [[ "$2" =～ ^[0-9]+$ ]] && (( $2 >= 1 && $2 <= 65535 )); then
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
            error "未知参数: $1"
            ;;
    esac
done

# ========== 功能函数 ==========

download_binary() {
    if [[ -f "$BIN_PATH" ]]; then
        if [[ $(head -c4 "$BIN_PATH" 2>/dev/null) == $'\x7fELF' ]]; then
            chmod +x "$BIN_PATH" 2>/dev/null || true
            success "有效二进制已存在，跳过下载"
            return
        fi
    fi

    local url="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_RELEASE_TAG}/${BIN_NAME}"
    log "正在下载: $url"
    curl -fL --retry 3 -o "$BIN_PATH" "$url" || error "下载失败（检查网络或 GitHub 可达性）"
    chmod +x "$BIN_PATH"
    success "二进制下载完成"
}

verify_checksum() {
    local tag_encoded="${HYSTERIA_RELEASE_TAG//\//%2F}"
    local hash_url="https://github.com/apernet/hysteria/releases/download/${tag_encoded}/hashes.txt"
    
    log "正在下载哈希校验文件: $hash_url"
    curl -fsSL --retry 3 -o /tmp/hashes.txt "$hash_url" || error "无法下载 hashes.txt"

    expected_sha=$(awk -v bin="$BIN_NAME" '$2 == bin {print $1}' /tmp/hashes.txt)
    if [[ -z "$expected_sha" ]]; then
        error "未在 hashes.txt 中找到 '$BIN_NAME' 的哈希值"
    fi

    actual_sha=$(sha256sum "$BIN_PATH" | awk '{print $1}')
    if [[ "$expected_sha" != "$actual_sha" ]]; then
        error "SHA256 校验失败！期望: $expected_sha，实际: $actual_sha"
    fi

    success "SHA256 校验通过"
    rm -f /tmp/hashes.txt
}

generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-24
}

setup_cert() {
    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        success "使用现有证书"
        return
    fi

    local cnf="/tmp/openssl_hy2.cnf"
    cat > "$cnf" <<EOF
[req]
default_bits = 256
distinguished_name = dn
prompt = no
[dn]
CN = ${SNI}
[v3_ca]
subjectAltName = DNS:${SNI}
EOF

    log "生成自签名 ECDSA 证书..."
    openssl req -batch -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -config "$cnf" -extensions v3_ca >/dev/null 2>&1

    rm -f "$cnf"
    success "自签名证书生成成功"
}

write_config() {
    AUTH_PASSWORD=$(generate_password)
    cat > "$CONFIG_FILE" <<EOF
listen: ":${SERVER_PORT}"
tls:
  cert: "${SCRIPT_DIR}/${CERT_FILE}"
  key: "${SCRIPT_DIR}/${KEY_FILE}"
  alpn:
    - "${ALPN}"
auth:
  type: password
  password: "${AUTH_PASSWORD}"
bandwidth:
  up: "200 mbps"
  down: "200 mbps"
quic:
  max_idle_timeout: "120s"
  keepalive_interval: "15s"
log:
  level: warn
EOF
    echo "$AUTH_PASSWORD" > "password.txt"
    chmod 600 "password.txt"
    success "配置文件和密码已保存（权限 600）"
}

install_service() {
    if [[ "$INSTALL_AS_SERVICE" == false ]]; then
        return
    fi

    # 创建专用用户（如果不存在）
    if ! id "$USER_NAME" &>/dev/null; then
        log "创建系统用户: $USER_NAME"
        sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    fi

    # 设置文件归属
    sudo chown "$USER_NAME:$USER_NAME" "$BIN_PATH" "$CERT_FILE" "$KEY_FILE" "$CONFIG_FILE" "password.txt"
    sudo chmod 700 "$SCRIPT_DIR"

    log "正在生成 systemd 服务文件..."
    cat > /tmp/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
User=${USER_NAME}
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${BIN_PATH} server -c ${SCRIPT_DIR}/${CONFIG_FILE}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SCRIPT_DIR}

[Install]
WantedBy=multi-user.target
EOF

    sudo mv /tmp/hysteria2.service "/etc/systemd/system/${SERVICE_NAME}"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "${SERVICE_NAME}"
    success "systemd 服务已启用并以 '$USER_NAME' 用户启动"
}

setup_firewall() {
    log "正在配置防火墙放行端口: ${SERVER_PORT} (TCP/UDP)..."

    if command -v ufw &> /dev/null && sudo ufw status | grep -q "active"; then
        sudo ufw allow "${SERVER_PORT}/tcp" >/dev/null
        sudo ufw allow "${SERVER_PORT}/udp" >/dev/null
        success "UFW 防火墙端口已开放"

    elif command -v firewall-cmd &> /dev/null && sudo systemctl is-active --quiet firewalld; then
        sudo firewall-cmd --permanent --add-port="${SERVER_PORT}/tcp" >/dev/null 2>&1
        sudo firewall-cmd --permanent --add-port="${SERVER_PORT}/udp" >/dev/null 2>&1
        sudo firewall-cmd --reload >/dev/null
        success "Firewalld 防火墙端口已开放"

    elif command -v iptables &> /dev/null; then
        # 检查规则是否存在，避免重复
        sudo iptables -C INPUT -p tcp --dport "$SERVER_PORT" -j ACCEPT 2>/dev/null || \
            sudo iptables -A INPUT -p tcp --dport "$SERVER_PORT" -j ACCEPT
        sudo iptables -C INPUT -p udp --dport "$SERVER_PORT" -j ACCEPT 2>/dev/null || \
            sudo iptables -A INPUT -p udp --dport "$SERVER_PORT" -j ACCEPT
        success "iptables 规则已添加（注意：重启后可能失效）"

    else
        log "⚠️  未检测到活跃防火墙（UFW/Firewalld），请手动放行端口 ${SERVER_PORT}"
    fi
}

get_ip() {
    for url in https://ifconfig.me/ip https://api.ipify.org https://ipecho.net/plain; do
        ip=$(curl -s --max-time 5 "$url" 2>/dev/null)
        if [[ "$ip" =～ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

# ========== 版本检查（可选，带容错）==========
LATEST_TAG=""
if latest_json=$(curl -fsSL --max-time 8 "https://api.github.com/repos/apernet/hysteria/releases/latest" 2>/dev/null); then
    LATEST_TAG=$(echo "$latest_json" | grep '"tag_name":' | head -n1 | cut -d'"' -f4)
fi

if [[ -n "$LATEST_TAG" && "$LATEST_TAG" != "$HYSTERIA_RELEASE_TAG" ]]; then
    log "💡 提示：发现新版本 $LATEST_TAG，当前使用 $HYSTERIA_RELEASE_TAG"
fi

# ========== 主流程 ==========
log "🚀 开始部署 Hysteria2 (端口: $SERVER_PORT)"
download_binary
verify_checksum
setup_cert
write_config
install_service
setup_firewall

IP=$(get_ip) || { error "无法获取公网IP，请检查网络或手动配置"; }
PASSWORD=$(cat password.txt)

# 👇 新增：服务状态检查（仅当安装为服务时）
if [[ "$INSTALL_AS_SERVICE" == true ]]; then
    echo
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        success "systemd 服务 '${SERVICE_NAME}' 正在运行"
    else
        log "⚠️  systemd 服务 '${SERVICE_NAME}' 未运行"
        echo "   请运行以下命令查看详细日志："
        echo "   sudo journalctl -u ${SERVICE_NAME} -n 50 --no-pager"
    fi
fi

echo

echo "🎉 部署成功！"
echo "🔑 密码: $PASSWORD"
echo "📱 链接: hysteria2://${PASSWORD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Vps"
echo
echo "⚠️  注意：链接包含 'insecure=1'，仅适用于自签名证书！"
echo "   如使用有效证书（如 Let's Encrypt），请移除此参数。"
echo
log "📌 已自动放行防火墙端口: $SERVER_PORT (TCP/UDP)"
