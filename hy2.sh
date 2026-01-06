#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全修复版部署脚本（兼容 BASH_SOURCE 问题 + 正确 release tag）
# # 作者: stephchow
# 更新时间: 2026-01-07

set -euo pipefail

# ========== 配置 ==========
HYSTERIA_RELEASE_TAG="app/v2.6.5"
DEFAULT_PORT=29999
SNI="www.microsoft.com"
ALPN="h3"
CERT_FILE="cert.pem"
KEY_FILE="key.pem"
CONFIG_FILE="server.yaml"
SERVICE_NAME="hysteria2.service"

# 使用当前目录作为工作目录（解决 BASH_SOURCE 问题）
SCRIPT_DIR="$(pwd)"
BIN_NAME="hysteria-linux-$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')"
BIN_PATH="${SCRIPT_DIR}/${BIN_NAME}"

# 架构检查（修复正则语法）
case "$BIN_NAME" in
    hysteria-linux-amd64|hysteria-linux-arm64)
        ;;
    *)
        echo "❌ 不支持的架构: $(uname -m)" >&2
        exit 1
        ;;
esac

# ========== 参数解析 ==========
SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--port)
            SERVER_PORT="$2"; shift 2 ;;
        --service)
            INSTALL_AS_SERVICE=true; shift ;;
        *)
            echo "未知参数: $1" >&2; exit 1 ;;
    esac
done

# ========== 函数 ==========
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2; }
error() { log "❌ ERROR: $*" >&2; exit 1; }
success() { log "✅ SUCCESS: $*"; }

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

# ========== SHA256 校验 ==========
verify_checksum() {
    local tag_encoded="${HYSTERIA_RELEASE_TAG//\//%2F}"
    local hash_url="https://github.com/apernet/hysteria/releases/download/${tag_encoded}/hashes.txt"
    
    log "正在下载哈希校验文件: $hash_url"
    curl -fsSL --retry 3 -o /tmp/hashes.txt "$hash_url" || error "无法下载 hashes.txt"

    # 从 hashes.txt 提取对应文件的 SHA256
    expected_sha=$(awk -v bin="$BIN_NAME" '$2 == bin {print $1}' /tmp/hashes.txt)
    if [[ -z "$expected_sha" ]]; then
        error "未在 hashes.txt 中找到 '$BIN_NAME' 的哈希值"
    fi

    actual_sha=$(sha256sum "$BIN_PATH" | awk '{print $1}')
    if [[ "$expected_sha" != "$actual_sha" ]]; then
        error "SHA256 校验失败！\n期望: $expected_sha\n实际: $actual_sha"
    fi

    success "SHA256 校验通过"
    rm -f /tmp/hashes.txt
}

# ========== 生成密码 ==========
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-24
}

# ========== 证书生成 ==========
setup_cert() {
    if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
        success "使用现有证书"
        return
    fi
    log "生成自签名 ECDSA 证书..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" \
        -subj "/CN=${SNI}" -addext "subjectAltName = DNS:${SNI}" >/dev/null 2>&1
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
    success "配置文件和密码已保存"
}

install_service() {
    if [[ "$INSTALL_AS_SERVICE" == false ]]; then return; fi
    cat > /tmp/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${BIN_PATH} server -c ${SCRIPT_DIR}/${CONFIG_FILE}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    sudo mv /tmp/hysteria2.service "/etc/systemd/system/${SERVICE_NAME}"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "${SERVICE_NAME}"
    success "systemd 服务已启用"
}

# ========== 获取公网 IP ==========
get_ip() {
    ip=$(curl -s https://ifconfig.me/ip 2>/dev/null || echo "YOUR_SERVER_IP")
    echo "$ip"
}

# ========== 主流程 ==========
log "🚀 开始部署 Hysteria2 (端口: $SERVER_PORT)"
download_binary
setup_cert
write_config
install_service

IP=$(get_ip)
PASSWORD=$(cat password.txt)

echo
echo "🎉 部署成功！"
echo "🔑 密码: $PASSWORD"
echo "📱 链接: hysteria2://${PASSWORD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Fixed"
echo
log "📌 请放行防火墙端口: $SERVER_PORT (TCP/UDP)"
