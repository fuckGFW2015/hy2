#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 安全增强部署脚本（支持命令行端口 + 自动密码 + 证书校验 + systemd）
# 适用于低内存环境（64MB+），兼顾安全与易用

set -euo pipefail

# ---------- 默认配置 ----------
HYSTERIA_VERSION="v2.6.5"
DEFAULT_PORT=29999
SNI=""
ALPN="h3"
USE_LETSENCRYPT=false
INSTALL_AS_SERVICE=false

CERT_FILE="cert.pem"
KEY_FILE="key.pem"
CONFIG_FILE="server.yaml"
SERVICE_NAME="hysteria2.service"

# ---------- 工具函数 ----------
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

error() {
    log "❌ ERROR: $*" >&2
    exit 1
}

warn() {
    log "⚠️ WARNING: $*" >&2
}

info() {
    log "ℹ️ INFO: $*"
}

success() {
    log "✅ SUCCESS: $*"
}

# ---------- 参数解析 ----------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port|-p)
            CUSTOM_PORT="$2"; shift 2 ;;
        --domain|-d)
            SNI="$2"; shift 2 ;;
        --letsencrypt)
            USE_LETSENCRYPT=true; shift ;;
        --service)
            INSTALL_AS_SERVICE=true; shift ;;
        --help|-h)
            cat <<EOF
用法: $0 [选项]
  -p, --port PORT       指定服务器端口（默认: $DEFAULT_PORT）
  -d, --domain DOMAIN   指定域名（用于 SNI 和 Let's Encrypt）
      --letsencrypt     使用 Let's Encrypt 自动申请证书（需域名解析 + 开放80端口）
      --service         安装为 systemd 服务（开机自启）
  -h, --help            显示此帮助
示例:
  $0 -p 443 -d my.example.com --letsencrypt --service
EOF
            exit 0 ;;
        *)
            error "未知参数: $1" ;;
    esac
done

SERVER_PORT="${CUSTOM_PORT:-$DEFAULT_PORT}"

if [[ $USE_LETSENCRYPT == true && -z "$SNI" ]]; then
    error "使用 --letsencrypt 必须指定 --domain"
fi

if [[ -z "$SNI" ]]; then
    SNI="www.microsoft.com"
    warn "未指定域名，SNI 将使用默认值: $SNI（仅用于伪装，建议绑定真实域名）"
fi

# ---------- 架构检测 ----------
arch_name() {
    local machine
    machine=$(uname -m | tr '[:upper:]' '[:lower:]')
    case "$machine" in
        *arm64*|*aarch64*) echo "arm64" ;;
        *x86_64*|*amd64*)  echo "amd64" ;;
        *) error "不支持的 CPU 架构: $(uname -m)" ;;
    esac
}

ARCH=$(arch_name)
HYSTERIA_VERSION_TAG="app/v2.6.5"
HYSTERIA_VERSION_NUM="2.6.5"   # 从 tag 中提取纯版本号
BIN_NAME="hysteria-${HYSTERIA_VERSION_NUM}-linux-${ARCH}"
BIN_PATH="./${BIN_NAME}""

# ---------- 下载并校验二进制 ----------
download_and_verify() {
    if [[ -f "$BIN_PATH" ]]; then
        success "二进制已存在，跳过下载。"
        return
    fi

    local url="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/${BIN_NAME}"
    local sha_url="https://github.com/apernet/hysteria/releases/download/${HYSTERIA_VERSION}/hashes.txt"

    info "正在下载 Hysteria2 二进制: ${url}"
    curl -L --retry 3 --connect-timeout 30 -o "$BIN_PATH" "$url" || error "下载失败"

    info "正在下载 SHA256 校验列表: ${sha_url}"
    local sha_file="hashes.txt"
    curl -L --retry 3 --connect-timeout 30 -o "$sha_file" "$sha_url" || error "无法获取校验和"

    # 计算本地文件的 SHA256
    local local_hash
    local_hash=$(sha256sum "$BIN_PATH" | cut -d' ' -f1)

    # 从 hashes.txt 中查找该文件对应的官方哈希
    local official_hash
    official_hash=$(awk -v file="$BIN_NAME" '$2 == file {print $1}' "$sha_file")

    if [[ -z "$official_hash" ]]; then
        rm -f "$sha_file" "$BIN_PATH"
        error "未在 hashes.txt 中找到文件 '$BIN_NAME' 的哈希值"
    fi

    if [[ "$local_hash" == "$official_hash" ]]; then
        success "✅ SHA256 校验通过！"
        rm -f "$sha_file"
        chmod +x "$BIN_PATH"
    else
        rm -f "$sha_file" "$BIN_PATH"
        error "❌ 校验失败！\n本地哈希: $local_hash\n官方哈希: $official_hash"
    fi
}
# ---------- 生成随机密码 ----------
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-24
}

AUTH_PASSWORD=$(generate_password)
export AUTH_PASSWORD

# ---------- 证书处理 ----------
setup_certificates() {
    if [[ $USE_LETSENCRYPT == true ]]; then
        info "使用 Let's Encrypt 申请证书（需 acme.sh）..."
        if ! command -v socat >/dev/null; then
            error "需要安装 socat（用于 HTTP-01 验证）\n请运行: apt install socat\n并确保 80 端口未被占用且对外可访问"
        fi
        if ! command -v acme.sh >/dev/null; then
            info "安装 acme.sh..."
            curl https://get.acme.sh | sh
        fi
        ~/.acme.sh/acme.sh --issue -d "$SNI" --standalone
        ~/.acme.sh/acme.sh --install-cert -d "$SNI" \
            --key-file "$(pwd)/$KEY_FILE" \
            --fullchain-file "$(pwd)/$CERT_FILE"
        success "Let's Encrypt 证书安装完成。"
    else
        if [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]]; then
            success "使用现有自签名证书。"
            return
        fi
        info "生成自签名 ECDSA 证书（prime256v1）..."
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -days 3650 -keyout "$KEY_FILE" -out "$CERT_FILE" -subj "/CN=${SNI}" \
            -addext "subjectAltName = DNS:${SNI}" >/dev/null 2>&1
        success "自签名证书生成成功。"
    fi
}

# ---------- 写入配置 ----------
write_config() {
    cat > "$CONFIG_FILE" <<EOF
listen: ":${SERVER_PORT}"
tls:
  cert: "$(pwd)/${CERT_FILE}"
  key: "$(pwd)/${KEY_FILE}"
  alpn:
    - "${ALPN}"
auth:
  type: password
  password: "${AUTH_PASSWORD}"
bandwidth:
  up: "200 mbps"
  down: "200 mbps"
quic:
  max_idle_timeout: "10s"
  max_concurrent_streams: 4
  initial_stream_receive_window: 65536
  max_stream_receive_window: 131072
  initial_conn_receive_window: 131072
  max_conn_receive_window: 262144
EOF
    success "配置文件写入: $CONFIG_FILE"
}

# ---------- 获取公网 IP 或域名 ----------
get_public_ip() {
    if [[ -n "${MY_CUSTOM_IP:-}" ]]; then
        echo "$MY_CUSTOM_IP"
        return
    fi

    # 尝试自动获取公网 IP
    local ip=""
    if command -v curl >/dev/null; then
        ip=$(curl -s --max-time 5 https://ifconfig.me/ip 2>/dev/null)
    elif command -v wget >/dev/null; then
        ip=$(wget -qO- --timeout=5 https://ifconfig.me/ip 2>/dev/null)
    fi

    # 验证是否为有效 IPv4 地址（简单判断）
    if [[ -n "$ip" && "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "$ip"
        return
    fi

    # 自动获取失败，要求用户手动输入（非空）
    while true; do
        read -rp "⚠️ 无法自动获取公网 IP，请手动输入服务器公网 IP 或域名: " ip_input
        if [[ -n "$ip_input" ]]; then
            echo "$ip_input"
            return
        fi
        echo "❌ 输入不能为空，请重试。"
    done
}

# ---------- 安装为 systemd 服务 ----------
install_systemd_service() {
    if [[ $INSTALL_AS_SERVICE == false ]]; then
        return
    fi

    local service_path="/etc/systemd/system/$SERVICE_NAME"
    cat > /tmp/hysteria2.service <<EOF
[Unit]
Description=Hysteria2 Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/$BIN_NAME server -c $(pwd)/$CONFIG_FILE
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo mv /tmp/hysteria2.service "$service_path"
    sudo systemctl daemon-reload
    sudo systemctl enable --now "$SERVICE_NAME"
    success "已安装为 systemd 服务: $SERVICE_NAME（开机自启）"
    echo "管理命令: sudo systemctl {start|stop|restart|status} $SERVICE_NAME"
}

# ---------- 打印连接信息 ----------
print_info() {
    local ip="$1"
    local insecure_flag=""
    [[ $USE_LETSENCRYPT == false ]] && insecure_flag="&insecure=1"

    echo
    echo "🎉 Hysteria2 部署成功！（安全增强版）"
    echo "=========================================================================="
    echo "🔑 密码（请妥善保存）: $AUTH_PASSWORD"
    echo ""
    echo "📱 节点链接:"
    echo "hysteria2://${AUTH_PASSWORD}@${ip}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}${insecure_flag}#Hy2-Secure"
    echo ""
    echo "📄 客户端配置示例:"
    echo "server: ${ip}:${SERVER_PORT}"
    echo "auth: ${AUTH_PASSWORD}"
    echo "tls:"
    echo "  sni: ${SNI}"
    echo "  alpn: [\"${ALPN}\"]"
    [[ $USE_LETSENCRYPT == false ]] && echo "  insecure: true"
    echo "socks5:"
    echo "  listen: 127.0.0.1:1080"
    echo "=========================================================================="
    echo

    # 防火墙提示
    info "📌 请确保防火墙已放行端口: $SERVER_PORT (TCP/UDP)"
    echo "  示例命令："
    echo "    ufw: sudo ufw allow $SERVER_PORT/tcp && sudo ufw allow $SERVER_PORT/udp"
    echo "    firewalld: sudo firewall-cmd --permanent --add-port=$SERVER_PORT/udp --add-port=$SERVER_PORT/tcp && sudo firewall-cmd --reload"
    echo "    iptables: iptables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT && iptables -A INPUT -p tcp --dport $SERVER_PORT -j ACCEPT"
}

# ---------- 主流程 ----------
main() {
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    echo "Hysteria2 安全增强部署脚本"
    echo "端口: $SERVER_PORT | 域名(SNI): $SNI"
    [[ $USE_LETSENCRYPT == true ]] && echo "✅ 启用 Let's Encrypt 证书（需 80 端口开放）"
    [[ $INSTALL_AS_SERVICE == true ]] && echo "✅ 安装为 systemd 服务"
    echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

    download_and_verify
    setup_certificates
    write_config
    install_systemd_service

    local ip
    ip=$(get_public_ip)

    print_info "$ip"

    if [[ $INSTALL_AS_SERVICE == false ]]; then
        info "启动 Hysteria2 服务（前台运行）..."
        exec "$BIN_PATH" server -c "$CONFIG_FILE"
    else
        info "服务已在后台运行（systemd）。"
    fi
}

main "$@"
