#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# Hysteria2 增强部署脚本
# 融合安全加固 | 云原生适配 | ACME 可选 | 内核智能调优 | 阿里云友好
# 基于 stephchow 的 v3.6 脚本重构增强
# 更新: 2026-01-09

set -euo pipefail

# ========== 日志函数 ==========
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2; }
error() { log "❌ ERROR: $*" >&2; exit 1; }
warn() { log "⚠️ WARNING: $*" >&2; }
success() { log "✅ SUCCESS: $*"; }
section() { echo -e "\n--- $1 ---"; }

# ========== 基础配置 ==========
HYSTERIA_RELEASE_TAG="app/v2.6.5"
DEFAULT_PORT=443
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

# ========== 参数解析 ==========
SERVER_PORT="$DEFAULT_PORT"
INSTALL_AS_SERVICE=true   # 默认安装为服务（更符合生产场景）
ENABLE_ACME=false
USE_CLOUD_METADATA=false

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--port)
            if [ "$2" -eq "$2" ] 2>/dev/null && [ "$2" -ge 1 ] && [ "$2" -le 65535 ]; then
                SERVER_PORT="$2"; shift 2
            else
                error "端口无效"
            fi ;;
        --no-service) INSTALL_AS_SERVICE=false; shift ;;
        --acme) ENABLE_ACME=true; shift ;;
        --use-cloud-metadata) USE_CLOUD_METADATA=true; shift ;;
        *) shift ;;
    esac
done

# ========== 依赖检查 ==========
section "依赖检查"
for cmd in curl openssl sha256sum awk sudo grep; do
    command -v "$cmd" >/dev/null 2>&1 || error "缺少必要命令: $cmd"
done

# 检查 systemd（仅当需要安装服务时）
if [ "$INSTALL_AS_SERVICE" = true ]; then
    command -v systemctl >/dev/null 2>&1 || error "systemd 未找到，无法安装服务"
fi

# ========== 辅助函数 ==========

get_public_ip() {
    local ip=""
    if [ "$USE_CLOUD_METADATA" = true ]; then
        # 优先尝试阿里云元数据（更快更可靠）
        if ip=$(curl -s -f -m 3 http://100.100.100.200/latest/meta-data/public-ipv4 2>/dev/null); then
            echo "$ip"; return
        fi
    fi
    # 回退到公共 API
    for api in "https://api.ipify.org" "https://ifconfig.me/ip" "https://ipecho.net/plain"; do
        if ip=$(curl -s -f -m 3 "$api" 2>/dev/null) && [ -n "$ip" ] && [[ "$ip" =～ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"; return
        fi
    done
    echo "YOUR_PUBLIC_IP"
}

create_temp_dir() {
    mktemp -d "/tmp/hy2-XXXXXX" || error "无法创建临时目录"
}

# ========== 核心功能 ==========

download_binary() {
    section "下载 Hysteria2 二进制"
    local tmp_dir=$(create_temp_dir)
    local bin_path="$tmp_dir/${BIN_NAME}"
    log "正在下载 Hysteria2 (${bin_arch})..."
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
        [ "$actual_sha" = "$expected_sha" ] || error "SHA256 校验失败"
        success "SHA256 校验通过"
    else
        warn "无法获取官方哈希，跳过校验（不推荐）"
    fi
    chmod +x "$bin_path"
    echo "$bin_path"
}

setup_cert() {
    if [ "$ENABLE_ACME" = true ]; then
        error "ACME 模式暂未实现（预留接口），请使用默认自签名模式"
        # TODO: 集成 acme.sh 或 certbot
    fi

    section "生成自签名证书"
    local tmp_dir=$(create_temp_dir)
    log "生成自签名证书 (SNI: $SNI)..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -days 3650 -keyout "$tmp_dir/$KEY_FILE" -out "$tmp_dir/$CERT_FILE" \
        -subj "/CN=${SNI}" >/dev/null 2>&1 || error "证书生成失败"
    echo "$tmp_dir"
}

write_config() {
    section "生成配置文件"
    local tmp_dir=$(create_temp_dir)
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
  level: info
EOF
    echo "$pwd_str" > "$tmp_dir/password.txt"
    echo "$tmp_dir"
}

install_service() {
    if [ "$INSTALL_AS_SERVICE" = false ]; then return; fi
    section "安装 systemd 服务"
    id "$USER_NAME" >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
    sudo mkdir -p "$INSTALL_DIR"
    sudo cp "$BIN_PATH" "$INSTALL_DIR/${BIN_NAME}"
    sudo cp "$CERT_DIR/$CERT_FILE" "$INSTALL_DIR/"
    sudo cp "$CERT_DIR/$KEY_FILE" "$INSTALL_DIR/"
    sudo cp "$CONF_DIR/$CONFIG_FILE" "$INSTALL_DIR/"
    sudo cp "$CONF_DIR/password.txt" "$INSTALL_DIR/"

    # 特权端口授权
    if [ "$SERVER_PORT" -lt 1024 ]; then
        sudo setcap 'cap_net_bind_service=+ep' "$INSTALL_DIR/${BIN_NAME}" || warn "setcap 失败，可能影响特权端口绑定"
    fi
    
    sudo chown -R "$USER_NAME:$USER_NAME" "$INSTALL_DIR"
    sudo chmod 755 "$INSTALL_DIR"
    sudo chmod 600 "$INSTALL_DIR"/*.pem "$INSTALL_DIR"/*.txt "$INSTALL_DIR"/*.yaml
    sudo chmod +x "$INSTALL_DIR/${BIN_NAME}"

    sudo tee "/etc/systemd/system/${SERVICE_NAME}.service" > /dev/null <<EOF
[Unit]
Description=Hysteria2 Server (Qwen Enhanced)
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
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable "${SERVICE_NAME}.service" --quiet
    sudo systemctl restart "${SERVICE_NAME}.service"
}

fix_firewall_conflicts() {
    section "修复防火墙冲突"
    local protocols=("udp" "tcp")
    local ip_versions=("4")
    if command -v ip >/dev/null && ip -6 addr show scope global | grep -q inet6; then
        ip_versions+=("6")
    fi

    # iptables / ip6tables
    for ver in "${ip_versions[@]}"; do
        local ipt_cmd="iptables"
        [ "$ver" = "6" ] && ipt_cmd="ip6tables"
        if command -v "$ipt_cmd" >/dev/null 2>&1; then
            for proto in "${protocols[@]}"; do
                sudo "$ipt_cmd" -C INPUT -p "$proto" --dport "$SERVER_PORT" -j ACCEPT 2>/dev/null || \
                    sudo "$ipt_cmd" -I INPUT 1 -p "$proto" --dport "$SERVER_PORT" -j ACCEPT
            done
        fi
    done

    # UFW
    if command -v ufw >/dev/null 2>&1 && sudo ufw status | grep -qw "active"; then
        for proto in "${protocols[@]}"; do
            sudo ufw allow "${SERVER_PORT}/$proto" >/dev/null
        done
    fi

    # Firewalld
    if command -v firewall-cmd >/dev/null 2>&1 && sudo systemctl is-active --quiet firewalld; then
        for proto in "${protocols[@]}"; do
            sudo firewall-cmd --permanent --add-port="${SERVER_PORT}/$proto" >/dev/null 2>&1
        done
        sudo firewall-cmd --reload >/dev/null 2>&1
    fi
    success "防火墙策略已开放端口 ${SERVER_PORT} (IPv4/IPv6, TCP/UDP)"
}

tune_kernel() {
    section "内核参数优化"
    local conf_file="/etc/sysctl.d/99-hysteria-qwen.conf"
    
    # 检测 BBR 支持
    local enable_bbr=false
    if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q 'bbr'; then
        enable_bbr=true
    else
        warn "内核不支持 BBR，将跳过拥塞控制优化"
    fi

    # 构建 sysctl 配置
    {
        echo "# Hysteria2 Qwen 优化 (2026)"
        echo "net.core.rmem_max = 16777216"
        echo "net.core.wmem_max = 16777216"
        echo "net.ipv4.udp_rmem_min = 16384"
        echo "net.ipv4.udp_wmem_min = 16384"
        echo "net.nf_conntrack_max = 1048576"
        echo "net.netfilter.nf_conntrack_max = 1048576"
        echo "fs.file-max = 1000000"
        if [ "$enable_bbr" = true ]; then
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        fi
    } | sudo tee "$conf_file" > /dev/null

    sudo sysctl --system >/dev/null 2>&1 || true
    
    if [ "$enable_bbr" = true ]; then
        local cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
        [ "$cc" = "bbr" ] && success "BBR + FQ + UDP 缓冲区优化已生效" || warn "BBR 未激活，当前: $cc"
    else
        success "基础网络参数已优化（BBR 不可用）"
    fi
}

health_check() {
    if [ "$INSTALL_AS_SERVICE" = false ]; then return; fi
    section "服务健康检查"
    sleep 5
    if systemctl is-active --quiet "${SERVICE_NAME}.service"; then
        success "Hysteria2 服务运行正常"
    else
        error "服务启动失败。最后5行日志：\n$(sudo journalctl -u ${SERVICE_NAME}.service -n 5 --no-pager)"
    fi
}

cleanup() {
    [ -n "${TMP_DIRS:-}" ] && rm -rf $TMP_DIRS
}
trap cleanup EXIT

# ========== 主流程 ==========
section "🚀 开始部署 Hysteria2

BIN_PATH=$(download_binary)
CERT_DIR=$(setup_cert)
CONF_DIR=$(write_config)

# 记录临时目录用于清理
TMP_DIRS="$BIN_PATH $(dirname "$BIN_PATH") $CERT_DIR $CONF_DIR"

# 停止旧服务（如果存在）
sudo systemctl stop "${SERVICE_NAME}.service" 2>/dev/null || true

install_service
fix_firewall_conflicts
tune_kernel
health_check

FINAL_PWD=$(cat "$CONF_DIR/password.txt")
IP=$(get_public_ip)

echo -e "\n==========================================="
echo -e "🎉 Hysteria2 部署成功！(Qwen 增强版)"
echo -e "🔑 密码: ${FINAL_PWD}"
echo -e "🔗 链接: hysteria2://${FINAL_PWD}@${IP}:${SERVER_PORT}?sni=${SNI}&alpn=${ALPN}&insecure=1#Hy2-Qwen"
echo -e "📁 配置目录: ${INSTALL_DIR}"
echo -e "==========================================="
echo -e "\n⚠️  重要提示："
echo -e "   1. 阿里云用户：务必在【安全组】中放行 ${SERVER_PORT}/UDP（入方向）"
echo -e "   2. 客户端需开启 'Allow insecure certificates'"
echo -e "   3. 如需域名证书，请手动替换 ${INSTALL_DIR}/{cert,key}.pem 并重启服务"
