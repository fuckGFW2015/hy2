#!/usr/bin/env bash
# Hysteria2 一键卸载脚本
# 支持自动识别端口与清理系统残留

set -u

# ========== 日志函数 ==========
log() { echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"; }

# 确保以 root 权限运行
if [[ $EUID -ne 0 ]]; then
   echo "请使用 sudo 或 root 用户运行此脚本"
   exit 1
fi

INSTALL_DIR="/etc/hysteria2"
SERVICE_NAME="hysteria2.service"
CONF_FILE="$INSTALL_DIR/server.yaml"

log "开始卸载 Hysteria2..."

# 1. 提取端口号（防止防火墙清理错误）
PORT=29999 # 默认值
if [[ -f "$CONF_FILE" ]]; then
    EXTRACTED_PORT=$(grep "listen:" "$CONF_FILE" | awk -F ':' '{print $NF}' | tr -d '" ' )
    if [[ "$EXTRACTED_PORT" =~ ^[0-9]+$ ]]; then
        PORT=$EXTRACTED_PORT
        log "检测到运行端口: $PORT"
    fi
fi

# 2. 停止并移除 systemd 服务
if systemctl is-active --quiet "$SERVICE_NAME"; then
    log "正在停止服务..."
    systemctl stop "$SERVICE_NAME"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME"; then
    log "正在禁用服务..."
    systemctl disable "$SERVICE_NAME"
fi

log "移除 systemd 配置文件..."
rm -f "/etc/systemd/system/$SERVICE_NAME"
systemctl daemon-reload

# 3. 清理防火墙规则
log "清理防火墙端口: $PORT..."
if command -v ufw &>/dev/null; then
    ufw delete allow "$PORT/tcp" >/dev/null 2>&1 || true
    ufw delete allow "$PORT/udp" >/dev/null 2>&1 || true
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --remove-port="$PORT/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port="$PORT/udp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1
fi

# 4. 删除安装目录与残留文件
if [[ -d "$INSTALL_DIR" ]]; then
    log "删除安装目录: $INSTALL_DIR"
    rm -rf "$INSTALL_DIR"
fi

# 5. 删除专用系统用户
if id "hysteria2" &>/dev/null; then
    log "删除系统用户: hysteria2"
    userdel hysteria2 2>/dev/null || true
fi

# 6. 还原内核参数优化
HY_SYSCTL="/etc/sysctl.d/99-hysteria.conf"
if [[ -f "$HY_SYSCTL" ]]; then
    log "还原内核参数设置..."
    rm -f "$HY_SYSCTL"
    sysctl --system >/dev/null 2>&1 || true
fi

echo "---------------------------------------"
echo "✅ Hysteria2 已成功从你的系统中卸载！"
echo "---------------------------------------"
