# Hysteria2 纯净一键安装脚本
✅ 安全 · 无后门 · 无第三方依赖 · 仅从 GitHub 官方源下载
🛡️ 不收集 IP · 不连接非必要服务 · 私钥权限严格限制

## 这是一个为 Hysteria2 服务端设计的纯净版一键安装脚本,适用于 Ubuntu、Debian、CentOS 等主流 Linux 发行版。脚本完全本地运行，所有组件均从 apernet/hysteria 官方仓库下载，无任何隐藏行为，阿里云实测过。

## 使用建议
## 1. 运行脚本前先更新系统
```
sudo apt update && sudo apt upgrade -y  # Debian/Ubuntu
或
sudo yum update -y  # CentOS

```
## 2.重启 (可选)： sudo reboot

## 3.安裝必要工具： 
```
# Debian/Ubuntu
sudo apt update && sudo apt install -y curl openssl coreutils gawk

# CentOS/Rocky/AlmaLinux
sudo yum install -y curl openssl coreutils gawk
# 或（较新版本）
sudo dnf install -y curl openssl coreutils gawk

```

## 4.一键部署脚本

```

curl -fsSL -o hy2.sh https://raw.githubusercontent.com/fuckGFW2015/hy2/refs/heads/main/hy2.sh && chmod +x hy2.sh && ./hy2.sh -p 29999 --service

```
## 默认端口29999，自定义的话，在-p后面加上你的服务器端口。比如./hy2.sh -p 3183 --service

## 5.一键开启 BBR加速（要求 Linux 内核 ≥ 4.9）
BBR 要求：
Linux 内核 ≥ 4.9
（搬瓦工大多数系统如 Ubuntu 20.04+/Debian 10+ 默认满足）
检查内核版本：
uname -r
✅ 如果输出类似 5.4.0, 5.15.0, 6.1.0 等 → 支持 BBR。

```
# 清理旧配置并启用 BBR
sudo sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
echo 'net.core.default_qdisc=fq' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_congestion_control=bbr' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

```
## 6.验证BBR是否启用

```
cc=$(cat /proc/sys/net/ipv4/tcp_congestion_control)

echo "当前拥塞控制算法：$cc"

[[ "$cc" == "bbr" ]] && echo "✅ BBR 已启用" || echo "❌ BBR 未启用"

sysctl net.ipv4.tcp_congestion_control
# 应输出：net.ipv4.tcp_congestion_control = bbr

lsmod | grep bbr
# 应看到 bbr 模块（如：bbr 20480 12）

```

## 7.卸载脚本

```
#!/bin/bash

# 停止并移除服务
sudo systemctl stop hysteria2.service
sudo systemctl disable hysteria2.service
sudo rm -f /etc/systemd/system/hysteria2.service
sudo systemctl daemon-reload

# 删除安装目录
sudo rm -rf /etc/hysteria2

# 删除用户（可选）
sudo userdel hysteria2 2>/dev/null || true

# 清理内核优化
sudo rm -f /etc/sysctl.d/99-hysteria.conf
sudo sysctl --system >/dev/null 2>&1

# 关闭防火墙端口（默认 29999，如使用其他端口请先修改！）
PORT=29999

if command -v ufw &>/dev/null; then
    sudo ufw delete allow "$PORT/tcp" 2>/dev/null || true
    sudo ufw delete allow "$PORT/udp" 2>/dev/null || true
elif command -v firewall-cmd &>/dev/null; then
    sudo firewall-cmd --permanent --remove-port="$PORT/tcp" 2>/dev/null || true
    sudo firewall-cmd --permanent --remove-port="$PORT/udp" 2>/dev/null || true
    sudo firewall-cmd --reload
fi

echo "✅ Hysteria2 已完全卸载！"

```

## 8. 验证卸载结果
```
执行完后，可以手动检查
# 检查服务是否存在
systemctl list-unit-files | grep hysteria2

# 检查文件是否删除
ls /etc/hysteria2  # 应该提示“没有那个文件或目录”

# 检查端口是否关闭
ss -uln | grep ':29999'  # 应该无输出
```

# 安全保证

本脚本严格遵循以下安全原则：

🔒 所有二进制文件 仅从 https://github.com/apernet/hysteria 下载

🌐 获取公网 IP 时仅连接一次公开服务 ifconfig.me（该服务声称不记录访问日志），不会将 IP 发送给任何第三方或作者服务器。

🔑 仅连接到可信的GitHub和Let's Encrypt服务，无隐藏的数据上传或外联

🧹 无隐藏服务、无后门命令、无多余依赖

✅ 无警告、无冗余、无兼容性问题

脚本逻辑完全透明，欢迎任何人审计源码。

```





