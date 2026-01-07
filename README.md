# Hysteria2 纯净一键安装脚本
✅ 安全 · 无后门 · 无第三方依赖 · 仅从 GitHub 官方源下载
🛡️ 不收集 IP · 不连接非必要服务 · 私钥权限严格限制

## 这是一个为 Hysteria2 服务端设计的纯净版一键安装脚本,适用于 Ubuntu、Debian、CentOS 等主流 Linux 发行版。脚本完全本地运行，所有组件均从 apernet/hysteria 官方仓库下载，无任何隐藏行为。

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
# 2. 一键部署（无需 sudo！）
curl -fsSL -o hy2.sh https://raw.githubusercontent.com/fuckGFW2015/hy2/main/hy2.sh && chmod +x hy2.sh && ./hy2.sh -p 29999 --service

```
## 默认端口29999，自定义的话，在-p后面加上你的服务器端口。比如sudo ./hy2.sh -p 3183 --service
## 5.一键开启 BBR（要求 Linux 内核 ≥ 4.9）
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





