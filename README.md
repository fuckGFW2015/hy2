# Hysteria2 纯净一键安装脚本
✅ 安全 · 无后门 · 无第三方依赖 · 仅从 GitHub 官方源下载
🛡️ 不收集 IP · 不连接非必要服务 · 私钥权限严格限制

## 这是一个为 Hysteria2 服务端设计的纯净版一键安装脚本，低内存环境优化,适用于 Ubuntu、Debian、CentOS 等主流 Linux 发行版。脚本完全本地运行，所有组件均从 apernet/hysteria 官方仓库下载，无任何隐藏行为。

# 一键安装命令

```

bash <(curl -fsSL https://raw.githubusercontent.com/fuckGFW2015/hy2/refs/heads/main/hy2.sh)

```
## 或

```
# 下载脚本
curl -fsSL https://raw.githubusercontent.com/fuckGFW2015/hy2/refs/heads/main/hy2.sh -o hy2.sh
# 修改脚本中的 BIN_PATH 变量，或者直接在有权限的目录下运行
sudo bash hy2.sh

```

# 若出现以下错误

```
INFO: 启动 Hysteria2 服务（前台运行）...
/dev/fd/63: line 277: /home/container/hysteria-linux-amd64: Permission denied

```
你可以尝试先执行这一行命令，看看能否解决当前目录的权限问题：

```
chmod +x hysteria-linux-amd64 && ./hysteria-linux-amd64 server -c server.yaml

```

# 修改自定义端口

直接使用 sed 工具（几乎所有系统都自带）来强行替换配置文件中的端口：

```
## 假设你想把端口从 29999 改成 443（或者VPS服务器分配的端口）
sed -i 's/listen: ":29999"/listen: ":443"/' server.yaml

```
修改完后，别忘了重启你的 Hysteria2 程序：

```
./hysteria-linux-amd64 server -c server.yaml

```
## **如果看到 server up and running {"listen": ":443"}，说明服务器已经就绪。**

# 重启一下VPS,用 cat 命令确认一下是否修改成功：

```
cat server.yaml

```
## （看一下Listen端口，是否是你指定的端口）

# 安全保证

```

本脚本严格遵循以下安全原则：

🔒 所有二进制文件 仅从 https://github.com/apernet/hysteria 下载

🌐 不上报服务器公网 IP，获取公网IP时使用ifconfig.me（公开、可信的IP查询服务）

🔑 仅连接到可信的GitHub和Let's Encrypt服务，无隐藏的数据上传或外联

🧹 无隐藏服务、无后门命令、无多余依赖

脚本逻辑完全透明，欢迎任何人审计源码。

```





