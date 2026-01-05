一键安装命令

```

bash <(curl -fsSL https://raw.githubusercontent.com/fuckGFW2015/hy2/refs/heads/main/hy2.sh)

```
或

```
# 下载脚本
curl -fsSL https://raw.githubusercontent.com/fuckGFW2015/hy2/refs/heads/main/hy2.sh -o hy2.sh
# 修改脚本中的 BIN_PATH 变量，或者直接在有权限的目录下运行
sudo bash hy2.sh

```

若出现一下错误

```
INFO: 启动 Hysteria2 服务（前台运行）...
/dev/fd/63: line 277: /home/container/hysteria-linux-amd64: Permission denied

```
你可以尝试先执行这一行命令，看看能否解决当前目录的权限问题：

```
chmod +x hysteria-linux-amd64 && ./hysteria-linux-amd64 server -c server.yaml

```

自定义端口

直接使用 sed 工具（几乎所有系统都自带）来强行替换配置文件中的端口：

```
# 假设你想把端口从 29999 改成 443
sed -i 's/listen: ":29999"/listen: ":443"/' server.yaml

```
修改完后，别忘了重启你的 Hysteria2 程序：

```
./hysteria-linux-amd64 server -c server.yaml

```
#**如果看到 server up and running {"listen": ":3102"}，说明服务器已经就绪。**

用 cat 命令确认一下是否修改成功：

```
cat server.yaml

```




