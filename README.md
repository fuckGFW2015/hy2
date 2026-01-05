一键安装命令

```

bash <(curl -fsSL https://raw.githubusercontent.com/fuckGFW2015/hy2/refs/heads/main/hy2.sh)

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


