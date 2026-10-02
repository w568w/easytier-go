# Mihomo 集成验收

目标 commit：`88dcbf7f1614a67c3b36b848ee3592dfa92ada36`。适配源码使用 `.go.txt` 保存，避免主库引入 Mihomo 依赖；应用到独立 checkout 后作为真正的 outbound 编译。

```sh
git clone https://github.com/MetaCubeX/mihomo.git ../easytier-mihomo-check
git -C ../easytier-mihomo-check checkout 88dcbf7f1614a67c3b36b848ee3592dfa92ada36
bash tests/mihomo/apply.sh ../easytier-mihomo-check
cd ../easytier-mihomo-check
CGO_ENABLED=0 go test -mod=mod ./adapter ./adapter/outbound -run '^TestNative'
go test -race -mod=mod ./adapter ./adapter/outbound -run '^TestNative'
CGO_ENABLED=0 go build -mod=mod .
```

示例配置：

```yaml
proxies:
  - name: et-lab
    type: easytier-native
    network-name: example
    network-secret: replace-me
    hostname: mihomo
    ipv4: 10.42.0.2/24
    peers: [tcp://127.0.0.1:21110]
    secure-mode: true
    udp-listen: 0.0.0.0:0
    # interface-name: eth0
    # routing-mark: 1234
    # dialer-proxy: upstream
```

业务 TCP/UDP 的目标可使用虚拟 IP 或节点名。Mihomo DNS 可引用现有 `easytier://et-lab` DNS transport 注册机制；A 查询由 `Server.LookupHost` 转换为 DNS 响应，AAAA 返回空结果，因为当前 overlay 为 IPv4。短名和 `hostname.et.net` 均可用。

`mihomoNetwork` 通过 `BasicOption.NewDialer` 保留 interface、routing mark、dialer-proxy 和移动端 socket 控制策略。TCP 监听使用 `dialer.Listen` 及相同 options；代理/自定义 dialer 无法提供 TCP 监听时明确返回错误。UDP 返回标准 `net.PacketConn` 即可，不需要 fd。启用打洞需要宿主 dialer 提供可接收多个来源数据包的 UDP 语义。

测试使用实际 Mihomo `C.Conn/C.PacketConn` 包装、Metadata 和配置解析，检查名称 DNS、注入调用、数据收发、context 取消、Close、多实例隔离、两套 EasyTier protobuf 并存。移动端系统 socket 策略由既有 Mihomo 实现执行；本测试不模拟 Android 系统 VPN 环境。
