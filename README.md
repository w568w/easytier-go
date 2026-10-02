# easytier-go

在 Go 应用中使用 EasyTier 虚拟网络的桥接库。

暴露标准 `net.Conn`、`net.Listener` 和 `net.PacketConn` 收发 TCP、UDP 数据。

## 1. 安装

在应用的 Go 模块目录中引用本地源码，将 `/path/to/easytier-go` 替换为本仓库的绝对路径：

```sh
go mod edit -replace=github.com/easytier/easytier-go=/path/to/easytier-go
go get github.com/easytier/easytier-go@v0.0.0
```

## 2. 使用

### 2.1. 快速开始

在本仓库目录启动服务端：

```sh
go run ./examples/http
```

服务端通过本机 `127.0.0.1:21110` 接受 EasyTier 连接，在虚拟地址 `10.42.0.1:8080` 提供 HTTP 服务。

在已完成安装的应用目录中，将下面的客户端保存为 `main.go`：

```go
package main

import (
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"time"

	easytier "github.com/easytier/easytier-go"
)

func main() {
	s, err := easytier.New(easytier.Config{
		NetworkName:   "example",
		NetworkSecret: "replace-me",
		Hostname:      "client",
		IPv4:          netip.MustParsePrefix("10.42.0.2/24"),
		Peers:         []string{"tcp://127.0.0.1:21110"},
		Encryption:    easytier.Noise,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	transport := &http.Transport{DialContext: s.Dial}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("http://10.42.0.1:8080/")
	if err != nil {
		log.Print(err)
		return
	}
	defer response.Body.Close()
	if _, err = io.Copy(os.Stdout, response.Body); err != nil {
		log.Print(err)
	}
}
```

运行客户端：

```sh
go run .
```

输出：

```text
hello from web.et.net
```

节点信息同步后，也可以用 `web` 或 `web.et.net` 代替虚拟 IP。

### 2.2. TCP 与 UDP

| 操作 | 调用 |
|---|---|
| 连接虚拟网络中的服务 | `s.Dial(ctx, "tcp", "web.et.net:8080")` |
| 接受 TCP 连接 | `s.Listen("tcp", ":8080")` |
| 创建 UDP socket | `s.ListenPacket("udp", ":0")` |
| 查询节点地址 | `s.LookupHost(ctx, "web")` |

## 3. 配置

```go
cfg := easytier.Config{
	NetworkName:   "example",    // 网络名称
	NetworkSecret: "replace-me", // 网络密码
	Hostname:      "client",     // 节点名，可通过 client 或 client.et.net 访问

	IPv4:       netip.MustParsePrefix("10.42.0.2/24"), // 固定虚拟 IPv4
	DHCP:       false,                                 // 自动分配地址；启用时将 IPv4 留空
	DHCPSubnet: netip.Prefix{},                        // DHCP 子网；留空则从其他节点学习

	Peers:     []string{"tcp://127.0.0.1:21110"}, // 对端地址，支持 tcp:// 和 udp://
	Listeners: []string{"tcp://127.0.0.1:0"},     // 本地 TCP 监听地址；nil 表示不监听
	UDP: easytier.UDPConfig{
		Listen:    "127.0.0.1:0", // 本地 UDP 监听地址，端口 0 表示自动分配
		Advertise: "",            // 已知的公网映射 IP:port，与 STUN 二选一
		STUN:      "",            // STUN 服务器地址，格式为 host:port
		Punch:     false,         // 启用 UDP 打洞
		NAT:       "auto",        // auto、symmetric、incremental 或 decremental
	},

	Encryption:  easytier.Noise,  // Legacy（默认）或 Noise
	PrivateKey:  nil,             // Noise 的 32 字节 X25519 私钥；nil 表示自动生成
	PeerID:      0,               // 节点 ID；0 表示自动生成
	Timeout:     5 * time.Second, // 连接与握手超时，默认 5 秒
	Logf:        log.Printf,      // 日志回调；nil 表示不输出
	HostNetwork: nil,             // 宿主网络实现；nil 使用默认实现
}
```

### 3.1. 自定义宿主网络

通过 `Config.HostNetwork` 提供底层网络的 Socket 和 DNS 实现：

```go
type HostNetwork interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error)
	LookupIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}
```

默认使用 Go 标准库作为 Backend。


## 4. 开发

```sh
go test -race ./...
go vet ./...
CGO_ENABLED=0 go build ./...
```

Rust 互通和 NAT 测试的运行方法见 [tests/RESULTS.md](tests/RESULTS.md)。
