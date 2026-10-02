# 嵌入式网络库验收

日期：2026-10-02。测试使用当前工作区的嵌入式 `Server` 和重新生成的 protobuf，生产 TUN/CLI 已删除。Go 测试驱动位于 `tests/driver`，通过真实 TCP/UDP echo 验证业务通信，不用 ping 代替业务检查。

## 环境与版本

- 库：Go 1.20.14；race、vet、构建均使用该版本。
- gVisor：`github.com/metacubex/gvisor v0.0.0-20260922041103-e2cbcd6e7400`。
- Protobuf：运行库及生成器 `v1.31.0`。恢复 hostname 字段 6 和错误 oneof 字段 1–8；descriptor 包/文件改用独立前缀，wire 编码不变。
- Rust：`easytier-core 2.6.4`。
- Mihomo：`88dcbf7f1614a67c3b36b848ee3592dfa92ada36`，独立 checkout `../easytier-mihomo-check`。
- 宿主：Linux x86_64。macOS/Windows/Android 项为交叉构建，不代表在对应设备上运行过。

## 已验证项目

| 范围 | 验证内容 | 结果 |
|---|---|---|
| 普通应用 | 三实例，TCP/UDP 底层 × Legacy/Noise，HTTP、双向 TCP、大于 MTU 的流、UDP 多目标、relay、节点名 | 通过；非 root，无 TUN |
| 名称 | 短名、`.et.net`、重名歧义、实例隔离 | 通过 |
| 生命周期 | New 无宿主 IO、重复 Start/Close、Close 后不可重启、Up/Dial 取消、初始化阻塞时取消、未完成拨号释放 | 通过 |
| 换址 | 旧 TCP 流关闭、显式旧地址监听关闭、通配 TCP/UDP 继续工作 | 通过 |
| HostNetwork | 标准接口包装对象、TCP dial/listen、DNS、UDP、重连、失败不回退、STUN、25/84 socket 池、关闭释放 | 通过 |
| Rust 直连 | TCP/UDP 底层 × Legacy/Noise，节点名，双向 TCP/UDP | 通过 |
| Rust/Go 中继 | TCP/UDP 底层 × Legacy/Noise × Rust/Go relay；双向业务和 relay 重启恢复 | 通过 |
| NAT + DHCP | 双 NAT、打洞后屏蔽 relay、TCP/UDP 持续通信、地址冲突后从 `.1` 换到 `.2` | 通过 |
| 对称 NAT | 递增预测、递减预测、随机端口、双端递增；屏蔽 relay 后业务通信 | 通过 |
| Mihomo | 实际 outbound、配置解析、C.Conn/C.PacketConn、DNS、注入、取消/关闭、多实例、两套 protobuf 并存 | 通过 |
| 检查 | Go 1.20 全套 race、vet、纯 Go build；Mihomo 定向 race 和完整纯 Go 二进制构建 | 通过 |
| 平台 | Linux amd64、macOS arm64、Windows amd64、Android arm64，Go 1.20，CGO_ENABLED=0 | 构建通过 |

NAT 外部测试驱动也注入了 `HostNetwork`，把连接、PacketConn 和地址包装为标准接口对象。源码检查中，生产代码的系统 socket/DNS 创建只出现在 `hostnet.System`；其余模块使用注入接口。Mihomo 接入保留自身 dialer 的接口绑定、routing mark、代理和移动端策略；实际 Android VPN 环境未在本机运行。

## 重跑命令

普通用户执行：

```sh
GOTOOLCHAIN=go1.20.14 go test -race ./...
GOTOOLCHAIN=go1.20.14 go vet ./...
CGO_ENABLED=0 GOTOOLCHAIN=go1.20.14 go build ./...
go build -o build/easytier-go ./tests/driver
go build -o build/service ./tests/service
go build -o build/stun ./tests/stun
go build -o build/nat ./tests/nat
```

Linux 隔离拓扑需要 `ip`、`iptables`、`curl`、Rust `easytier-core`、TUN/veth/netfilter 模块。root 只用于建立测试拓扑和 Rust TUN，不是 Go 嵌入库的运行要求：

```sh
for mode in secure legacy; do
  for transport in tcp udp; do
    sudo bash tests/rust-loopback.sh "$mode" "$transport" direct
    sudo bash tests/interop.sh "$mode" rust go "$transport"
    sudo bash tests/interop.sh "$mode" go rust "$transport"
  done
done
sudo bash tests/nat-dhcp.sh
for model in predicted decremental random both; do
  sudo bash tests/symmetric-nat.sh "$model"
done
```

Mihomo 命令及示例在 [mihomo/README.md](mihomo/README.md)。该 checkout 的适配实现保存在项目中，可重新应用；不依赖 `/tmp` 中的源码。

完整命令输出保存在 `build/validation/`，属于本地生成物：`race.log`、`vet.log`、`build.log`、`platforms.log`、`rust-matrix.log`、`rust-initiator.log`、`nat-*.log`、`mihomo*.log`。NAT 脚本末尾打印各节点详细日志目录。

## 注入网络的实测计数

最后一轮外部测试的 Go 驱动返回标准接口包装对象，退出时记录如下。DNS 使用数字 STUN 地址，因此此处为 0；域名 DNS 注入另由库测试和 Mihomo 测试覆盖。

```text
predicted: host calls dial=3 listen=0 packet=86 dns=0
decremental: host calls dial=3 listen=0 packet=86 dns=0
random: host calls dial=2 listen=0 packet=86 dns=0
both: host calls dial=3 listen=0 packet=27 dns=0
both responder: host calls dial=3 listen=0 packet=27 dns=0
dhcp: host calls dial=3 listen=0 packet=1 dns=0
```

## 底层接口内部化回归（2026-10-02）

`peerconn`、`route`、`wire`、`transport`、`hostnet` 已移入 `internal/`。删除独立连接模式后，非心跳消息统一由 `Node.handle` 处理。原有底层测试随包迁移，断言保留；配置、取消和就绪机制未调整。

| 检查 | 结果 |
|---|---|
| 根包 API | `go doc -all` 前后对比无差异；独立 `example.com/easytier-consumer` 模块实现 `HostNetwork` 并启动 `Server` 成功 |
| 外部导入限制 | 五个底层包均触发 `use of internal package ... not allowed`；旧目录及兼容包装不存在 |
| Go 1.20 | 全套测试、race、vet、纯 Go 构建通过；Linux amd64、macOS arm64、Windows amd64、Android arm64 库交叉构建通过 |
| Rust 2.6.4 | TCP/UDP × Legacy/Noise 的直连及 Rust/Go 中继共 12 项通过，包含双向业务和中继重启恢复 |
| NAT / DHCP | 递增、递减、随机、双端对称 NAT，以及 DHCP 冲突换址均通过 |
| Mihomo | 原有适配代码无需修改；outbound/config 定向 race 测试及完整 `CGO_ENABLED=0` 构建通过 |

本轮输出保存于 `build/internalize/`：`race.log`、`vet.log`、`build.log`、`platforms.log`、`rust-matrix.log`、`nat-*.log`、`mihomo-*.log`。独立消费者验证位于该目录的 `consumer/`，五项拒绝导入输出为 `deny-*.log`。

## 上游场景与真实网络验证（2026-10-02）

Go 1.20 及对应依赖已恢复。复用 EasyTier v2.6.4 的测试源码，新增的 12 个兼容测试函数现均通过：算法名补齐 `chacha20-poly1305`，SYNC 按上游规则保存五秒旧接收窗口快照。迁移用例由 `upstream` build tag 运行；常规测试另外覆盖快照生命周期与算法名称。

12 项 Rust/Go 互通、六种对称 NAT 场景及 DHCP 冲突换址通过。通过本机 TCP、本机 UDP、公网 peer 三条路径，Go 实例均成功完成 `root@10.114.0.2` 的 SSH 认证和远程命令执行。现有服务 PID 和原路由保留，临时节点已清理。

修复后普通测试、带 `upstream` tag 的全套 race 测试、vet、纯 Go 构建，以及六项 Rust Noise 直连/中继/重连检查均通过。日志见 `build/session-compat/`。

用例映射、适配差异、修复说明和完整结果见 [UPSTREAM.md](UPSTREAM.md)。
