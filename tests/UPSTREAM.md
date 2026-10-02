# 上游场景与真实网络验证

## 1. 版本与运行

上游源码：EasyTier v2.6.4，commit `8428a89d2dabc94c97d370ec607c6ca142473626`。Rust 对端使用系统已安装的 `easytier-core 2.6.4`。Go 使用恢复后的 Go 1.20 配置和依赖版本，测试工具链为 Go 1.20.14。

上游源码中的输入和断言迁移到 Go 测试；下表区分直接迁移、部分断言迁移和场景适配。上游 Rust 测试本身没有编译或运行。

```sh
GOTOOLCHAIN=go1.20.14 go test -tags upstream ./... -run Upstream -v -count=1
GOTOOLCHAIN=go1.20.14 go test -race -tags upstream ./... -count=1
```

迁移测试使用 `upstream` build tag，作为显式运行的兼容性检查；普通 `go test ./...` 运行常规回归测试。两组现均通过。

## 2. 用例对应

源文件链接均固定到上述 commit。迁移的 12 个测试函数均通过；参数化子用例详见日志。

| 上游测试 | Go 对应 | 适配与结果 |
|---|---|---|
| [packet_def.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/tunnel/packet_def.rs)：`test_zc_packet` | `internal/wire/TestUpstreamPacketLayout` | 保留 `hello world`、长度 11、Data 类型和往返载荷断言；Rust 零拷贝 buffer 类型转换不适用。通过 |
| 同文件：`test_short_tcp_packet_header_access_is_safe` | `internal/wire/TestUpstreamShortPacket` | 保留单字节输入；Rust 返回 None，Go 的 ParseHeader/ParsePacket 返回错误。通过 |
| [common.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/tunnel/common.rs)：`framed_reader_rejects_short_peer_manager_body` | `internal/transport/TestUpstreamShortFrame` | 相同的 15 字节 peer header body 和长度前缀，断言拒绝。通过 |
| [tcp.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/tunnel/tcp.rs)：`tcp_pingpong`；[udp.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/tunnel/udp.rs)：`udp_pingpong` | `internal/transport/TestUpstreamTunnelPingpong` | 使用原载荷 `12345678abcdefg`、5 秒截止时间；经真实 TCP/UDP socket 收发帧。两项通过 |
| udp.rs：`test_v4_hole_punch_packet` | `internal/transport/TestUpstreamV4PunchPacket` | 2 秒内收到 IPv4 探测包；额外检查 Go 协议头和 transaction ID。通过 |
| [aes_gcm.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/peers/encrypt/aes_gcm.rs)：`test_aes_gcm_cipher` | `internal/peerconn/TestUpstreamAESGCM` | 相同的全零 128-bit key、`1234567`、28 字节 tail、加密标志和解密载荷断言。通过 |
| [peer_session.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/peers/peer_session.rs)：`peer_session_supports_asymmetric_algorithms`；[secure_datagram.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/peers/secure_datagram.rs)：`secure_datagram_supports_asymmetric_algorithms` | `internal/peerconn/TestUpstreamAsymmetricAlgorithms` | 相同的 peer 10/20、双向载荷和 AES-256-GCM/ChaCha20-Poly1305 组合。`chacha20-poly1305` 与 `chacha20` 两种名称均通过 |
| secure_datagram.rs：`replay_window_out_of_order_within_window` | `internal/peerconn/TestUpstreamOutOfOrderWindow` | 保留序号 0–20、先偶数后奇数、拒绝重复包；通过真实加解密入口测试。通过 |
| secure_datagram.rs：`sync_root_key_keeps_previous_epochs_during_grace_window` | `internal/peerconn/TestUpstreamSyncEpochGrace` | 保留 epoch 0/1 → SYNC → 2/1/0 的接收顺序。Go 本地发送算法设为其 SYNC 接口要求的 AES-128-GCM，接收仍为 AES-256-GCM。SYNC 后的 epoch 2、1、0 均通过 |
| [peer_conn.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/peers/peer_conn.rs)：`peer_conn_handshake_same_id` | `internal/peerconn/TestUpstreamHandshakeSameID` | Rust ring tunnel 换为本机 TCP；保留双方使用相同 PeerID、双方握手均失败的断言。通过 |
| [peer_ospf_route.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/peers/peer_ospf_route.rs)：`test_raw_peer_info`、`sync_route_preserves_unknown_fields_for_shared_sender` | `internal/peerconn/TestUpstreamRouteUnknownFields` | 迁移共享节点 route info 的存储/转发与未知字段 9999=42 保留断言，覆盖 list/bitmap；不覆盖 credential proof 处理。通过 |
| peer_ospf_route.rs：`test_connect_at_different_time` | 根包 `TestUpstreamLatePeerJoin` | A–B 收敛后才接入 C，保持链式拓扑；用双向 TCP 服务验证 A–C 通信，覆盖 Legacy/Noise。通过 |

## 3. 网络场景

[three_node.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/tests/three_node.rs) 的 `basic_three_node_test`、`relay_peer_e2e_encryption` 和 `relay_peer_session_cleanup` 对应现有 `rust-loopback.sh`、`interop.sh`。选择 TCP/UDP 与 Go 支持的 Legacy/Noise 模式，保留三节点及中继故障场景；原来的 ICMP 连通检查换为 TCP/UDP echo 服务。Rust 或 Go 分别担任中继，共 12 项通过。

| 上游打洞测试 | 隔离场景 | 结果 |
|---|---|---|
| [sym_to_cone.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/connector/udp_hole_punch/sym_to_cone.rs)：`hole_punching_symmetric_only_predict(true/false)` | `symmetric-nat.sh predicted` / `decremental` | 两项通过 |
| 同文件：`hole_punching_symmetric_only_random` | `symmetric-nat.sh random` | 通过 |
| [both_easy_sym.rs](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/connector/udp_hole_punch/both_easy_sym.rs)：`hole_punching_easy_sym(true/false)` | 新增 `both-inc-dec` / `both-dec-inc`，两端分别递增/递减 | 两项通过 |
| 项目原有补充场景 | `symmetric-nat.sh both`，两端递增 | 通过 |

上游以 mock STUN/NAT 驱动打洞；这里用 Linux 网络命名空间中的 NAT 和本地 STUN，保持端口变化方向。成功标准是收到对端 UDP 连接，并在屏蔽中继后完成双向 TCP/UDP 业务通信。

DHCP 没有找到同等的上游独立测试；对应 [instance.rs::check_dhcp_ip_conflict](https://github.com/EasyTier/EasyTier/blob/8428a89d2dabc94c97d370ec607c6ca142473626/easytier/src/instance/instance.rs) 的分配逻辑，使用现有分配/保留/冲突/耗尽单测和 `nat-dhcp.sh` 回归。实际验证 `.1` 冲突后迁移到 `.2`，通过。

```sh
sudo bash tests/symmetric-nat.sh both-inc-dec
sudo bash tests/symmetric-nat.sh both-dec-inc
```

其他网络场景的运行命令见 [RESULTS.md](RESULTS.md)。

## 4. 兼容性修复

### 4.1. 算法名

`trafficCipher` 已将 `chacha20-poly1305` 加入现有 ChaCha20-Poly1305 分支。三个算法名产生相同密文，均能解密；未知名称仍返回错误，会话内的算法名称一致性检查保持原样。

```sh
GOTOOLCHAIN=go1.20.14 go test -tags upstream ./internal/peerconn -run 'TestUpstreamAsymmetricAlgorithms/chacha20-poly1305' -v -count=1
```

### 4.2. SYNC 后的接收窗口

根密钥相同的 SYNC 会把原来的两个接收窗口保存为五秒快照，再清空常规窗口。旧 epoch 的包在快照中校验和记录；到期后清除快照。CREATE 或根密钥变化会清空两组窗口，JOIN 保持现有状态。连续 SYNC 使用最新常规窗口替换快照。

```sh
GOTOOLCHAIN=go1.20.14 go test -tags upstream ./internal/peerconn -run TestUpstreamSyncEpochGrace -v -count=1
```

上述两个原失败用例均通过。常规测试新增 `session_sync_test.go`，覆盖别名、未知算法、重复包、快照到期、换密钥、CREATE/JOIN、连续 SYNC 和解密失败时的状态保持。到期测试直接调整内部截止时间。

## 5. 真实 SSH

执行 `GOTOOLCHAIN=go1.20.14 go run ./tests/live`。驱动针对本机 `easytier.service` 和 `root@10.114.0.2:22`，从服务进程参数读取网络身份，沿用本机 SSH 密钥/agent 与 known_hosts。只在手动运行该命令时访问真实网络。

系统网络基线和以下三轮均执行 `id -u; hostname`，结果都是 `0` 与 `w568w-pi`：

| Go 的接入点 | 临时虚拟地址 | SSH | Go 连接发送/接收字节 |
|---|---|---|---|
| `tcp://127.0.0.1:11010` | `10.114.0.254/24` | 成功 | 4314 / 2818 |
| `udp://127.0.0.1:11010` | `10.114.0.254/24` | 成功 | 4314 / 2818 |
| `tcp://sh.kyln24.top:11020` | `10.114.0.253/24` | 成功 | 4314 / 2818 |

每轮也验证了 `w568w-pi` 和 `w568w-pi.et.net` 解析到 `10.114.0.2`。OpenSSH 关闭连接复用，通过本地转发器使用 `Server.Dial` 返回的连接；表中字节数由该连接的双向复制计数得出。

结束后 `easytier.service` 仍为 active/running，PID 保持 1523；原有 `.1/.2/.3` 路由保留，临时节点已从路由表消失。

## 6. 日志与范围

日志在 `build/upstream-review/`：`adapted.log`、`late-join.log`、`compatibility.jsonl`、`race-upstream.log`、`race-baseline.log`、`interop.log`、`nat-*.log`、`live.log`、`live-debug.log`。固定版本的上游源码保存在该目录的 `source/`。

修复后的普通测试、带 `upstream` tag 的全套 race 测试、vet 和纯 Go 构建均通过。修复回归日志保存在 `build/session-compat/`，此前差异的复现日志保留在 `build/upstream-review/`。

本轮覆盖表中选取的协议场景。未覆盖 WireGuard、WebSocket、QUIC、IPv6、credential 身份等 Go 未实现的功能，也未把场景适配结果称为上游 Rust 全套测试通过。
