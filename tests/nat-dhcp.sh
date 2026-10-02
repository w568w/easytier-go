#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
logs=$(mktemp -d /tmp/easytier-go-nat.XXXXXX)
tag=etn-$$
a=$tag-a; x=$tag-x; r=$tag-r; y=$tag-y; c=$tag-c
pids=()
cleanup(){ for p in "${pids[@]}";do kill -TERM "$p" 2>/dev/null||true;done;for p in "${pids[@]}";do wait "$p" 2>/dev/null||true;done;for n in "$a" "$x" "$r" "$y" "$c";do ip netns del "$n" 2>/dev/null||true;done;echo "logs=$logs"; }
trap cleanup EXIT
for n in "$a" "$x" "$r" "$y" "$c";do ip netns add "$n";ip -n "$n" link set lo up;done
link(){ ip -n "$1" link add "$2" type veth peer name "$4" netns "$3";ip -n "$1" addr add "$5" dev "$2";ip -n "$3" addr add "$6" dev "$4";ip -n "$1" link set "$2" up;ip -n "$3" link set "$4" up; }
link "$a" eth0 "$x" lan 10.20.0.2/24 10.20.0.1/24
link "$x" wan "$r" ar 192.0.2.2/24 192.0.2.1/24
link "$c" eth0 "$y" lan 10.30.0.2/24 10.30.0.1/24
link "$y" wan "$r" cr 198.51.100.2/24 198.51.100.1/24
ip -n "$a" route add default via 10.20.0.1
ip -n "$c" route add default via 10.30.0.1
ip -n "$x" route add default via 192.0.2.1
ip -n "$y" route add default via 198.51.100.1
for n in "$x" "$r" "$y";do ip netns exec "$n" sysctl -qw net.ipv4.ip_forward=1;done
for n in "$x" "$y";do
 ip netns exec "$n" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
 # Fixed endpoint-independent mapping; FORWARD still rejects unsolicited traffic.
 inner=10.20.0.2; if [[ $n == "$y" ]]; then inner=10.30.0.2; fi
 ip netns exec "$n" iptables -t nat -A PREROUTING -i wan -p udp -j DNAT --to-destination "$inner"
 ip netns exec "$n" iptables -P FORWARD DROP
 ip netns exec "$n" iptables -A FORWARD -i lan -j ACCEPT
 ip netns exec "$n" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
ip netns exec "$r" "$repo/build/stun" 0.0.0.0:3478 >"$logs/stun.log" 2>&1 & pids+=($!)
ip netns exec "$r" easytier-core --network-name nat-test --network-secret secret --secure-mode true --listeners tcp://0.0.0.0:11010 --disable-p2p true --stun-servers 192.0.2.1:3478 --stun-servers-v6 --disable-ipv6 true --console-log-level warn --disable-env-parsing >"$logs/relay.log" 2>&1 & pids+=($!)
ip netns exec "$c" easytier-core --network-name nat-test --network-secret secret --secure-mode true --peers tcp://198.51.100.1:11010 --no-listener --disable-p2p true --stun-servers 198.51.100.1:3478 --stun-servers-v6 --disable-ipv6 true --ipv4 10.199.0.3 --dev-name et-c --console-log-level warn --disable-env-parsing >"$logs/c.log" 2>&1 & pids+=($!)
ip netns exec "$a" "$repo/build/easytier-go" -network-name nat-test -network-secret secret -secure-mode -peer 192.0.2.1:11010 -udp-listen 0.0.0.0:0 -udp-punch -stun 192.0.2.1:3478 -dhcp -dhcp-subnet 10.199.0.0/24 >"$logs/a.log" 2>&1 & pids+=($!)
if [[ ${model:-rust} != both ]];then
 ip netns exec "$c" "$repo/build/service" serve :18081 >"$logs/service.log" 2>&1 & pids+=($!)
fi
probe() { ip netns exec "$a" curl --noproxy '*' -fsS --max-time 8 'http://127.0.0.1:18080/probe?target=10.199.0.3:18081'; }
# Observe a punched endpoint, not only a UDP path to the public relay.
ok=false
for i in $(seq 1 45);do
 if grep -q 'UDP connected peer=.*address=198.51.100.2:' "$logs/a.log";then ok=true;break;fi
 sleep 1
done
if [[ $ok != true ]];then tail -n 35 "$logs/"*.log;exit 1;fi
ip netns exec "$a" curl --noproxy '*' -fsS http://127.0.0.1:18080/status | tee "$logs/dhcp.log"
# No more TCP packets may use the rendezvous relay.
ip netns exec "$r" iptables -I INPUT -p tcp --dport 11010 -j DROP
ip netns exec "$r" iptables -I OUTPUT -p tcp --sport 11010 -j DROP
ip netns exec "$r" iptables -I INPUT -p udp ! --dport 3478 -j DROP
ip netns exec "$r" iptables -I OUTPUT -p udp ! --sport 3478 -j DROP
probe | tee "$logs/a-to-c.log"
if [[ ${model:-rust} == both ]];then
 ip netns exec "$c" curl --noproxy '*' -fsS --max-time 8 'http://127.0.0.1:18080/probe?target=10.199.0.1:18081' | tee "$logs/c-to-a.log"
else
 ip netns exec "$c" "$repo/build/service" probe 10.199.0.1:18081 | tee "$logs/c-to-a.log"
fi
sleep 7
probe | tee "$logs/udp-after-tcp-timeout.log"
# Rejoin Rust with the address currently occupied by DHCP; Go must move to .2.
ip netns exec "$r" iptables -F INPUT
ip netns exec "$r" iptables -F OUTPUT
kill -TERM "${pids[2]}"
wait "${pids[2]}" || true
ip netns exec "$c" easytier-core --network-name nat-test --network-secret secret --secure-mode true --peers tcp://198.51.100.1:11010 --no-listener --disable-p2p true --stun-servers 198.51.100.1:3478 --stun-servers-v6 --disable-ipv6 true --ipv4 10.199.0.1 --dev-name et-c --console-log-level warn --disable-env-parsing >"$logs/conflict.log" 2>&1 & pids[2]=$!
ok=false
for i in $(seq 1 35);do
 if ip netns exec "$a" curl --noproxy '*' -fsS http://127.0.0.1:18080/status | grep -q '10.199.0.2';then ok=true;break;fi
 sleep 1
done
if [[ $ok != true ]];then tail -n 30 "$logs/a.log";exit 1;fi
ok=false
for i in $(seq 1 20);do
 if ip netns exec "$c" "$repo/build/service" probe 10.199.0.2:18081 >"$logs/conflict-probe.log" 2>&1;then ok=true;break;fi
 sleep 1
done
if [[ $ok != true ]];then exit 1;fi
ip netns exec "$c" "$repo/build/service" probe 10.199.0.2:18081 | tee "$logs/after-conflict.log"
grep -q "PASS TCP UDP" "$logs/after-conflict.log"
echo 'PASS: two NATs, DHCP allocation/conflict, UDP punch, data survives relay loss'
