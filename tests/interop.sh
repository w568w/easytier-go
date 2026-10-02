#!/usr/bin/env bash
# Run as root: isolated A -- relay -- C, no direct underlay path between A and C.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:-secure}
relay_impl=${2:-rust}
initiator=${3:-go}
transport=${4:-tcp}
if [[ $transport == udp ]];then go_listen=-udp-listen;go_peer=-udp-peer;else go_listen=-listen;go_peer=-peer;fi
run_dir=$(mktemp -d /tmp/easytier-go-interop.XXXXXX)
tag=etg-$$
a=$tag-a
r=$tag-r
c=$tag-c
pids=()
cleanup() {
 for pid in "${pids[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
 for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
 for ns in "$a" "$r" "$c"; do ip netns del "$ns" 2>/dev/null || true; done
 echo "logs=$run_dir"
}
trap cleanup EXIT
for ns in "$a" "$r" "$c"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip -n "$a" link add eth0 type veth peer name ar netns "$r"
ip -n "$c" link add eth0 type veth peer name cr netns "$r"
ip -n "$a" addr add 192.0.2.2/24 dev eth0
ip -n "$r" addr add 192.0.2.1/24 dev ar
ip -n "$c" addr add 198.51.100.2/24 dev eth0
ip -n "$r" addr add 198.51.100.1/24 dev cr
ip -n "$a" link set eth0 up
ip -n "$c" link set eth0 up
ip -n "$r" link set ar up
ip -n "$r" link set cr up
secure=false
if [[ $mode == secure ]]; then secure=true; fi
common=(--network-name interop --network-secret test-secret --secure-mode "$secure" --disable-p2p true --stun-servers --stun-servers-v6 --disable-ipv6 true --console-log-level warn --disable-env-parsing)
start_relay() {
if [[ $relay_impl == rust ]]; then
 ip netns exec "$r" easytier-core "${common[@]}" --listeners "$transport://0.0.0.0:11010" --rpc-portal 127.0.0.1:15888 >"$run_dir/relay.log" 2>&1 &
else
 ip netns exec "$r" "$repo/build/easytier-go" -network-name interop -network-secret test-secret -secure-mode="$secure" "$go_listen" 0.0.0.0:11010 >"$run_dir/relay.log" 2>&1 &
fi
relay_pid=$!
}
start_relay
pids+=($relay_pid)
ip netns exec "$c" easytier-core "${common[@]}" --peers "$transport://198.51.100.1:11010" --no-listener --ipv4 10.199.0.3 --dev-name et-c --rpc-portal 127.0.0.1:15888 >"$run_dir/c.log" 2>&1 &
pids+=($!)
ip netns exec "$a" "$repo/build/easytier-go" -network-name interop -network-secret test-secret -secure-mode="$secure" "$go_peer" 192.0.2.1:11010 -ipv4 10.199.0.1/32 >"$run_dir/a.log" 2>&1 &
pids+=($!)
ip netns exec "$c" "$repo/build/service" serve :18081 >"$run_dir/service.log" 2>&1 &
pids+=($!)
# Wait for TCP and UDP payload delivery.
probe() { ip netns exec "$a" curl --noproxy '*' -fsS --max-time 8 'http://127.0.0.1:18080/probe?target=10.199.0.3:18081'; }
probe_initial() {
 if [[ $initiator == rust ]];then ip netns exec "$c" "$repo/build/service" probe 10.199.0.1:18081;else probe;fi
}
ok=false
for i in $(seq 1 30); do if probe_initial >"$run_dir/probe.log" 2>&1;then ok=true;break;fi;sleep 1;done
if [[ $ok != true ]];then tail -n 30 "$run_dir/"*.log;exit 1;fi
probe | tee "$run_dir/a-to-c.log"
ip netns exec "$c" "$repo/build/service" probe 10.199.0.1:18081 | tee "$run_dir/c-to-a.log"
# Restart the relay; both endpoints must reconnect and regain routes.
kill -TERM "$relay_pid"
wait "$relay_pid" || true
start_relay
pids[0]=$relay_pid
ok=false
for i in $(seq 1 30); do
 if probe >"$run_dir/reconnect-probe.log" 2>&1; then ok=true; break; fi
 sleep 1
done
if [[ $ok != true ]]; then tail -n 30 "$run_dir/"*.log; exit 1; fi
probe | tee "$run_dir/reconnected.log"
kill -TERM "${pids[2]}"
wait "${pids[2]}"
if ip -n "$a" -o link show | grep -q "et-a"; then echo "unexpected TUN"; exit 1; fi
echo "PASS mode=$mode relay=$relay_impl initiator=$initiator transport=$transport"
