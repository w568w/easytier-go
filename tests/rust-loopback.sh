#!/usr/bin/env bash
# One isolated namespace; only Rust creates a TUN. No veth modules required.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
mode=${1:-secure};transport=${2:-tcp};topology=${3:-relay}
logs=$(mktemp -d /tmp/easytier-embedded-rust.XXXXXX)
ns=et-embed-$$;pids=()
cleanup(){ for p in "${pids[@]}";do kill -TERM "$p" 2>/dev/null||true;done;for p in "${pids[@]}";do wait "$p" 2>/dev/null||true;done;ip netns del "$ns" 2>/dev/null||true;echo "logs=$logs"; }
trap cleanup EXIT
ip netns add "$ns";ip -n "$ns" link set lo up
secure=false;[[ $mode == secure ]] && secure=true
common=(--network-name interop --network-secret test-secret --secure-mode "$secure" --disable-p2p true --stun-servers --stun-servers-v6 --disable-ipv6 true --console-log-level warn --disable-env-parsing)
start_relay(){ ip netns exec "$ns" easytier-core "${common[@]}" --listeners "$transport://127.0.0.1:11010" --rpc-portal 127.0.0.1:15888 >"$logs/relay.log" 2>&1 & relay_pid=$!; }
if [[ $topology == relay ]];then start_relay;pids+=($relay_pid);cconn=(--peers "$transport://127.0.0.1:11010" --no-listener);else cconn=(--listeners "$transport://127.0.0.1:11010");fi
ip netns exec "$ns" easytier-core "${common[@]}" "${cconn[@]}" --ipv4 10.199.0.3 --hostname rust-node --dev-name et-rust --rpc-portal 127.0.0.1:15889 >"$logs/rust.log" 2>&1 & pids+=($!)
peer=-peer;[[ $transport == udp ]] && peer=-udp-peer
ip netns exec "$ns" "$repo/build/easytier-go" -network-name interop -network-secret test-secret -secure-mode="$secure" "$peer" 127.0.0.1:11010 -ipv4 10.199.0.1/24 >"$logs/go.log" 2>&1 & pids+=($!)
ip netns exec "$ns" "$repo/build/service" serve :18081 >"$logs/service.log" 2>&1 & pids+=($!)
probe(){ ip netns exec "$ns" curl --noproxy '*' -fsS --max-time 8 'http://127.0.0.1:18080/probe?target=rust-node.et.net:18081'; }
wait_probe(){ for i in $(seq 1 30);do if probe >"$logs/probe.log" 2>&1;then return;fi;sleep 1;done;tail -n 25 "$logs/"*.log;return 1; }
wait_probe
probe | tee "$logs/go-to-rust.log"
ip netns exec "$ns" "$repo/build/service" probe 10.199.0.1:18081 | tee "$logs/rust-to-go.log"
if [[ $topology == relay ]];then
 kill -TERM "$relay_pid";wait "$relay_pid"||true;start_relay;pids[0]=$relay_pid
 wait_probe;probe | tee "$logs/reconnect.log"
fi
[[ $(ip -n "$ns" -o link show | wc -l) == 2 ]]
echo "PASS embedded Rust $mode $transport $topology: bidirectional TCP/UDP, names, cleanup"
