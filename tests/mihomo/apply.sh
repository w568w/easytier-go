#!/usr/bin/env bash
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
checkout=${1:?usage: apply.sh MIHOMO_CHECKOUT}
[[ $(git -C "$checkout" rev-parse HEAD) == 88dcbf7f1614a67c3b36b848ee3592dfa92ada36 ]] || { echo 'wrong Mihomo revision';exit 1; }
cp "$repo/tests/mihomo/easytier_native.go.txt" "$checkout/adapter/outbound/easytier_native.go"
cp "$repo/tests/mihomo/easytier_native_test.go.txt" "$checkout/adapter/outbound/easytier_native_test.go"
cp "$repo/tests/mihomo/parser_test.go.txt" "$checkout/adapter/easytier_native_test.go"
if ! grep -q 'case "easytier-native"' "$checkout/adapter/parser.go";then
 patch -d "$checkout" -p1 < "$repo/tests/mihomo/parser.patch"
fi
cd "$checkout"
gofmt -w adapter/outbound/easytier_native*.go adapter/parser.go
go mod edit -require=github.com/easytier/easytier-go@v0.0.0 -replace="github.com/easytier/easytier-go=$repo"
