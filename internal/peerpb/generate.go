package peerpb

// Wire-compatible subset of EasyTier ff3921ce6842f9660d629eafac499498026c6784.
// Descriptor packages/files use an easytier_go/etg_ prefix to coexist with the
// upstream WASM host protobufs in Mihomo. Field numbers and types are unchanged.
// Generate with protoc-gen-go v1.31.0 (Go 1.20 compatible).
//go:generate protoc -I schema -I /usr/include --go_out=. --go_opt=paths=source_relative schema/etg_common.proto schema/etg_error.proto schema/etg_peer_rpc.proto
