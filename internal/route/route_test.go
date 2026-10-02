package route

import (
	"net/netip"
	"testing"
)

func TestLookupLongestPrefix(t *testing.T) {
	var table Table
	if err := table.Add(Entry{Prefix: netip.MustParsePrefix("10.0.0.0/8"), PeerID: 2, NextHop: 2}); err != nil {
		t.Fatal(err)
	}
	if err := table.Add(Entry{Prefix: netip.MustParsePrefix("10.1.0.0/16"), PeerID: 3, NextHop: 4}); err != nil {
		t.Fatal(err)
	}
	got, ok := table.Lookup(netip.MustParseAddr("10.1.2.3"))
	if !ok || got.PeerID != 3 || got.NextHop != 4 {
		t.Fatalf("lookup = %#v, %v", got, ok)
	}
}
