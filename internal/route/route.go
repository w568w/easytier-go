// Package route maps virtual IP prefixes to EasyTier peers and next hops.
package route

import (
	"errors"
	"net/netip"
	"sync"
)

type Entry struct {
	Prefix  netip.Prefix
	PeerID  uint32
	NextHop uint32
}

type Table struct {
	mu      sync.RWMutex
	entries []Entry
}

func (t *Table) Add(e Entry) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	e.Prefix = e.Prefix.Masked()
	if !e.Prefix.IsValid() || e.PeerID == 0 || e.NextHop == 0 {
		return errors.New("route: invalid entry")
	}
	for i := range t.entries {
		if t.entries[i].Prefix == e.Prefix {
			t.entries[i] = e
			return nil
		}
	}
	t.entries = append(t.entries, e)
	return nil
}

func (t *Table) Lookup(addr netip.Addr) (Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var best Entry
	found := false
	for _, e := range t.entries {
		if e.Prefix.Contains(addr) && (!found || e.Prefix.Bits() > best.Prefix.Bits()) {
			best, found = e, true
		}
	}
	return best, found
}

func (t *Table) Replace(entries []Entry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = append([]Entry(nil), entries...)
}
func (t *Table) Entries() []Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return append([]Entry(nil), t.entries...)
}
