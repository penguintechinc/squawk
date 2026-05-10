package zonecache

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Cache is a thread-safe in-memory DNS zone cache.
// Stores FQDN -> []dns.RR mappings. All FQDNs are normalized
// to lowercase with a trailing dot.
type Cache struct {
	mu    sync.RWMutex
	zones map[string][]dns.RR
}

// New creates a new empty zone cache.
func New() *Cache {
	return &Cache{
		zones: make(map[string][]dns.RR),
	}
}

// normalizeFQDN returns the FQDN in lowercase with trailing dot.
func normalizeFQDN(fqdn string) string {
	fqdn = strings.ToLower(fqdn)
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	return fqdn
}

// Set stores or replaces all DNS records for the given FQDN.
func (c *Cache) Set(fqdn string, rrs []dns.RR) {
	if len(rrs) == 0 {
		c.Delete(fqdn)
		return
	}

	fqdn = normalizeFQDN(fqdn)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.zones[fqdn] = append([]dns.RR{}, rrs...)
}

// Delete removes all records for the given FQDN.
func (c *Cache) Delete(fqdn string) {
	fqdn = normalizeFQDN(fqdn)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.zones, fqdn)
}

// Lookup returns the slice of records for the given FQDN, or nil if not found.
func (c *Cache) Lookup(fqdn string) []dns.RR {
	fqdn = normalizeFQDN(fqdn)
	c.mu.RLock()
	defer c.mu.RUnlock()
	rrs, ok := c.zones[fqdn]
	if !ok {
		return nil
	}
	// Return a copy to prevent external mutation
	return append([]dns.RR{}, rrs...)
}

// Clear removes all records from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.zones = make(map[string][]dns.RR)
}

// Len returns the number of unique FQDNs in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.zones)
}
