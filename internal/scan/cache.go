package scan

import (
	"sync"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Global vulnerability cache instance shared across the entire application
var globalVulnerabilityCache *VulnerabilityCache

// Initialize the global cache once
func init() {
	globalVulnerabilityCache = NewVulnerabilityCache()
}

// GetGlobalCache returns the shared global vulnerability cache
func GetGlobalCache() *VulnerabilityCache {
	return globalVulnerabilityCache
}

// VulnerabilityCache provides a thread-safe per-run cache of OSV lookups:
// batch-query results by package@version, and full advisory records by ID
// (one advisory typically affects many packages and recurs across files).
// Cached values are shared pointers returned directly to callers - treat them as
// read-only; mutating a cached *osvschema.Vulnerability corrupts every other holder.
type VulnerabilityCache struct {
	mu         sync.RWMutex
	entries    map[string][]*osvschema.Vulnerability // Key: "ecosystem|package@version"
	advisories map[string]*osvschema.Vulnerability   // Key: advisory ID
}

// cacheKeyFor builds an ecosystem-qualified cache key, preventing collisions
// between packages that share a name+version across different ecosystems
// (e.g. a Go module and a crate of the same name and version).
func cacheKeyFor(ecosystem, name, version string) string {
	return ecosystem + "|" + name + "@" + version
}

// NewVulnerabilityCache creates a new vulnerability cache
func NewVulnerabilityCache() *VulnerabilityCache {
	return &VulnerabilityCache{
		entries:    make(map[string][]*osvschema.Vulnerability),
		advisories: make(map[string]*osvschema.Vulnerability),
	}
}

// Get retrieves cached vulnerability results for a package@version key
// Returns the vulnerabilities and true if found, empty slice and false if not found
func (c *VulnerabilityCache) Get(key string) ([]*osvschema.Vulnerability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	vulns, ok := c.entries[key]
	return vulns, ok
}

// Set stores vulnerability results for a package@version key
func (c *VulnerabilityCache) Set(key string, vulns []*osvschema.Vulnerability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = vulns
}

// GetAdvisory returns the cached full record for an advisory ID.
func (c *VulnerabilityCache) GetAdvisory(id string) (*osvschema.Vulnerability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	record, ok := c.advisories[id]
	return record, ok
}

// SetAdvisory caches the full record for an advisory ID.
func (c *VulnerabilityCache) SetAdvisory(id string, record *osvschema.Vulnerability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advisories[id] = record
}

// Size returns the number of entries in the cache
func (c *VulnerabilityCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries from the cache
func (c *VulnerabilityCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string][]*osvschema.Vulnerability)
	c.advisories = make(map[string]*osvschema.Vulnerability)
}
