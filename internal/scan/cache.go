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

	// Git-range lookups (see gitrange.go): module proxy origins by
	// "module@version", proxy version lists by module, and OSV commit-query
	// results by commit hash.
	origins  map[string]originInfo
	versions map[string][]string
	commits  map[string][]*osvschema.Vulnerability
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
		origins:    make(map[string]originInfo),
		versions:   make(map[string][]string),
		commits:    make(map[string][]*osvschema.Vulnerability),
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
	c.origins = make(map[string]originInfo)
	c.versions = make(map[string][]string)
	c.commits = make(map[string][]*osvschema.Vulnerability)
}

// GetOrigin returns the cached proxy origin of a module@version.
func (c *VulnerabilityCache) GetOrigin(key string) (originInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	o, ok := c.origins[key]
	return o, ok
}

// SetOrigin caches the proxy origin of a module@version.
func (c *VulnerabilityCache) SetOrigin(key string, o originInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.origins[key] = o
}

// GetVersions returns the cached proxy version list of a module.
func (c *VulnerabilityCache) GetVersions(module string) ([]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.versions[module]
	return v, ok
}

// SetVersions caches the proxy version list of a module.
func (c *VulnerabilityCache) SetVersions(module string, versions []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.versions[module] = versions
}

// GetCommit returns the cached OSV commit-query result for a commit hash.
func (c *VulnerabilityCache) GetCommit(hash string) ([]*osvschema.Vulnerability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.commits[hash]
	return v, ok
}

// SetCommit caches the OSV commit-query result for a commit hash.
func (c *VulnerabilityCache) SetCommit(hash string, vulns []*osvschema.Vulnerability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.commits[hash] = vulns
}
