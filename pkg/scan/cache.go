package scan

import (
	"sync"

	"github.com/google/osv-scanner/pkg/models"
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

// VulnerabilityCache provides a thread-safe cache for vulnerability scan results
// to avoid redundant API calls for the same package@version combinations within a single run
type VulnerabilityCache struct {
	mu      sync.RWMutex
	entries map[string][]models.Vulnerability // Key: "package@version"
}

// NewVulnerabilityCache creates a new vulnerability cache
func NewVulnerabilityCache() *VulnerabilityCache {
	return &VulnerabilityCache{
		entries: make(map[string][]models.Vulnerability),
	}
}

// Get retrieves cached vulnerability results for a package@version key
// Returns the vulnerabilities and true if found, empty slice and false if not found
func (c *VulnerabilityCache) Get(key string) ([]models.Vulnerability, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	vulns, ok := c.entries[key]
	return vulns, ok
}

// Set stores vulnerability results for a package@version key
func (c *VulnerabilityCache) Set(key string, vulns []models.Vulnerability) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = vulns
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
	c.entries = make(map[string][]models.Vulnerability)
}
