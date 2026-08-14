package output

import (
	"sort"

	"github.com/isometry/choam/internal/gobump"
)

// DistinctStdlibVulnIDs returns a file's distinct fixable stdlib
// vulnerability IDs across all of its StdlibBump entries, sorted for
// deterministic display. gobump.evaluateStdlibStaleness records one
// StdlibBump per go-package pin constraint, so the same vulnerability ID can
// recur across constraints (e.g. a package pinning both go1.22 and go1.23
// toolchains, both affected by the same stdlib CVE) - callers that count or
// list stdlib vulnerabilities per file must dedupe via this function rather
// than summing len(bump.VulnIDs) across bumps.
func DistinctStdlibVulnIDs(bumps []gobump.StdlibBump) []string {
	if len(bumps) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var ids []string
	for _, bump := range bumps {
		for _, id := range bump.VulnIDs {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}
