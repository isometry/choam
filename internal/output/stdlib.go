package output

import "github.com/isometry/choam/internal/gobump"

// DistinctStdlibVulnIDs returns a file's distinct fixable stdlib
// vulnerability IDs across all of its StdlibBump entries, sorted for
// deterministic display. gobump.evaluateStdlibStaleness records one
// StdlibBump per go-package pin constraint, so the same vulnerability ID can
// recur across constraints (e.g. a package pinning both go1.22 and go1.23
// toolchains, both affected by the same stdlib CVE) - callers that count or
// list stdlib vulnerabilities per file must dedupe via this function rather
// than summing len(bump.VulnIDs) across bumps.
func DistinctStdlibVulnIDs(bumps []gobump.StdlibBump) []string {
	return gobump.DistinctStdlibVulnIDs(bumps)
}
