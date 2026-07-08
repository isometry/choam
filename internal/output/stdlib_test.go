package output

import (
	"testing"

	"github.com/isometry/choam/internal/gobump"
	"github.com/stretchr/testify/assert"
)

func TestDistinctStdlibVulnIDs(t *testing.T) {
	t.Run("nil bumps", func(t *testing.T) {
		assert.Nil(t, DistinctStdlibVulnIDs(nil))
	})

	t.Run("empty bumps", func(t *testing.T) {
		assert.Nil(t, DistinctStdlibVulnIDs([]gobump.StdlibBump{}))
	})

	t.Run("single bump, single constraint", func(t *testing.T) {
		bumps := []gobump.StdlibBump{
			{GoPackagePin: "1.22", VulnIDs: []string{"GO-STD-2", "GO-STD-1"}},
		}
		assert.Equal(t, []string{"GO-STD-1", "GO-STD-2"}, DistinctStdlibVulnIDs(bumps))
	})

	t.Run("same vuln ID recurs across pin constraints - deduped", func(t *testing.T) {
		bumps := []gobump.StdlibBump{
			{GoPackagePin: "1.22", VulnIDs: []string{"GO-STD-1", "GO-STD-2"}},
			{GoPackagePin: "1.23", VulnIDs: []string{"GO-STD-1", "GO-STD-3"}},
		}
		assert.Equal(t, []string{"GO-STD-1", "GO-STD-2", "GO-STD-3"}, DistinctStdlibVulnIDs(bumps))
	})

	t.Run("unlinked vuln IDs are not counted as fixable", func(t *testing.T) {
		bumps := []gobump.StdlibBump{
			{GoPackagePin: "1.22", VulnIDs: []string{"GO-STD-1"}, UnlinkedVulnIDs: []string{"GO-STD-9"}},
		}
		assert.Equal(t, []string{"GO-STD-1"}, DistinctStdlibVulnIDs(bumps))
	})

	t.Run("no fixable IDs in any constraint", func(t *testing.T) {
		bumps := []gobump.StdlibBump{
			{GoPackagePin: "1.22", UnlinkedVulnIDs: []string{"GO-STD-9"}},
		}
		assert.Nil(t, DistinctStdlibVulnIDs(bumps))
	})
}
