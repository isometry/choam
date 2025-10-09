package testhelpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// LoadTestYAML loads a YAML file from testdata directory
// Tries relative path first, then from project root
func LoadTestYAML(t *testing.T, name string) []byte {
	t.Helper()

	// Try relative path first (for tests in same package)
	path := filepath.Join("testdata", "melange", name)
	data, err := os.ReadFile(path)
	if err != nil {
		// Try from internal/ directory level
		path = filepath.Join("../testdata/melange", name)
		data, err = os.ReadFile(path)
	}

	require.NoError(t, err, "failed to load test YAML %s", name)
	return data
}
