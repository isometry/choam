package ecosystem

import (
	"os"
	"path/filepath"
)

// WriteTempFiles materializes files into a fresh temporary directory,
// preserving their relative paths, for ecosystems whose underlying tooling
// requires a real directory rather than in-memory content (see the Rust
// ecosystem, whose omnibump analyzer has no checkout-free AnalyzeRemote).
// The caller must call the returned cleanup func when done.
func WriteTempFiles(files map[string][]byte) (dir string, cleanup func(), err error) {
	dir, err = os.MkdirTemp("", "choam-bump-*")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }

	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			cleanup()
			return "", nil, err
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			cleanup()
			return "", nil, err
		}
	}

	return dir, cleanup, nil
}
