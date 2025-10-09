package updater

import (
	"fmt"
	"io"
	"os"
)

// withFileReader opens a file and ensures it's properly closed after the operation
// This reduces duplication of file opening/closing patterns
func withFileReader(filePath string, fn func(io.Reader) error) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("opening file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	return fn(file)
}
