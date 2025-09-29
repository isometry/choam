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

// readFileWithContext reads a file and provides better error context
func readFileWithContext(filePath string, context string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("%s - reading file %s: %w", context, filePath, err)
	}
	return content, nil
}

// writeFileWithContext writes a file and provides better error context
func writeFileWithContext(filePath string, content []byte, context string) error {
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("%s - writing file %s: %w", context, filePath, err)
	}
	return nil
}
