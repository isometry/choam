package updater

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// ChecksumHelper handles SHA256 calculation for URLs and files
type ChecksumHelper struct {
	httpClient *http.Client
}

// NewChecksumHelper creates a new checksum helper
func NewChecksumHelper() *ChecksumHelper {
	return &ChecksumHelper{
		httpClient: &http.Client{
			Timeout: 60 * time.Second, // Longer timeout for downloads
		},
	}
}

// NewChecksumHelperWithClient creates a checksum helper with custom HTTP client
func NewChecksumHelperWithClient(client *http.Client) *ChecksumHelper {
	return &ChecksumHelper{
		httpClient: client,
	}
}

// CalculateSHA256FromURL downloads content from a URL and calculates its SHA256
func (ch *ChecksumHelper) CalculateSHA256FromURL(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request for %s: %w", url, err)
	}

	resp, err := ch.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, url)
	}

	// Calculate SHA256 while reading
	hasher := sha256.New()

	// Use a buffer to avoid loading entire file into memory
	buffer := make([]byte, 32*1024) // 32KB buffer

	for {
		n, err := resp.Body.Read(buffer)
		if n > 0 {
			hasher.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("reading response from %s: %w", url, err)
		}
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// CalculateSHA256FromFile calculates SHA256 hash of a local file
func (ch *ChecksumHelper) CalculateSHA256FromFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("opening file %s: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("reading file %s: %w", filePath, err)
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
