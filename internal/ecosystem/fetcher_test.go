package ecosystem

import (
	"errors"
	"testing"
)

func TestCheckRepository(t *testing.T) {
	for url, supported := range map[string]bool{
		"https://github.com/owner/repo":          true,
		"https://github.com/owner/repo.git":      true,
		"https://github.com/owner/repo/":         true,
		"https://gitlab.com/owner/repo":          false,
		"git@github.com:owner/repo.git":          false,
		"https://github.com.evil.example/o/r":    false,
		"mirror+https://github.com/owner/repo":   false,
		"https://github.com/owner/repo/tree/foo": false,
		"":                                       false,
	} {
		err := CheckRepository(url)
		if supported && err != nil {
			t.Errorf("CheckRepository(%q) = %v, want nil", url, err)
		}
		if !supported && !errors.Is(err, ErrUnsupportedRepository) {
			t.Errorf("CheckRepository(%q) = %v, want ErrUnsupportedRepository", url, err)
		}
	}
}
