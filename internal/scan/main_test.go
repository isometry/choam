package scan

import (
	"os"
	"testing"
)

// The git-range pass talks to the module proxy; tests exercise it by setting
// scanner.proxyURL explicitly and must never reach a real one otherwise.
func TestMain(m *testing.M) {
	_ = os.Setenv("GOPROXY", "off")
	os.Exit(m.Run())
}
