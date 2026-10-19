package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

// TestGoModRunnable guards the remedy choam prints when a toolchain is newer
// than its go/types (simulate.ErrToolchainTooNew): `go run
// github.com/isometry/choam@latest`. `go run`/`go install pkg@version`
// refuses a main module whose go.mod has replace or exclude directives, so
// either would break that command.
func TestGoModRunnable(t *testing.T) {
	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)
	mod, err := modfile.Parse("go.mod", content, nil)
	require.NoError(t, err)
	assert.Empty(t, mod.Replace, "replace directives break `go run github.com/isometry/choam@latest`")
	assert.Empty(t, mod.Exclude, "exclude directives break `go run github.com/isometry/choam@latest`")
}
