package ecosystem

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitDep(t *testing.T) {
	tests := []struct {
		dep, wantCoord, wantVersion string
	}{
		// Non-Rust grammars split on the last "@", exactly as before.
		{"golang.org/x/net@v0.56.0", "golang.org/x/net", "v0.56.0"},
		{"github.com/old/mod=github.com/new/mod@v1.2.3", "github.com/old/mod=github.com/new/mod", "v1.2.3"},
		{"github.com/old/mod@v1.0.0=github.com/new/mod@v1.2.3", "github.com/old/mod@v1.0.0=github.com/new/mod", "v1.2.3"},
		{"io.netty@netty-codec-http@4.1.94.Final", "io.netty@netty-codec-http", "4.1.94.Final"},
		{"serde@1.0.200", "serde", "1.0.200"},
		// Rust entry pinned to one locked version.
		{"rand@0.9.2=0.9.3", "rand@0.9.2", "0.9.3"},
	}

	for _, tt := range tests {
		t.Run(tt.dep, func(t *testing.T) {
			coord, version, ok := SplitDep(tt.dep)
			require.True(t, ok)
			assert.Equal(t, tt.wantCoord, coord)
			assert.Equal(t, tt.wantVersion, version)
		})
	}

	t.Run("no @ at all", func(t *testing.T) {
		_, _, ok := SplitDep("malformed")
		assert.False(t, ok)
	})
}
