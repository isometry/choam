package gobump

import (
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGoPackagePin(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantBase  string
		wantMinor string
		wantOK    bool
	}{
		{"bare go", "go", "go", "", true},
		{"go-1.24", "go-1.24", "go", "1.24", true},
		{"go-fips no minor", "go-fips", "go-fips", "", true},
		{"go-fips-1.24", "go-fips-1.24", "go-fips", "1.24", true},
		{"go-1.9", "go-1.9", "go", "1.9", true},
		{"go-1.10 distinct from go-1.9", "go-1.10", "go", "1.10", true},
		{"golang is not a toolchain pin", "golang", "", "", false},
		{"rust is not go", "rust", "", "", false},
		{"empty value", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, minor, ok := parseGoPackagePin(tt.value)
			require.Equal(t, tt.wantOK, ok)
			if !tt.wantOK {
				return
			}
			assert.Equal(t, tt.wantBase, base)
			assert.Equal(t, tt.wantMinor, minor)
		})
	}
}

func TestGoToolchainPins(t *testing.T) {
	t.Run("go/build pinned, go/install unpinned, subpackage go/build pinned differently, non-go steps ignored", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "git-checkout"},
				{Uses: "go/build", With: map[string]string{"go-package": "go-1.24"}},
				{Uses: "go/install"},
				{Uses: "cargo/build", With: map[string]string{"modroot": "."}},
			},
			Subpackages: []melange.Subpackage{
				{Name: "sub", Pipeline: []melange.Pipeline{
					{Uses: "go/build", With: map[string]string{"go-package": "go-fips-1.23"}},
				}},
			},
		}

		pins := goToolchainPins(cfg)
		require.Len(t, pins, 3)
		assert.Equal(t, GoToolchainPin{Package: "go-1.24", Minor: "1.24"}, pins[0])
		assert.Equal(t, GoToolchainPin{Package: "", Minor: ""}, pins[1])
		assert.Equal(t, GoToolchainPin{Package: "go-fips-1.23", Minor: "1.23"}, pins[2])
	})

	t.Run("templated go-package resolved via vars block", func(t *testing.T) {
		cfg := &melange.Configuration{
			Vars: map[string]string{"go-pkg": "go-1.24"},
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"go-package": "${{vars.go-pkg}}"}},
			},
		}

		pins := goToolchainPins(cfg)
		require.Len(t, pins, 1)
		assert.Equal(t, GoToolchainPin{Package: "go-1.24", Minor: "1.24"}, pins[0])
	})

	t.Run("unresolvable template keeps raw value and is treated as unpinned", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{
				{Uses: "go/build", With: map[string]string{"go-package": "${{vars.missing}}"}},
			},
		}

		pins := goToolchainPins(cfg)
		require.Len(t, pins, 1)
		assert.Equal(t, "${{vars.missing}}", pins[0].Package)
		assert.Equal(t, "", pins[0].Minor)
	})

	t.Run("no matching steps returns empty", func(t *testing.T) {
		cfg := &melange.Configuration{
			Pipeline: []melange.Pipeline{{Uses: "git-checkout"}, {Uses: "cargo/build"}},
		}
		assert.Empty(t, goToolchainPins(cfg))
	})
}

func TestDistinctMinorConstraints(t *testing.T) {
	t.Run("empty input returns unpinned only", func(t *testing.T) {
		assert.Equal(t, []string{""}, distinctMinorConstraints(nil))
	})

	t.Run("mixed pins incl. duplicates and unpinned, numeric ordering", func(t *testing.T) {
		pins := []GoToolchainPin{
			{Minor: "1.24"},
			{Minor: "1.9"},
			{Minor: ""},
			{Minor: "1.10"},
			{Minor: "1.24"},
			{Minor: "1.9"},
		}
		assert.Equal(t, []string{"", "1.9", "1.10", "1.24"}, distinctMinorConstraints(pins))
	})

	t.Run("all pinned, no unpinned entries", func(t *testing.T) {
		pins := []GoToolchainPin{{Minor: "1.25"}, {Minor: "1.24"}}
		assert.Equal(t, []string{"1.24", "1.25"}, distinctMinorConstraints(pins))
	})
}
