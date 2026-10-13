package gobump

import (
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGoTargetArches(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   []string
		want []string
	}{
		{"absent: melange's default", nil, []string{"amd64", "arm64"}},
		{"x86_64", []string{"x86_64"}, []string{"amd64"}},
		{"aarch64", []string{"aarch64"}, []string{"arm64"}},
		{"both, any order", []string{"aarch64", "x86_64"}, []string{"amd64", "arm64"}},
		{"GOARCH spellings", []string{"arm64", "amd64"}, []string{"amd64", "arm64"}},
		{"all", []string{"all"}, []string{"amd64", "arm64"}},
		{"others mapped", []string{"armv7", "ppc64le", "x86_64"}, []string{"amd64", "arm", "ppc64le"}},
		{"unknown only: default", []string{"pdp11"}, []string{"amd64", "arm64"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &melange.Configuration{Package: melange.Package{TargetArchitecture: tt.in}}
			assert.Equal(t, tt.want, goTargetArches(t.Context(), cfg))
		})
	}

	t.Run("threaded onto every go unit", func(t *testing.T) {
		cfg := &melange.Configuration{
			Package:  melange.Package{TargetArchitecture: []string{"x86_64"}, Annotations: map[string]string{"choam/bump-go": "cmd/annotated"}},
			Pipeline: []melange.Pipeline{{Uses: "go/build"}},
		}
		units, _ := goUnits(t, cfg)
		require.Len(t, units, 2)
		for _, unit := range units {
			assert.Equal(t, []string{"amd64"}, unit.Arches, unit.Modroot)
		}
	})
}
