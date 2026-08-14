package golang

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

func TestNeedsGoSumMerge(t *testing.T) {
	parse := func(t *testing.T, goDirective string) *modfile.File {
		t.Helper()
		src := "module example.com/app\n"
		if goDirective != "" {
			src += "go " + goDirective + "\n"
		}
		modFile, err := modfile.Parse("go.mod", []byte(src), nil)
		require.NoError(t, err)
		return modFile
	}

	tests := []struct {
		name      string
		modFile   *modfile.File
		wantMerge bool
	}{
		{"nil modfile - fail wide", nil, true},
		{"missing go directive - fail wide", parse(t, ""), true},
		{"go 1.16 - pre-pruning, merge", parse(t, "1.16"), true},
		{"go 1.16.5 - pre-pruning, merge", parse(t, "1.16.5"), true},
		{"go 1.17 - pruning invariant, skip", parse(t, "1.17"), false},
		{"go 1.21.0 - modern, skip", parse(t, "1.21.0"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantMerge, needsGoSumMerge(tt.modFile))
		})
	}

	t.Run("unparsable directive - fail wide", func(t *testing.T) {
		// modfile.Parse rejects garbage directives, so hand-build the case.
		modFile := &modfile.File{Go: &modfile.Go{Version: "banana"}}
		assert.True(t, needsGoSumMerge(modFile))
	})
}

func TestParseGoModWithSum_GoSumMergeGate(t *testing.T) {
	goSum := []byte(`github.com/sum/only v1.2.3 h1:hash=
github.com/sum/only v1.2.3/go.mod h1:hash=
`)
	goModFor := func(directive string) []byte {
		src := "module example.com/app\n"
		if directive != "" {
			src += "go " + directive + "\n"
		}
		src += "require github.com/direct/dep v1.0.0\n"
		return []byte(src)
	}

	p := newParser()

	t.Run("go 1.17 - go.sum-only module excluded", func(t *testing.T) {
		info, err := p.parseGoModWithSum(goModFor("1.17"), goSum)
		require.NoError(t, err)
		assert.NotContains(t, info.AllRequirements, "github.com/sum/only")
		assert.Contains(t, info.AllRequirements, "github.com/direct/dep")
	})

	t.Run("go 1.16 - go.sum merged", func(t *testing.T) {
		info, err := p.parseGoModWithSum(goModFor("1.16"), goSum)
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", info.AllRequirements["github.com/sum/only"])
	})

	t.Run("no go directive - go.sum merged", func(t *testing.T) {
		info, err := p.parseGoModWithSum(goModFor(""), goSum)
		require.NoError(t, err)
		assert.Equal(t, "v1.2.3", info.AllRequirements["github.com/sum/only"])
	})
}
