package config

import (
	"testing"

	melange "chainguard.dev/melange/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRenderOrRaw(t *testing.T) {
	cfg := &melange.Configuration{Package: melange.Package{Name: "example", Version: "1.2.3"}}
	r, err := NewRenderer(cfg)
	require.NoError(t, err)

	assert.Equal(t, "v1.2.3", r.RenderOrRaw(t.Context(), "v${{package.version}}"), "renders")
	assert.Equal(t, "./cmd/x", r.RenderOrRaw(t.Context(), "./cmd/x"), "no template: unchanged")
	assert.Equal(t, "", r.RenderOrRaw(t.Context(), ""))
	assert.Equal(t, "${{vars.missing}}", r.RenderOrRaw(t.Context(), "${{vars.missing}}"), "render error: raw kept")

	var nilRenderer *Renderer
	assert.Equal(t, "v${{package.version}}", nilRenderer.RenderOrRaw(t.Context(), "v${{package.version}}"), "nil renderer: raw kept")
}

func TestForEachPipelineStep(t *testing.T) {
	cfg := &melange.Configuration{
		Pipeline: []melange.Pipeline{{Uses: "a"}, {Uses: "b"}},
		Subpackages: []melange.Subpackage{
			{Pipeline: []melange.Pipeline{{Uses: "c"}}},
			{},
			{Pipeline: []melange.Pipeline{{Uses: "d"}, {Uses: "e"}}},
		},
	}
	var seen []string
	ForEachPipelineStep(cfg, func(step *melange.Pipeline) { seen = append(seen, step.Uses) })
	assert.Equal(t, []string{"a", "b", "c", "d", "e"}, seen, "top-level first, then each subpackage in order")

	ForEachPipelineStep(cfg, func(step *melange.Pipeline) { step.Name = "touched" })
	assert.Equal(t, "touched", cfg.Subpackages[2].Pipeline[1].Name, "fn sees the step itself, not a copy")

	ForEachPipelineStep(nil, func(*melange.Pipeline) { t.Fatal("called for a nil configuration") })
}

func TestBumpStepEffectiveLanguage(t *testing.T) {
	assert.Equal(t, "go", BumpStep{}.EffectiveLanguage())
	assert.Equal(t, "rust", BumpStep{Language: "rust"}.EffectiveLanguage())
}
