package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const certManagerLikeYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        github.com/foo/bar@v1.1.1
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/a
        cmd/b
        .

  - uses: bump
    with:
      deps: |-
        github.com/foo/baz@v2.2.2
        golang.org/x/net@v0.55.0
      modroot: |-
        cmd/b
        .
        test/e2e
`

const singleGoBumpYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/build
    with:
      packages: .

  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
`

func TestLoader_FindBumpSteps(t *testing.T) {
	loader := NewLoader()

	steps, err := loader.FindBumpSteps([]byte(certManagerLikeYAML))
	require.NoError(t, err)
	require.Len(t, steps, 2)

	assert.Equal(t, 1, steps[0].Index)
	assert.Equal(t, "go/bump", steps[0].Action)
	assert.Equal(t, []string{"cmd/a", "cmd/b", "."}, steps[0].Modroots)
	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0"}, steps[0].Deps)

	assert.Equal(t, 2, steps[1].Index)
	assert.Equal(t, "bump", steps[1].Action)
	assert.Equal(t, []string{"cmd/b", ".", "test/e2e"}, steps[1].Modroots)
	assert.Equal(t, []string{"github.com/foo/baz@v2.2.2", "golang.org/x/net@v0.55.0"}, steps[1].Deps)
}

func TestLoader_FindBumpSteps_Language(t *testing.T) {
	const withLanguage = `pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: bump
    with:
      language: rust
      deps: |-
        serde@1.0.200
`
	loader := NewLoader()
	steps, err := loader.FindBumpSteps([]byte(withLanguage))
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "rust", steps[0].Language)

	// A step with no with.language reads back as "".
	noLangSteps, err := loader.FindBumpSteps([]byte(singleGoBumpYAML))
	require.NoError(t, err)
	require.Len(t, noLangSteps, 1)
	assert.Equal(t, "", noLangSteps[0].Language)
}

func TestLoader_InsertBumpPipelineStep_WritesLanguage(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, "bump", "rust", []string{"."}, []string{"serde@1.0.200"}, nil, true)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)

	var inserted *BumpStep
	for i := range steps {
		if steps[i].Language == "rust" {
			inserted = &steps[i]
		}
	}
	require.NotNil(t, inserted)
	assert.Equal(t, []string{"serde@1.0.200"}, inserted.Deps)
}

func TestLoader_GetBumpModroots_DefaultsToDot(t *testing.T) {
	loader := NewLoader()

	steps, err := loader.FindBumpSteps([]byte(singleGoBumpYAML))
	require.NoError(t, err)
	require.Len(t, steps, 1)

	assert.Equal(t, []string{"."}, steps[0].Modroots)
}

func TestLoader_InsertBumpPipelineStep_SingleRootOmitsModroot(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, "bump", "", []string{"."}, []string{"github.com/foo/bar@v1.0.0"}, nil, true)
	require.NoError(t, err)

	content := string(updated)
	assert.Contains(t, content, "- uses: bump")
	assert.Contains(t, content, "github.com/foo/bar@v1.0.0")
	assert.NotContains(t, content, "modroot")
	assert.NotContains(t, content, "language")
}

func TestLoader_InsertBumpPipelineStep_MultiRootWritesModroot(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, "bump", "",
		[]string{"cmd/a", "cmd/b", "."}, []string{"github.com/foo/bar@v1.0.0"}, nil, true)
	require.NoError(t, err)

	content := string(updated)
	assert.Contains(t, content, "- uses: bump")
	assert.Contains(t, content, "modroot: |-")

	loader2 := NewLoader()
	steps, err := loader2.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 2) // the new step plus the existing go/bump step

	var inserted *BumpStep
	for i := range steps {
		if strings.Join(steps[i].Deps, ",") == "github.com/foo/bar@v1.0.0" {
			inserted = &steps[i]
		}
	}
	require.NotNil(t, inserted)
	assert.Equal(t, []string{"cmd/a", "cmd/b", "."}, inserted.Modroots)
}

// TestLoader_RemoveThenInsertPreservesComments guards against a goccy/go-yaml
// footgun: SequenceNode.ValueHeadComments must stay length-matched with
// Values, or the block-style renderer silently drops every head comment (and
// blank line, which is modeled the same way) in the whole sequence - not just
// around the edited index.
func TestLoader_RemoveThenInsertPreservesComments(t *testing.T) {
	const withTrailingComment = `pipeline:
  - uses: a

  - uses: b
    with:
      deps: |-
        x

  - uses: c
    with:
      deps: |-
        y

  # important comment
  - runs: |
      echo hi
`

	loader := NewLoader()

	updated, err := loader.RemovePipelineStep([]byte(withTrailingComment), 2)
	require.NoError(t, err)
	updated, err = loader.RemovePipelineStep(updated, 1)
	require.NoError(t, err)

	content := string(updated)
	assert.Contains(t, content, "# important comment")
	assert.Contains(t, content, "\n\n  # important comment")

	inserted, err := loader.InsertPipelineStep(updated, 1, map[string]any{"uses": "z"})
	require.NoError(t, err)
	assert.Contains(t, string(inserted), "# important comment")
}

func TestLoader_RemovePipelineWithField(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.RemovePipelineWithField([]byte(certManagerLikeYAML), 1, "modroot")
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 2)
	assert.Equal(t, []string{"."}, steps[0].Modroots)                                                 // field removed -> default
	assert.Equal(t, []string{"github.com/foo/bar@v1.1.1", "golang.org/x/net@v0.55.0"}, steps[0].Deps) // deps untouched

	// Removing an absent field is a no-op.
	unchanged, err := loader.RemovePipelineWithField(updated, 1, "modroot")
	require.NoError(t, err)
	assert.Equal(t, updated, unchanged)
}

const replacesGoBumpYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  # keep me
  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      replaces: |-
        github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0
        github.com/old/mod=github.com/fork/mod@v2.0.0
`

func TestLoader_FindBumpSteps_Replaces(t *testing.T) {
	loader := NewLoader()

	steps, err := loader.FindBumpSteps([]byte(replacesGoBumpYAML))
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, []string{
		"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0",
		"github.com/old/mod=github.com/fork/mod@v2.0.0",
	}, steps[0].Replaces)

	// A step without replaces reads back as empty.
	noReplaces, err := loader.FindBumpSteps([]byte(singleGoBumpYAML))
	require.NoError(t, err)
	require.Len(t, noReplaces, 1)
	assert.Empty(t, noReplaces[0].Replaces)
}

func TestLoader_UpdateGoBumpStep_UpsertsReplaces(t *testing.T) {
	loader := NewLoader()

	// singleGoBumpYAML's go/bump step (index 2) has no replaces field yet.
	updated, err := loader.UpdateGoBumpStep([]byte(singleGoBumpYAML), 2,
		[]string{"golang.org/x/net@v0.55.0"},
		[]string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"})
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, []string{"golang.org/x/net@v0.55.0"}, steps[0].Deps)
	assert.Equal(t, []string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, steps[0].Replaces)
}

func TestLoader_UpdateGoBumpStep_UpdatesAndClearsReplaces(t *testing.T) {
	loader := NewLoader()

	// Update existing replaces in place.
	updated, err := loader.UpdateGoBumpStep([]byte(replacesGoBumpYAML), 1,
		[]string{"golang.org/x/net@v0.55.0"},
		[]string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"})
	require.NoError(t, err)
	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"}, steps[0].Replaces)
	assert.Contains(t, string(updated), "# keep me", "comments must be preserved")

	// Empty replaces removes just the field, keeping the step.
	cleared, err := loader.UpdateGoBumpStep([]byte(replacesGoBumpYAML), 1,
		[]string{"golang.org/x/net@v0.55.0"}, nil)
	require.NoError(t, err)
	steps, err = loader.FindBumpSteps(cleared)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Empty(t, steps[0].Replaces)
	assert.Equal(t, []string{"golang.org/x/net@v0.55.0"}, steps[0].Deps)
}

func TestLoader_UpdateGoBumpStep_ReplacesOnlyKeepsStep(t *testing.T) {
	loader := NewLoader()

	// Deps empty + replaces non-empty must keep the step (gobump accepts a
	// replaces-only invocation) with only the deps field removed.
	updated, err := loader.UpdateGoBumpStep([]byte(replacesGoBumpYAML), 1,
		nil, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"})
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Empty(t, steps[0].Deps)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, steps[0].Replaces)
}

func TestLoader_UpdateGoBumpStep_BothEmptyRemovesStep(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.UpdateGoBumpStep([]byte(replacesGoBumpYAML), 1, nil, nil)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	assert.Empty(t, steps)
}

func TestLoader_InsertBumpPipelineStep_WritesReplaces(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, "bump", "go",
		[]string{"."},
		[]string{"golang.org/x/net@v0.55.0"},
		[]string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, true)
	require.NoError(t, err)

	assert.Contains(t, string(updated), "replaces: |-")

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 2)

	var inserted *BumpStep
	for i := range steps {
		if steps[i].Action == "bump" {
			inserted = &steps[i]
		}
	}
	require.NotNil(t, inserted)
	assert.Equal(t, []string{"golang.org/x/net@v0.55.0"}, inserted.Deps)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, inserted.Replaces)
}

func TestLoader_InsertBumpPipelineStep_ReplacesOnly(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, "bump", "go",
		[]string{"."}, nil,
		[]string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, true)
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 2)

	var inserted *BumpStep
	for i := range steps {
		if steps[i].Action == "bump" {
			inserted = &steps[i]
		}
	}
	require.NotNil(t, inserted)
	assert.Empty(t, inserted.Deps)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, inserted.Replaces)
}

func TestLoader_UpdateGoBumpStep_UpsertMidPipeline(t *testing.T) {
	// Regression: upserting replaces into a step FOLLOWED by other steps
	// must splice inside that step's with block, not after the next step
	// (goccy token origins carry trailing blank lines + next-token indent).
	const midPipelineYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 1

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      deps: |-
        github.com/aws/aws-sdk-go@v1.34.0
        golang.org/x/crypto@v0.45.0

  - uses: go/build
    with:
      packages: .
`
	loader := NewLoader()
	updated, err := loader.UpdateGoBumpStep([]byte(midPipelineYAML), 1,
		[]string{"github.com/aws/aws-sdk-go@v1.34.0"},
		[]string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"})
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err, "updated YAML must stay parseable:\n%s", string(updated))
	require.Len(t, steps, 1)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go@v1.34.0"}, steps[0].Deps)
	assert.Equal(t, []string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, steps[0].Replaces)

	// The following step must be untouched and still parse.
	assert.Contains(t, string(updated), "- uses: go/build")
	indices, err := loader.FindPipelinesByUse(updated, "go/build")
	require.NoError(t, err)
	require.Len(t, indices, 1)
	withFields, err := loader.GetPipelineWithField(updated, indices[0])
	require.NoError(t, err)
	assert.Equal(t, ".", withFields["packages"])
}

// TestLoader_InsertBumpPipelineStep_BlankLinesForEveryInsertedStep guards
// against the first-match-only fix-up bug: when several same-action steps are
// inserted in sequence (as the reconciler's general path does), EVERY inserted
// step must get its blank-line separator, not just the first.
func TestLoader_InsertBumpPipelineStep_BlankLinesForEveryInsertedStep(t *testing.T) {
	loader := NewLoader()

	content := []byte(singleGoBumpYAML)
	for i, deps := range [][]string{
		{"github.com/one/one@v1.0.0"},
		{"github.com/two/two@v2.0.0"},
		{"github.com/three/three@v3.0.0"},
	} {
		updated, err := loader.InsertBumpPipelineStep(content, 1+i, "bump", "go", []string{"."}, deps, nil, true)
		require.NoError(t, err)
		content = updated
	}

	lines := strings.Split(string(content), "\n")
	for i, line := range lines {
		if !strings.HasPrefix(line, "  - uses:") || i == 0 {
			continue
		}
		firstStep := strings.Contains(lines[i-1], "pipeline:")
		if firstStep {
			continue
		}
		assert.Equal(t, "", strings.TrimSpace(lines[i-1]),
			"pipeline step at line %d (%q) must be preceded by a blank line", i+1, line)
	}

	// The output must still parse, with all five steps present.
	steps, err := loader.FindBumpSteps(content)
	require.NoError(t, err)
	assert.Len(t, steps, 4) // 3 inserted + the fixture's go/bump
}

// TestLoader_InsertBumpPipelineStep_CompactFileStaysCompact: a file whose
// steps are NOT blank-line-separated must stay compact after insertion.
func TestLoader_InsertBumpPipelineStep_CompactFileStaysCompact(t *testing.T) {
	compactYAML := `package:
  name: example
  version: "1.0.0"
  epoch: 0
pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}
  - uses: go/build
    with:
      packages: .
`
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(compactYAML), 1, "bump", "go", []string{"."},
		[]string{"golang.org/x/net@v0.56.0"}, nil, false)
	require.NoError(t, err)

	pipelinePart := string(updated)[strings.Index(string(updated), "pipeline:"):]
	assert.NotContains(t, pipelinePart, "\n\n", "compact pipeline must not gain blank lines")

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
}
