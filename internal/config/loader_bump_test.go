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

func TestLoader_FindBumpSteps_GoVersion(t *testing.T) {
	const withQuotedGoVersion = `pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example
      tag: v${{package.version}}

  - uses: go/bump
    with:
      go-version: "1.25"
      deps: |-
        golang.org/x/net@v0.55.0
`
	loader := NewLoader()
	steps, err := loader.FindBumpSteps([]byte(withQuotedGoVersion))
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "1.25", steps[0].GoVersion)

	// A step with no with.go-version reads back as "".
	noGoVersionSteps, err := loader.FindBumpSteps([]byte(singleGoBumpYAML))
	require.NoError(t, err)
	require.Len(t, noGoVersionSteps, 1)
	assert.Equal(t, "", noGoVersionSteps[0].GoVersion)

	// An UNQUOTED go-version parses as a YAML float, but the AST-based reader
	// preserves its raw token text ("1.25"), so it must be read back verbatim -
	// NOT dropped (silently lowering/vanishing a user's pin) and NOT coerced
	// through float64 (which would turn "1.30" into "1.3", a 27-minor
	// corruption).
	const withUnquotedGoVersion = `pipeline:
  - uses: bump
    with:
      go-version: 1.25
      deps: |-
        golang.org/x/net@v0.55.0
`
	unquotedSteps, err := loader.FindBumpSteps([]byte(withUnquotedGoVersion))
	require.NoError(t, err)
	require.Len(t, unquotedSteps, 1)
	assert.Equal(t, "1.25", unquotedSteps[0].GoVersion, "unquoted go-version must be read from its raw token text, not dropped")

	// Load-bearing: an unquoted "1.30" must NOT be coerced through float64 to
	// "1.3". goversion.Compare("1.3", "1.30") differ by 27 minors, so a float
	// round-trip here would silently corrupt a pinned toolchain.
	const withUnquotedTrailingZero = `pipeline:
  - uses: bump
    with:
      go-version: 1.30
      deps: |-
        golang.org/x/net@v0.55.0
`
	trailingZeroSteps, err := loader.FindBumpSteps([]byte(withUnquotedTrailingZero))
	require.NoError(t, err)
	require.Len(t, trailingZeroSteps, 1)
	assert.Equal(t, "1.30", trailingZeroSteps[0].GoVersion, "unquoted 1.30 must survive as raw text, not float64(1.3)")
}

// TestLoader_GetPipelineWithField_ScalarTypes pins the AST-based reader's
// behaviour across scalar kinds: strings keep their interpreted value (quotes
// stripped), non-string scalars (int/float/bool) surface their raw token text
// rather than being coerced or dropped, block scalars are interpreted, and
// null/sequence/mapping values are skipped.
func TestLoader_GetPipelineWithField_ScalarTypes(t *testing.T) {
	loader := NewLoader()

	t.Run("quoted string strips quotes", func(t *testing.T) {
		const y = `pipeline:
  - uses: bump
    with:
      go-version: "1.25"
`
		fields, err := loader.GetPipelineWithField([]byte(y), 0)
		require.NoError(t, err)
		assert.Equal(t, "1.25", fields["go-version"])
	})

	t.Run("unquoted float keeps raw token text", func(t *testing.T) {
		const y = `pipeline:
  - uses: bump
    with:
      go-version: 1.30
`
		fields, err := loader.GetPipelineWithField([]byte(y), 0)
		require.NoError(t, err)
		assert.Equal(t, "1.30", fields["go-version"], "must not coerce through float64(1.3)")
	})

	t.Run("single-key with block (MappingValueNode path)", func(t *testing.T) {
		const y = `pipeline:
  - uses: bump
    with:
      go-version: 1.25
`
		fields, err := loader.GetPipelineWithField([]byte(y), 0)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"go-version": "1.25"}, fields)
	})

	t.Run("int and bool scalars surface raw text", func(t *testing.T) {
		const y = `pipeline:
  - uses: bump
    with:
      go-version: 1.25
      some-int: 42
      some-bool: true
`
		fields, err := loader.GetPipelineWithField([]byte(y), 0)
		require.NoError(t, err)
		assert.Equal(t, "1.25", fields["go-version"])
		assert.Equal(t, "42", fields["some-int"])
		assert.Equal(t, "true", fields["some-bool"])
	})

	t.Run("block scalar deps interpreted, sequence/null skipped", func(t *testing.T) {
		const y = `pipeline:
  - uses: bump
    with:
      deps: |-
        github.com/foo/bar@v1.1.1
        golang.org/x/net@v0.55.0
      empty:
      seq:
        - a
        - b
`
		fields, err := loader.GetPipelineWithField([]byte(y), 0)
		require.NoError(t, err)
		assert.Equal(t, "github.com/foo/bar@v1.1.1\ngolang.org/x/net@v0.55.0", fields["deps"])
		_, hasEmpty := fields["empty"]
		assert.False(t, hasEmpty, "null value must be skipped")
		_, hasSeq := fields["seq"]
		assert.False(t, hasSeq, "sequence value must be skipped")
	})
}

// TestLoader_FindBumpSteps_UnquotedGoVersionRoundTrip proves the never-lower
// path: an unquoted go-version read as its raw text ("1.30") can be re-quoted
// in place without lowering it and without disturbing comments.
func TestLoader_FindBumpSteps_UnquotedGoVersionRoundTrip(t *testing.T) {
	loader := NewLoader()

	const withUnquotedAndComment = `pipeline:
  # keep me
  - uses: go/bump
    with:
      go-version: 1.30
      deps: |-
        golang.org/x/net@v0.55.0
`
	steps, err := loader.FindBumpSteps([]byte(withUnquotedAndComment))
	require.NoError(t, err)
	require.Len(t, steps, 1)
	require.Equal(t, "1.30", steps[0].GoVersion)

	// Re-quoting at the same version must not lower it and must keep comments.
	updated, err := loader.UpsertPipelineWithQuotedString([]byte(withUnquotedAndComment), 0, "go-version", steps[0].GoVersion)
	require.NoError(t, err)

	content := string(updated)
	assert.Contains(t, content, `go-version: "1.30"`)
	assert.Equal(t, 1, strings.Count(content, "go-version:"), "must not duplicate the key")
	assert.Contains(t, content, "# keep me", "comments must be preserved")

	reread, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, reread, 1)
	assert.Equal(t, "1.30", reread[0].GoVersion, "round-trip must never lower the pinned version")
}

func TestLoader_InsertBumpPipelineStep_WritesLanguage(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:   "bump",
		Language: "rust",
		Modroots: []string{"."},
		Deps:     []string{"serde@1.0.200"},
	}, true)
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

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:   "bump",
		Modroots: []string{"."},
		Deps:     []string{"github.com/foo/bar@v1.0.0"},
	}, true)
	require.NoError(t, err)

	content := string(updated)
	assert.Contains(t, content, "- uses: bump")
	assert.Contains(t, content, "github.com/foo/bar@v1.0.0")
	assert.NotContains(t, content, "modroot")
	assert.NotContains(t, content, "language")
}

func TestLoader_InsertBumpPipelineStep_MultiRootWritesModroot(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:   "bump",
		Modroots: []string{"cmd/a", "cmd/b", "."},
		Deps:     []string{"github.com/foo/bar@v1.0.0"},
	}, true)
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
		[]string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, "")
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
		[]string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"}, "")
	require.NoError(t, err)
	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.55.0"}, steps[0].Replaces)
	assert.Contains(t, string(updated), "# keep me", "comments must be preserved")

	// Empty replaces removes just the field, keeping the step.
	cleared, err := loader.UpdateGoBumpStep([]byte(replacesGoBumpYAML), 1,
		[]string{"golang.org/x/net@v0.55.0"}, nil, "")
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
		nil, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, "")
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Empty(t, steps[0].Deps)
	assert.Equal(t, []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"}, steps[0].Replaces)
}

func TestLoader_UpdateGoBumpStep_BothEmptyRemovesStep(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.UpdateGoBumpStep([]byte(replacesGoBumpYAML), 1, nil, nil, "")
	require.NoError(t, err)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	assert.Empty(t, steps)
}

func TestLoader_UpdateGoBumpStep_GoVersionEmptyLeavesExistingUntouched(t *testing.T) {
	loader := NewLoader()

	const withGoVersion = `pipeline:
  - uses: go/bump
    with:
      go-version: "1.24"
      deps: |-
        golang.org/x/net@v0.55.0
`
	// goVersion == "" must never remove or alter an already-present go-version.
	updated, err := loader.UpdateGoBumpStep([]byte(withGoVersion), 0,
		[]string{"golang.org/x/net@v0.56.0"}, nil, "")
	require.NoError(t, err)
	assert.Contains(t, string(updated), `go-version: "1.24"`)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "1.24", steps[0].GoVersion)
	assert.Equal(t, []string{"golang.org/x/net@v0.56.0"}, steps[0].Deps)
}

func TestLoader_UpdateGoBumpStep_AddsGoVersionToStepLackingIt(t *testing.T) {
	loader := NewLoader()

	// singleGoBumpYAML's go/bump step (index 2) has no go-version field yet.
	updated, err := loader.UpdateGoBumpStep([]byte(singleGoBumpYAML), 2,
		[]string{"golang.org/x/net@v0.56.0"}, nil, "1.25")
	require.NoError(t, err)
	assert.Contains(t, string(updated), `go-version: "1.25"`, "go-version must be rendered as a quoted scalar")

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "1.25", steps[0].GoVersion)
}

// TestLoader_UpdateGoBumpStep_AddsGoVersionAfterModrootAtEOF is a regression
// test for a spliceIntoPipelineWith off-by-one: appending a brand-new field
// (go-version) after an existing block-scalar field (modroot) that is both
// the with-block's last field AND the file's last content must not eat the
// file's own trailing newline into the "before insertion" half - which
// produced a spurious blank line before the new field and, on any subsequent
// splice into the same spot, a non-idempotent extra trailing newline.
func TestLoader_UpdateGoBumpStep_AddsGoVersionAfterModrootAtEOF(t *testing.T) {
	loader := NewLoader()

	const withModrootLastAtEOF = `pipeline:
  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.55.0
      modroot: |-
        .
        cmd/a
`
	updated, err := loader.UpdateGoBumpStep([]byte(withModrootLastAtEOF), 0,
		[]string{"golang.org/x/net@v0.56.0"}, nil, "1.26")
	require.NoError(t, err)

	content := string(updated)
	assert.Equal(t, `pipeline:
  - uses: go/bump
    with:
      deps: |-
        golang.org/x/net@v0.56.0
      modroot: |-
        .
        cmd/a
      go-version: "1.26"
`, content, "no spurious blank line before go-version, and the file's trailing newline is preserved")

	// A second splice into the same already-updated spot must be byte-stable.
	again, err := loader.UpsertPipelineWithQuotedString(updated, 0, "go-version", "1.26")
	require.NoError(t, err)
	assert.Equal(t, content, string(again), "re-splicing at EOF must be idempotent")
}

func TestLoader_UpdateGoBumpStep_UpdatesExistingGoVersion(t *testing.T) {
	loader := NewLoader()

	const withGoVersionAndComment = `pipeline:
  # keep me
  - uses: go/bump
    with:
      go-version: "1.24"
      deps: |-
        golang.org/x/net@v0.55.0
`
	updated, err := loader.UpdateGoBumpStep([]byte(withGoVersionAndComment), 0,
		[]string{"golang.org/x/net@v0.56.0"}, nil, "1.25")
	require.NoError(t, err)
	assert.Contains(t, string(updated), `go-version: "1.25"`)
	assert.NotContains(t, string(updated), `go-version: "1.24"`)
	assert.Contains(t, string(updated), "# keep me", "comments must be preserved")

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
	assert.Equal(t, "1.25", steps[0].GoVersion)
}

func TestLoader_UpsertPipelineWithQuotedString(t *testing.T) {
	loader := NewLoader()

	t.Run("creates field on step lacking it", func(t *testing.T) {
		updated, err := loader.UpsertPipelineWithQuotedString([]byte(singleGoBumpYAML), 2, "go-version", "1.25")
		require.NoError(t, err)
		assert.Contains(t, string(updated), `go-version: "1.25"`)
	})

	t.Run("updates existing field in place, preserving comments", func(t *testing.T) {
		const withGoVersionAndComment = `pipeline:
  # keep me
  - uses: go/bump
    with:
      go-version: "1.24"
      deps: |-
        golang.org/x/net@v0.55.0
`
		updated, err := loader.UpsertPipelineWithQuotedString([]byte(withGoVersionAndComment), 0, "go-version", "1.25")
		require.NoError(t, err)
		assert.Contains(t, string(updated), `go-version: "1.25"`)
		assert.NotContains(t, string(updated), `go-version: "1.24"`)
		assert.Contains(t, string(updated), "# keep me")
	})

	// Regression test: an existing UNQUOTED "go-version: 1.25" parses as a
	// YAML float, not a string. GetPipelineWithField (which the existence
	// probe used to rely on) silently drops non-string values, so the probe
	// would see the field as absent and splice in a second go-version key,
	// producing an unparseable duplicate-key YAML document.
	t.Run("replaces unquoted float-typed go-version instead of duplicating the key", func(t *testing.T) {
		const withUnquotedGoVersionAndComment = `pipeline:
  # keep me
  - uses: go/bump
    with:
      go-version: 1.25
      deps: |-
        golang.org/x/net@v0.55.0
`
		updated, err := loader.UpsertPipelineWithQuotedString([]byte(withUnquotedGoVersionAndComment), 0, "go-version", "1.26")
		require.NoError(t, err)

		content := string(updated)
		assert.Equal(t, 1, strings.Count(content, "go-version:"), "must not duplicate the go-version key")
		assert.Contains(t, content, `go-version: "1.26"`)
		assert.NotContains(t, content, "go-version: 1.25")
		assert.Contains(t, content, "# keep me", "comments must be preserved")

		// A duplicate go-version key would make this unparseable, so a
		// successful round-trip through FindBumpSteps proves the YAML is valid.
		steps, err := loader.FindBumpSteps(updated)
		require.NoError(t, err)
		require.Len(t, steps, 1)
		assert.Equal(t, "1.26", steps[0].GoVersion)
	})
}

// TestLoader_UpsertPipelineWithQuotedString_RejectsUnsafeValue covers the
// hardening half of the go-version fix: values containing '"' or '\' can't
// be embedded literally inside an unescaped double-quoted YAML scalar
// without either breaking the YAML or silently mutating the value (e.g. a
// literal "\n" becoming a newline), so they must be rejected outright.
func TestLoader_UpsertPipelineWithQuotedString_RejectsUnsafeValue(t *testing.T) {
	loader := NewLoader()

	for _, value := range []string{
		`1.25"`,
		`1.25\n`,
		`1.25" }, deps: [evil]; #`,
		"1.25\ttab",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := loader.UpsertPipelineWithQuotedString([]byte(singleGoBumpYAML), 2, "go-version", value)
			require.Error(t, err)
		})
	}
}

func TestLoader_InsertBumpPipelineStep_WritesGoVersion(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:    "bump",
		Language:  "go",
		GoVersion: "1.25",
		Modroots:  []string{"."},
		Deps:      []string{"golang.org/x/net@v0.56.0"},
	}, true)
	require.NoError(t, err)
	assert.Contains(t, string(updated), `go-version: "1.25"`)

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 2)

	var inserted *BumpStep
	for i := range steps {
		if steps[i].GoVersion == "1.25" {
			inserted = &steps[i]
		}
	}
	require.NotNil(t, inserted)
	assert.Equal(t, []string{"golang.org/x/net@v0.56.0"}, inserted.Deps)
}

// TestLoader_InsertBumpPipelineStep_RejectsUnsafeGoVersion mirrors
// TestLoader_UpsertPipelineWithQuotedString_RejectsUnsafeValue: the template
// path embeds spec.GoVersion literally between double quotes too, so it
// needs the same rejection for values containing '"' or '\'.
func TestLoader_InsertBumpPipelineStep_RejectsUnsafeGoVersion(t *testing.T) {
	loader := NewLoader()

	_, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:    "bump",
		Language:  "go",
		GoVersion: `1.25"`,
		Modroots:  []string{"."},
		Deps:      []string{"golang.org/x/net@v0.56.0"},
	}, true)
	require.Error(t, err)
}

// TestLoader_InsertBumpPipelineStep_NoGoVersionOmitsField is the byte-for-byte
// emission regression the brief calls for: a spec without GoVersion must
// render identically to before the BumpStepSpec refactor (mirrors
// TestLoader_InsertBumpPipelineStep_SingleRootOmitsModroot's assertions).
func TestLoader_InsertBumpPipelineStep_NoGoVersionOmitsField(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:   "bump",
		Modroots: []string{"."},
		Deps:     []string{"github.com/foo/bar@v1.0.0"},
	}, true)
	require.NoError(t, err)

	content := string(updated)
	assert.Contains(t, content, "- uses: bump")
	assert.Contains(t, content, "github.com/foo/bar@v1.0.0")
	assert.NotContains(t, content, "go-version")
	assert.NotContains(t, content, "modroot")
	assert.NotContains(t, content, "language")
}

func TestLoader_InsertBumpPipelineStep_WritesReplaces(t *testing.T) {
	loader := NewLoader()

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:   "bump",
		Language: "go",
		Modroots: []string{"."},
		Deps:     []string{"golang.org/x/net@v0.55.0"},
		Replaces: []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"},
	}, true)
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

	updated, err := loader.InsertBumpPipelineStep([]byte(singleGoBumpYAML), 1, BumpStepSpec{
		Action:   "bump",
		Language: "go",
		Modroots: []string{"."},
		Replaces: []string{"github.com/aws/aws-sdk-go=github.com/aws/aws-sdk-go@v1.34.0"},
	}, true)
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
		[]string{"golang.org/x/crypto=golang.org/x/crypto@v0.52.0"}, "")
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
		updated, err := loader.InsertBumpPipelineStep(content, 1+i, BumpStepSpec{
			Action:   "bump",
			Language: "go",
			Modroots: []string{"."},
			Deps:     deps,
		}, true)
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

	updated, err := loader.InsertBumpPipelineStep([]byte(compactYAML), 1, BumpStepSpec{
		Action:   "bump",
		Language: "go",
		Modroots: []string{"."},
		Deps:     []string{"golang.org/x/net@v0.56.0"},
	}, false)
	require.NoError(t, err)

	pipelinePart := string(updated)[strings.Index(string(updated), "pipeline:"):]
	assert.NotContains(t, pipelinePart, "\n\n", "compact pipeline must not gain blank lines")

	steps, err := loader.FindBumpSteps(updated)
	require.NoError(t, err)
	require.Len(t, steps, 1)
}

const goPackagePinYAML = `package:
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
      go-package: go-1.24
      modroot: ./cmd/app

subpackages:
  - name: example-extra
    pipeline:
      - uses: go/install
        with:
          # pinned pending toolchain support for the new build tag
          go-package: go-1.23
          packages: ./cmd/extra

  - name: example-templated
    pipeline:
      - uses: go/build
        with:
          go-package: go-${{vars.go-version}}

  - name: example-no-pin
    pipeline:
      - uses: go/build
        with:
          packages: ./cmd/other

  - name: example-numeric-modroot
    pipeline:
      - uses: go/build
        with:
          go-package: go-1.24
          # unquoted numeric-looking modroot parses as a YAML integer
          modroot: 2024
`

func TestLoader_FindGoPackagePins(t *testing.T) {
	loader := NewLoader()

	pins, err := loader.FindGoPackagePins([]byte(goPackagePinYAML))
	require.NoError(t, err)
	require.Len(t, pins, 4)

	assert.Equal(t, "$.pipeline[1].with.go-package", pins[0].Path)
	assert.Equal(t, "", pins[0].Subpackage)
	assert.Equal(t, "go-1.24", pins[0].Value)
	assert.Equal(t, "go/build", pins[0].Uses)
	assert.Equal(t, "./cmd/app", pins[0].Modroot, "explicit with.modroot read verbatim")

	assert.Equal(t, "$.subpackages[0].pipeline[0].with.go-package", pins[1].Path)
	assert.Equal(t, "example-extra", pins[1].Subpackage)
	assert.Equal(t, "go-1.23", pins[1].Value)
	assert.Equal(t, "go/install", pins[1].Uses)
	assert.Equal(t, ".", pins[1].Modroot, "go/install carries no modroot - defaults to \".\"")

	// A templated value is returned raw, untouched by rendering.
	assert.Equal(t, "$.subpackages[1].pipeline[0].with.go-package", pins[2].Path)
	assert.Equal(t, "example-templated", pins[2].Subpackage)
	assert.Equal(t, "go-${{vars.go-version}}", pins[2].Value)
	assert.Equal(t, "go/build", pins[2].Uses)
	assert.Equal(t, ".", pins[2].Modroot, "go/build without with.modroot defaults to \".\"")

	// An unquoted numeric-looking modroot unmarshals as a YAML integer; it
	// must coerce to its string form (matching melange's map[string]string
	// coercion, which keys the floors map) - never mis-default to ".".
	assert.Equal(t, "$.subpackages[3].pipeline[0].with.go-package", pins[3].Path)
	assert.Equal(t, "example-numeric-modroot", pins[3].Subpackage)
	assert.Equal(t, "go-1.24", pins[3].Value)
	assert.Equal(t, "go/build", pins[3].Uses)
	assert.Equal(t, "2024", pins[3].Modroot, "unquoted numeric modroot coerced to string, not defaulted")
}

func TestLoader_FindGoPackagePins_None(t *testing.T) {
	loader := NewLoader()

	// singleGoBumpYAML's go/build step has no go-package field.
	pins, err := loader.FindGoPackagePins([]byte(singleGoBumpYAML))
	require.NoError(t, err)
	assert.Empty(t, pins)
}

// TestLoader_FindGoPackagePins_SubpackageWriteBack proves the write-back path
// the brief requires: a pin found in a SUBPACKAGE pipeline (with a comment
// nearby) must be rewritable via its own Path using UpdateField, changing
// only that value and leaving comments/formatting/everything else intact.
func TestLoader_FindGoPackagePins_SubpackageWriteBack(t *testing.T) {
	loader := NewLoader()

	pins, err := loader.FindGoPackagePins([]byte(goPackagePinYAML))
	require.NoError(t, err)
	require.Len(t, pins, 4)

	pin := pins[1] // $.subpackages[0].pipeline[0].with.go-package
	require.Equal(t, "example-extra", pin.Subpackage)
	require.Equal(t, "go-1.23", pin.Value)

	updated, err := loader.UpdateField([]byte(goPackagePinYAML), pin.Path, "go-1.25")
	require.NoError(t, err)

	content := string(updated)
	// (a) the value changed
	assert.Contains(t, content, "go-package: go-1.25")
	assert.NotContains(t, content, "go-package: go-1.23")
	// (b) comments/formatting preserved
	assert.Contains(t, content, "# pinned pending toolchain support for the new build tag")
	// (c) nothing else changed: every other pin's value is untouched
	assert.Contains(t, content, "go-package: go-1.24")
	assert.Contains(t, content, "go-package: go-${{vars.go-version}}")

	rePins, err := loader.FindGoPackagePins(updated)
	require.NoError(t, err)
	require.Len(t, rePins, 4)
	assert.Equal(t, "go-1.25", rePins[1].Value)
	assert.Equal(t, "go-1.24", rePins[0].Value)
	assert.Equal(t, "go-${{vars.go-version}}", rePins[2].Value)
}
