package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const editYAML = `package:
  name: example
  version: "1.0.0"
  epoch: 0

environment:
  contents:
    packages:
      - build-base
      - go-1.26

pipeline:
  - uses: git-checkout
    with:
      repository: https://github.com/example/example

  # the bump step
  - uses: "go/bump" # inline
    with:
      # why go-version
      # is set
      go-version: 1.26.8 # trailing
      deps: |-
        a@v1
        b@v2
      # about tidy
      tidy: false

  - uses: go/build
    with:
      packages: .

subpackages:
  - name: sub
    pipeline:
      - uses: go/install
        with:
          package: example.com/tool@v1
          go-package: go-1.25
`

func TestLoader_SetPipelineUses(t *testing.T) {
	out, err := NewLoader().SetPipelineUses([]byte(editYAML), 1, "bump")
	require.NoError(t, err)
	assert.Equal(t, strings.Replace(editYAML, `"go/bump" # inline`, `bump # inline`, 1), string(out))
}

func TestLoader_RemovePipelineWithFieldLines(t *testing.T) {
	l := NewLoader()
	out, err := l.RemovePipelineWithFieldLines([]byte(editYAML), 1, "go-version")
	require.NoError(t, err)
	assert.Equal(t, strings.Replace(editYAML, "      # why go-version\n      # is set\n      go-version: 1.26.8 # trailing\n", "", 1), string(out),
		"the key, its inline comment and the comment lines above it go; nothing else")

	out, err = l.RemovePipelineWithFieldLines([]byte(editYAML), 1, "tidy")
	require.NoError(t, err)
	assert.Equal(t, strings.Replace(editYAML, "      # about tidy\n      tidy: false\n", "", 1), string(out), "last key of the block")

	out, err = l.RemovePipelineWithFieldLines([]byte(editYAML), 1, "deps")
	require.NoError(t, err)
	assert.Equal(t, strings.Replace(editYAML, "      deps: |-\n        a@v1\n        b@v2\n", "", 1), string(out), "block scalar")

	out, err = l.RemovePipelineWithFieldLines([]byte(editYAML), 1, "absent")
	require.NoError(t, err)
	assert.Equal(t, editYAML, string(out))
}

func TestLoader_SpliceIntoWith_Subpackage(t *testing.T) {
	out, err := NewLoader().SpliceIntoWith([]byte(editYAML), "$.subpackages[0].pipeline[0].with", []string{"extra: 1"})
	require.NoError(t, err)
	assert.Equal(t, strings.Replace(editYAML, "          go-package: go-1.25\n", "          go-package: go-1.25\n          extra: 1\n", 1), string(out))
}

func TestLoader_FindGoToolchainStepsAndEnvironment(t *testing.T) {
	l := NewLoader()
	steps, err := l.FindGoToolchainSteps([]byte(editYAML))
	require.NoError(t, err)
	require.Len(t, steps, 2)
	assert.Equal(t, "$.pipeline[2].with", steps[0].WithPath)
	assert.False(t, steps[0].HasPin)
	assert.Equal(t, "$.subpackages[0].pipeline[0].with", steps[1].WithPath)
	assert.True(t, steps[1].HasPin)
	assert.Equal(t, "go-1.25", steps[1].Value)
	assert.Equal(t, "sub", steps[1].Subpackage)

	pins, err := l.FindGoPackagePins([]byte(editYAML))
	require.NoError(t, err)
	require.Len(t, pins, 1)
	assert.Equal(t, "$.subpackages[0].pipeline[0].with.go-package", pins[0].Path)

	pkgs, err := l.EnvironmentPackages([]byte(editYAML))
	require.NoError(t, err)
	assert.Equal(t, []string{"build-base", "go-1.26"}, pkgs)
}

func TestLoader_CloneAndSetModroots(t *testing.T) {
	const multi = `pipeline:
  - uses: git-checkout

  - name: bump it
    uses: bump
    with:
      deps: |-
        a@v1
      modroot: |-
        cmd/a
        cmd/b
      tidy: false

  - uses: go/build
`
	l := NewLoader()
	out, err := l.ClonePipelineStepAfter([]byte(multi), 1, true)
	require.NoError(t, err)
	steps, err := l.FindBumpSteps(out)
	require.NoError(t, err)
	require.Len(t, steps, 2)
	assert.Equal(t, 2, steps[1].Index)
	assert.True(t, steps[1].NoTidy, "the clone keeps the step's options")

	out, err = l.SetBumpModroots(out, 1, []string{"cmd/a"})
	require.NoError(t, err)
	out, err = l.SetBumpModroots(out, 2, []string{"cmd/b", "cmd/c"})
	require.NoError(t, err)
	assert.Equal(t, `pipeline:
  - uses: git-checkout

  - name: bump it
    uses: bump
    with:
      deps: |-
        a@v1
      tidy: false
      modroot: cmd/a

  - name: bump it
    uses: bump
    with:
      deps: |-
        a@v1
      modroot: |-
        cmd/b
        cmd/c
      tidy: false

  - uses: go/build
`, string(out))

	out, err = l.SetBumpModroots(out, 1, []string{"."})
	require.NoError(t, err)
	assert.NotContains(t, strings.Split(string(out), "  - name: bump it")[1], "modroot", "a lone . is the default")
}
