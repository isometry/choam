package gobump

import (
	"testing"

	"github.com/isometry/choam/internal/config"
	"github.com/stretchr/testify/assert"
)

func TestExistingGoVersionsForModroots(t *testing.T) {
	steps := []config.BumpStep{
		{Index: 1, Action: "go/bump", Modroots: []string{".", "cmd/a"}, GoVersion: "1.24"},
		{Index: 2, Action: "go/bump", Modroots: []string{"."}, GoVersion: "1.26"},
		{Index: 3, Action: "bump", Language: "go", Modroots: []string{"."}, GoVersion: "1.99"}, // bump has no go-version input: ignored
		{Index: 4, Action: "go/bump", Modroots: []string{"cmd/b"}, GoVersion: "${{vars.go}}"},  // unorderable value ignored
		{Index: 5, Action: "go/bump", Modroots: []string{"cmd/b"}, GoVersion: ""},              // no value
		{Index: 6, Action: "go/bump", Modroots: []string{"test/e2e"}, GoVersion: "1.25.2"},     // patch-level value kept as-is
	}

	got := existingGoVersionsForModroots([]string{".", "cmd/a", "cmd/b", "test/e2e"}, steps)
	assert.Equal(t, "1.26", got["."], "max across covering go/bump steps")
	assert.Equal(t, "1.24", got["cmd/a"])
	assert.Equal(t, "", got["cmd/b"])
	assert.Equal(t, "1.25.2", got["test/e2e"])
}

func TestEffectiveGoVersionHelpers(t *testing.T) {
	assert.Equal(t, "1.26", effectiveGoVersion(ModrootAnalysis{ExistingGoVersion: "1.26", RequiredGoVersion: "1.25"}), "existing wins when higher - never lowered")
	assert.Equal(t, "1.27", effectiveGoVersion(ModrootAnalysis{ExistingGoVersion: "1.26", RequiredGoVersion: "1.27"}))
	assert.Equal(t, "", effectiveGoVersion(ModrootAnalysis{}))

	assert.Equal(t, "1.26", maxEffectiveGoVersion([]*ModrootAnalysis{
		{Modroot: "a", RequiredGoVersion: "1.26"},
		{Modroot: "b", ExistingGoVersion: "1.26"},
	}), "shared roots: max equals the common value")
	assert.Equal(t, "1.26", maxEffectiveGoVersion([]*ModrootAnalysis{
		{Modroot: "a", RequiredGoVersion: "1.26"},
		{Modroot: "b"},
	}), "divergent roots: max is the highest, not the empty one")
	assert.Equal(t, "", maxEffectiveGoVersion(nil))
}
