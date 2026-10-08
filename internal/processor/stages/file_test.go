package stages

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/isometry/choam/internal/processor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validSpec = "package:\n  name: example\n  version: \"1.0.0\"\n  epoch: 1\n"

// writerFixture writes original to a 0600 file and returns a processor whose
// current YAML is current.
func writerFixture(t *testing.T, original, current string, opts processor.ProcessorOptions) (*processor.BaseProcessor, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "example.yaml")
	require.NoError(t, os.WriteFile(path, []byte(original), 0o600))
	p := processor.NewBaseProcessor(path, "example", "1.0.0", 0)
	p.Options = opts
	p.OriginalYAML = []byte(original)
	p.CurrentYAML = []byte(current)
	return p, path
}

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestFileWriterStage_AtomicPreservesModeAndBacksUp(t *testing.T) {
	updated := validSpec + "# updated\n"
	p, path := writerFixture(t, validSpec, updated, processor.ProcessorOptions{})

	require.NoError(t, NewFileWriterStage(true, ".orig").Apply(t.Context(), p))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, updated, string(got))
	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "mode preserved across the rename")

	backup, err := os.ReadFile(path + ".orig")
	require.NoError(t, err)
	assert.Equal(t, validSpec, string(backup))
	assert.ElementsMatch(t, []string{"example.yaml", "example.yaml.orig"}, dirEntries(t, filepath.Dir(path)), "no temp file left behind")
}

func TestFileWriterStage_DryRunWritesNothing(t *testing.T) {
	p, path := writerFixture(t, validSpec, validSpec+"# updated\n", processor.ProcessorOptions{DryRun: true})

	require.NoError(t, NewFileWriterStage(true, ".orig").Apply(t.Context(), p))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, validSpec, string(got))
	assert.Equal(t, []string{"example.yaml"}, dirEntries(t, filepath.Dir(path)), "no backup or temp file in dry-run")
}

// TestValidationBeforeWrite: an invalid rewrite fails the pipeline before the
// writer runs - the file on disk is untouched.
func TestValidationBeforeWrite(t *testing.T) {
	p, path := writerFixture(t, validSpec, "package: [not, a, mapping\n", processor.ProcessorOptions{})

	pipeline := processor.NewPipeline("test")
	pipeline.AddStages(NewValidationStage(false, true), NewFileWriterStage(false, ""))
	require.Error(t, pipeline.Execute(t.Context(), p))

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, validSpec, string(got))
}

func TestValidationStage_HonoursTempDir(t *testing.T) {
	p, _ := writerFixture(t, validSpec, validSpec, processor.ProcessorOptions{TempDir: filepath.Join(t.TempDir(), "missing")})

	err := NewValidationStage(false, true).Apply(t.Context(), p)
	require.Error(t, err, "the temp file must be created in opts.TempDir")
	assert.Contains(t, err.Error(), "creating temp file")

	p.Options.TempDir = t.TempDir()
	require.NoError(t, NewValidationStage(false, true).Apply(t.Context(), p))
	assert.Empty(t, dirEntries(t, p.Options.TempDir), "validation temp file removed")
}
