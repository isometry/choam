package simulate

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSourceLint_Determinism keeps the bump packages free of the two
// constructs that made output depend on map iteration or sort instability:
// sort.Slice (unstable; use slices.SortFunc with a total order, or
// slices.SortStableFunc) and maps.Keys/maps.Values not immediately sorted
// (slices.Sorted / slices.SortedFunc). Test files are exempt (fixtures and
// fakes may iterate freely); intentional exceptions are listed below as
// "file:needle".
func TestSourceLint_Determinism(t *testing.T) {
	allowed := map[string]bool{
		// (none today)
	}
	banned := regexp.MustCompile(`\bsort\.Slice\(|\bmaps\.(Keys|Values)\(`)
	sortedWrap := regexp.MustCompile(`slices\.Sorted(Func)?\(maps\.(Keys|Values)\($`)

	for _, dir := range []string{".", "../gobump", "../scan"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		require.NoError(t, err)
		require.NotEmpty(t, files, dir)
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			src, err := os.ReadFile(file)
			require.NoError(t, err)
			for n, line := range strings.Split(string(src), "\n") {
				for _, loc := range banned.FindAllStringIndex(line, -1) {
					match := line[loc[0]:loc[1]]
					if strings.HasPrefix(match, "maps.") && sortedWrap.MatchString(line[:loc[1]]) {
						continue
					}
					key := filepath.Base(file) + ":" + match
					if allowed[key] {
						continue
					}
					t.Errorf("%s:%d: %s is nondeterministic (see test doc): %s", file, n+1, match, strings.TrimSpace(line))
				}
			}
		}
	}
}
