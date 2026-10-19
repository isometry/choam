package simulate

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/gcexportdata"
)

// typecheckFields are the go list -json fields the type-check engine decodes.
const typecheckFields = "ImportPath,Dir,GoFiles,CgoFiles,Imports,ImportMap,Standard,Module,Error"

// ErrToolchainTooNew marks a graph choam's own go/types (the Go choam was
// built with) is too old to judge: the toolchain the go list ran under, or
// a module's go directive, is a newer minor. Compile fails with it rather
// than issue a verdict; callers fail the file closed. Its text is the remedy.
var ErrToolchainTooNew = errors.New("run a choam built with that Go or newer, e.g. go run github.com/isometry/choam@latest")

// maxCompileErrorLines caps the error lines kept per failing package.
const maxCompileErrorLines = 5

// typecheckCache memoizes per-package type-check outcomes for the lifetime
// of a GoToolchain (one spec), keyed by typecheckKey: a package is rechecked
// only when its own files, language version, sizes or a direct import's API
// hash change - an importer of a patch bump that leaves the API unchanged is
// a hit (early cutoff).
// ponytail: never evicted - measure memory on the large specs first; add an
// LRU or a disk cache only if that shows it is needed.
type typecheckCache struct {
	mu           sync.Mutex
	entries      map[[sha256.Size]byte]*typecheckEntry
	hits, misses int
}

// typecheckEntry is one package's outcome: position-free export data and
// its hash when it checked cleanly, else the error lines.
type typecheckEntry struct {
	export   []byte
	apiHash  [sha256.Size]byte
	errLines []string
}

func (c *typecheckCache) get(key [sha256.Size]byte) (*typecheckEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	return entry, ok
}

func (c *typecheckCache) put(key [sha256.Size]byte, entry *typecheckEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = make(map[[sha256.Size]byte]*typecheckEntry)
	}
	c.entries[key] = entry
}

// stats returns the cumulative cache hits and misses.
func (c *typecheckCache) stats() (hits, misses int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

// unsafeEntry stands for "unsafe", which is never type-checked from source
// (the importer returns types.Unsafe).
var unsafeEntry = &typecheckEntry{apiHash: sha256.Sum256([]byte("unsafe"))}

// Compile type-checks every non-test package in the transitive import graph
// of the target's patterns in process (see typecheck), fed by one
// `go list -e -deps -json` under targetBuildEnv for arch (one arch per
// call; nothing is compiled, so no C toolchain is needed - the spec's CGO
// applies as is). An error return means the go tool or the engine could
// not judge the graph (including ErrToolchainTooNew), not that
// packages failed to type-check.
func (t *GoToolchain) Compile(ctx context.Context, dir string, target BuildTarget, arch string) (*CompileReport, error) {
	args := targetListArgs([]string{"list", "-e", "-deps", "-json=" + typecheckFields}, target.Patterns, target.Tags)
	output, err := t.runEnv(ctx, dir, targetBuildEnv(arch, target.Env), args...)
	if err != nil {
		return nil, err
	}
	var pkgs []goListPackage
	decoder := json.NewDecoder(bytes.NewReader(output))
	for {
		var pkg goListPackage
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parsing go list -deps -json output: %w", err)
		}
		pkgs = append(pkgs, pkg)
	}
	return t.typecheck(ctx, pkgs, arch)
}

// typecheck type-checks pkgs (a `go list -deps` listing, dependency order)
// in process with go/types for GOARCH=arch, as a CompileReport: a package
// with a go list error or type errors is Failed; a package whose dependency
// failed or was skipped is skipped and not reported, so failures surface on
// the deepest broken package - the module that needs blaming. A
// standard-library failure is an error, never a verdict: it is the engine,
// not the graph, that is wrong.
// Packages are checked concurrently (bounded by GOMAXPROCS) as soon as their
// imports are done; each check reads its imports' export data into a fresh
// map, so no live *types.Package is ever shared between checks.
func (t *GoToolchain) typecheck(ctx context.Context, pkgs []goListPackage, arch string) (*CompileReport, error) {
	rootVersion, err := typecheckEligible(pkgs, strings.TrimPrefix(runtime.Version(), "go"))
	if err != nil {
		return nil, err
	}
	sizes := types.SizesFor("gc", arch)
	if sizes == nil {
		return nil, fmt.Errorf("type-check: go/types has no gc sizes for GOARCH=%s", arch)
	}
	sizesKey := fmt.Sprintf("%d/%d", sizes.Sizeof(types.Typ[types.Uintptr]), sizes.Alignof(types.Typ[types.Complex128]))

	index := make(map[string]int, len(pkgs))
	for i, pkg := range pkgs {
		index[pkg.ImportPath] = i
	}
	results := make([]*typecheckEntry, len(pkgs)) // nil: skipped
	done := make([]chan struct{}, len(pkgs))
	for i := range done {
		done[i] = make(chan struct{})
	}

	hits, misses := t.typecheckCache.stats()
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.GOMAXPROCS(0))
	for i := range pkgs {
		// Launch order is dependency order, so the lowest-indexed running
		// check never waits on an unlaunched one: the bounded group cannot
		// deadlock.
		g.Go(func() error {
			defer close(done[i])
			for _, imp := range pkgs[i].Imports {
				if j, ok := index[imp]; ok {
					select {
					case <-done[j]:
					case <-gctx.Done():
						return gctx.Err()
					}
				}
			}
			entry, err := t.checkPackage(gctx, &pkgs[i], index, results, rootVersion, sizes, sizesKey)
			results[i] = entry
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	report := &CompileReport{
		Failed:  make(map[string][]string),
		Modules: make(map[string]string),
		Imports: make(map[string][]string),
	}
	for i, pkg := range pkgs {
		if pkg.Standard {
			continue
		}
		if pkg.Module != nil {
			modulePath := pkg.Module.Path
			if pkg.Module.Replace != nil && pkg.Module.Replace.Version != "" {
				modulePath = pkg.Module.Replace.Path
			}
			if pkg.Module.Main {
				modulePath = ""
			}
			report.Modules[pkg.ImportPath] = modulePath
		}
		if results[i] == nil || results[i].errLines == nil {
			continue
		}
		report.Failed[pkg.ImportPath] = results[i].errLines
		report.Imports[pkg.ImportPath] = pkg.Imports
	}
	newHits, newMisses := t.typecheckCache.stats()
	logging.From(ctx).Debug("type-checked import graph", "arch", arch, "packages", len(pkgs),
		"cached", newHits-hits, "checked", newMisses-misses, "failed", len(report.Failed))
	return report, nil
}

// checkPackage returns pkg's outcome (nil: skipped because an import failed
// or was skipped), from the cache when its key is known. results holds the
// outcomes of every import (all done).
func (t *GoToolchain) checkPackage(ctx context.Context, pkg *goListPackage, index map[string]int, results []*typecheckEntry,
	rootVersion string, sizes types.Sizes, sizesKey string) (*typecheckEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if pkg.Error != nil {
		if pkg.Standard {
			return nil, fmt.Errorf("type-check: standard package %s: %s", pkg.ImportPath, firstLine(pkg.Error.Err))
		}
		return &typecheckEntry{errLines: compileErrorLines(pkg.Error.Err)}, nil
	}
	if pkg.ImportPath == "unsafe" {
		return unsafeEntry, nil
	}
	for _, imp := range pkg.Imports {
		if j, ok := index[imp]; ok && (results[j] == nil || results[j].errLines != nil) {
			return nil, nil
		}
	}

	lang := "go" + goversion.Minor(packageGoVersion(pkg, rootVersion))
	names := slices.Concat(pkg.GoFiles, pkg.CgoFiles)
	slices.Sort(names)
	key, sources, err := typecheckKey(pkg, names, index, results, rootVersion, lang, sizesKey)
	if err != nil {
		return nil, err
	}
	if entry, ok := t.typecheckCache.get(key); ok {
		return entry, nil
	}

	entry, err := checkSources(pkg, names, sources, index, results, lang, sizes)
	if err != nil {
		return nil, err
	}
	if entry.errLines != nil && pkg.Standard {
		return nil, fmt.Errorf("type-check: standard package %s: %s", pkg.ImportPath, entry.errLines[0])
	}
	t.typecheckCache.put(key, entry)
	return entry, nil
}

// typecheckKey is the cache key of pkg: sha256 of its import path, file
// identity, language version, sizes and the sorted (import, API hash)
// pairs. GOOS/GOARCH/CGO/tags are deliberately absent - go list's file
// selection already reflects them, and amd64/arm64 gc sizes are identical.
// File identity is module@version plus file names for immutable module-cache
// and GOROOT sources; for the main module and local replacements it is the
// file contents, which are returned so a miss parses what was hashed.
func typecheckKey(pkg *goListPackage, names []string, index map[string]int, results []*typecheckEntry,
	rootVersion, lang, sizesKey string) ([sha256.Size]byte, map[string][]byte, error) {
	h := sha256.New()
	field := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }
	field(pkg.ImportPath)
	field(lang)
	field(sizesKey)

	var sources map[string][]byte
	switch {
	case pkg.Standard:
		field("go" + rootVersion)
	case pkg.Module != nil && pkg.Module.Version != "" && (pkg.Module.Replace == nil || pkg.Module.Replace.Version != ""):
		coord := pkg.Module.Path + "@" + pkg.Module.Version
		if r := pkg.Module.Replace; r != nil {
			coord = r.Path + "@" + r.Version
		}
		field(coord)
	default:
		sources = make(map[string][]byte, len(names))
		for _, name := range names {
			content, err := os.ReadFile(filepath.Join(pkg.Dir, name))
			if err != nil {
				return [sha256.Size]byte{}, nil, fmt.Errorf("type-check: reading %s: %w", name, err)
			}
			sources[name] = content
			sum := sha256.Sum256(content)
			field(string(sum[:]))
		}
	}
	for _, name := range names {
		field(name)
	}
	for _, imp := range pkg.Imports {
		if j, ok := index[imp]; ok {
			field(imp)
			field(string(results[j].apiHash[:]))
		}
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	return key, sources, nil
}

// checkSources parses and type-checks pkg (absolute Dir/file names in error
// lines), returning its export data and
// API hash, or its sorted error lines. sources supplies already-read file
// contents (nil: read from disk).
func checkSources(pkg *goListPackage, names []string, sources map[string][]byte, index map[string]int,
	results []*typecheckEntry, lang string, sizes types.Sizes) (*typecheckEntry, error) {
	fset := token.NewFileSet()
	files := make([]*ast.File, 0, len(names))
	var parseErrs []string
	for _, name := range names {
		var src any
		if content, ok := sources[name]; ok {
			src = content
		}
		file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), src, parser.SkipObjectResolution)
		if list, ok := errors.AsType[scanner.ErrorList](err); ok {
			for _, e := range list {
				parseErrs = append(parseErrs, e.Error())
			}
			continue
		} else if err != nil {
			return nil, fmt.Errorf("type-check: parsing %s: %w", name, err)
		}
		files = append(files, file)
	}
	if len(parseErrs) > 0 {
		return &typecheckEntry{errLines: compileErrorLines(strings.Join(parseErrs, "\n"))}, nil
	}

	imports := make(map[string]*types.Package) // fresh per check: never share live packages
	var typeErrs []types.Error
	conf := types.Config{
		GoVersion:   lang,
		Sizes:       sizes,
		FakeImportC: true,
		Importer: importerFunc(func(path string) (*types.Package, error) {
			if path == "unsafe" {
				return types.Unsafe, nil
			}
			if mapped, ok := pkg.ImportMap[path]; ok {
				path = mapped
			}
			if p := imports[path]; p != nil && p.Complete() {
				return p, nil
			}
			j, ok := index[path]
			if !ok || results[j] == nil || results[j].export == nil {
				return nil, fmt.Errorf("no export data for %s", path)
			}
			return gcexportdata.Read(bytes.NewReader(results[j].export), fset, imports, path)
		}),
		Error: func(err error) {
			if te, ok := errors.AsType[types.Error](err); ok && !cgoArtefact(te.Msg) {
				typeErrs = append(typeErrs, te)
			}
		},
	}
	checked, _ := conf.Check(pkg.ImportPath, fset, files, nil)
	if len(typeErrs) > 0 {
		// Position order, as gc reports them.
		slices.SortStableFunc(typeErrs, func(a, b types.Error) int {
			pa, pb := a.Fset.Position(a.Pos), b.Fset.Position(b.Pos)
			if c := strings.Compare(pa.Filename, pb.Filename); c != 0 {
				return c
			}
			if pa.Line != pb.Line {
				return pa.Line - pb.Line
			}
			return pa.Column - pb.Column
		})
		var lines []string
		var last token.Position
		var lastMsg string
		for _, e := range typeErrs {
			// gc prints one of identical messages on the same line.
			pos := e.Fset.Position(e.Pos)
			if pos.Filename == last.Filename && pos.Line == last.Line && e.Msg == lastMsg {
				continue
			}
			last, lastMsg = pos, e.Msg
			lines = append(lines, e.Error())
		}
		return &typecheckEntry{errLines: compileErrorLines(strings.Join(lines, "\n"))}, nil
	}

	// A nil FileSet writes no positions: the bytes (and hash) are the API.
	var buf bytes.Buffer
	if err := gcexportdata.Write(&buf, nil, checked); err != nil {
		return nil, fmt.Errorf("type-check: exporting %s: %w", pkg.ImportPath, err)
	}
	return &typecheckEntry{export: buf.Bytes(), apiHash: sha256.Sum256(buf.Bytes())}, nil
}

// compileErrorLines extracts the first maxCompileErrorLines diagnostic lines
// from a go list package error or joined type errors, dropping any "# pkg"
// header.
func compileErrorLines(errText string) []string {
	var lines []string
	for line := range strings.SplitSeq(errText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		lines = append(lines, line)
		if len(lines) == maxCompileErrorLines {
			break
		}
	}
	if len(lines) == 0 {
		lines = []string{strings.TrimSpace(errText)}
	}
	return lines
}

// cgoArtefact reports whether a type error is about an invalid operand or
// type. FakeImportC gives every C.x an invalid type (no C toolchain runs),
// and that type travels through export data, so such errors appear in cgo
// packages and in their non-cgo importers (a cgo package exporting a C
// type). Any other invalid operand is a follow-on of an error go/types
// reports in its own right, so no root cause is ever dropped - but an error
// whose root cause IS a C-typed expression is missed (an accepted gap,
// pinned by TestTypecheck_CgoLimitation_CTypedErrorNotCaught).
func cgoArtefact(msg string) bool {
	return strings.Contains(msg, "invalid type") || strings.Contains(msg, "invalid operand")
}

// importerFunc adapts a function to types.Importer.
type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// packageGoVersion is pkg's language version (bare), as cmd/go picks -lang
// (work/gc.go): the toolchain's for a package with no module - the standard
// library, and the command-line-arguments package go list synthesizes for a
// file pattern (main.go) - else its module's go directive (the
// replacement's when replaced), 1.16 when the module records none.
func packageGoVersion(pkg *goListPackage, rootVersion string) string {
	switch {
	case pkg.Module == nil:
		return rootVersion
	case pkg.Module.Replace != nil && pkg.Module.Replace.GoVersion != "":
		return pkg.Module.Replace.GoVersion
	default:
		return cmp.Or(pkg.Module.GoVersion, "1.16")
	}
}

// typecheckEligible returns the bare version of the GOROOT the listing was
// produced with (located through the runtime package's Dir - the go list
// may run under a GOTOOLCHAIN=auto switched toolchain, so the host probe is
// not it), or ErrToolchainTooNew when that version or any module's go
// directive is a newer minor than host (choam's own go/types). An unknown
// version on either side is a plain error.
func typecheckEligible(pkgs []goListPackage, host string) (string, error) {
	hostMinor := goversion.Minor(host)
	if hostMinor == "" {
		return "", fmt.Errorf("type-check: choam's go/types version %q is not a Go release", host)
	}
	newer := func(v string) bool { return goversion.Compare(goversion.Minor(v), hostMinor) > 0 }
	var rootVersion string
	for i := range pkgs {
		pkg := &pkgs[i]
		if pkg.Standard && pkg.ImportPath == "runtime" {
			content, err := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(pkg.Dir)), "VERSION"))
			if err != nil {
				return "", fmt.Errorf("type-check: reading the toolchain's GOROOT VERSION: %w", err)
			}
			first, _, _ := strings.Cut(string(content), "\n")
			rootVersion = strings.TrimPrefix(strings.TrimSpace(first), "go")
			continue
		}
		if v := packageGoVersion(pkg, ""); v != "" && newer(v) {
			module := pkg.Module.Path
			if r := pkg.Module.Replace; r != nil && r.GoVersion != "" {
				module = r.Path
			}
			return "", fmt.Errorf("module %s's go directive (go %s) is newer than choam's go/types (go%s): %w", module, v, host, ErrToolchainTooNew)
		}
	}
	if !goversion.IsValid(rootVersion) {
		return "", fmt.Errorf("type-check: toolchain version %q (GOROOT VERSION) is not a Go release", rootVersion)
	}
	if newer(rootVersion) {
		return "", fmt.Errorf("toolchain go %s is newer than choam's go/types (go%s): %w", rootVersion, host, ErrToolchainTooNew)
	}
	return rootVersion, nil
}
