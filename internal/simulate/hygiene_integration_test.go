package simulate

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/semver"
)

// Scanner-hygiene replay fixtures, kubeconform-shaped: the main module
// links golang.org/x/text's language and message packages only, while the
// x/text advisories name unicode/norm and secure/precis - linked module,
// unlinked vulnerable packages (see hygienePass).

const (
	modXText = "golang.org/x/text"
	modXSys  = "golang.org/x/sys"
	modExtra = "example.com/extra"
	modHB    = "example.com/hb"

	advNorm   = "GO-TEST-NORM"   // x/text/unicode/norm: not linked
	advPrecis = "GO-TEST-PRECIS" // x/text/secure/precis: not linked
	advLang   = "GO-TEST-LANG"   // x/text/language: linked
	advHBTool = "GO-TEST-HBTOOL" // example.com/hb/tool: not linked
	advExtra  = "GO-TEST-EXTRA"  // example.com/extra: module not linked
)

// textVariant shapes one x/text stub version: its go directive, its go.mod
// requires, and whether its (linked) language package imports modExtra.
type textVariant struct {
	goVersion    string
	requires     map[string]string
	importsExtra bool
}

// modFiles renders a stub module's go.mod plus its source files.
func modFiles(path, goVersion string, requires map[string]string, files map[string]string) map[string]string {
	if goVersion == "" {
		goVersion = "1.21"
	}
	var b strings.Builder
	b.WriteString("module " + path + "\n\ngo " + goVersion + "\n")
	if len(requires) > 0 {
		b.WriteString("\nrequire (\n")
		for _, mod := range sortedKeys(requires) {
			b.WriteString("\t" + mod + " " + requires[mod] + "\n")
		}
		b.WriteString(")\n")
	}
	out := map[string]string{"go.mod": b.String()}
	for name, src := range files {
		out[name] = src
	}
	return out
}

func xtextModule(v textVariant) map[string]string {
	language := "package language\n\nfunc Tag() string { return \"en\" }\n"
	if v.importsExtra {
		language = "package language\n\nimport \"" + modExtra + "\"\n\nfunc Tag() string { return extra.Name() }\n"
	}
	return modFiles(modXText, v.goVersion, v.requires, map[string]string{
		"language/language.go": language,
		"message/message.go":   "package message\n\nimport \"" + modXText + "/language\"\n\nfunc Print() string { return language.Tag() }\n",
		"unicode/norm/norm.go": "package norm\n\nfunc NFC() string { return \"nfc\" }\n",
		"secure/precis/precis.go": "package precis\n\nimport \"" + modXText + "/unicode/norm\"\n\n" +
			"func Profile() string { return norm.NFC() }\n",
	})
}

// hygieneModules serves x/text at v0.20.0 (baseline), v0.20.5, v0.21.0 and
// v0.21.5 - every version a free bump unless overridden - plus x/sys
// v0.1.0/v0.2.0, modExtra and the two-package modHB.
func hygieneModules(overrides map[string]textVariant) map[string]map[string]string {
	sysSrc := "package unix\n\nfunc Name() string { return \"unix\" }\n"
	hbFiles := map[string]string{
		"core/core.go": "package core\n\nfunc Name() string { return \"core\" }\n",
		"tool/tool.go": "package tool\n\nfunc Name() string { return \"tool\" }\n",
	}
	modules := map[string]map[string]string{
		modXSys + "@v0.1.0":  modFiles(modXSys, "", nil, map[string]string{"unix/unix.go": sysSrc}),
		modXSys + "@v0.2.0":  modFiles(modXSys, "", nil, map[string]string{"unix/unix.go": sysSrc}),
		modExtra + "@v1.0.0": modFiles(modExtra, "", nil, map[string]string{"extra.go": "package extra\n\nfunc Name() string { return \"extra\" }\n"}),
		modHB + "@v1.0.0":    modFiles(modHB, "", nil, hbFiles),
		// v1.1.0 (the hb/tool fix) raises a sibling: never free.
		modHB + "@v1.1.0": modFiles(modHB, "", map[string]string{modXSys: "v0.2.0"}, hbFiles),
	}
	for _, version := range []string{"v0.20.0", "v0.20.5", "v0.21.0", "v0.21.5"} {
		modules[modXText+"@"+version] = xtextModule(overrides[version])
	}
	return modules
}

// kubeconformMain links x/text/language and x/text/message (plus x/sys and,
// when withHB, example.com/hb/core) - never unicode/norm or secure/precis.
func kubeconformMain(textVersion string, withHB bool) map[string]string {
	requires := "\t" + modXText + " " + textVersion + "\n\t" + modXSys + " v0.1.0\n"
	imports := "\t\"" + modXSys + "/unix\"\n\t\"" + modXText + "/message\"\n"
	call := "unix.Name(), message.Print()"
	if withHB {
		requires += "\t" + modHB + " v1.0.0\n"
		imports += "\t\"" + modHB + "/core\"\n"
		call += ", core.Name()"
	}
	return map[string]string{
		"go.mod":  "module example.com/kubeconform\n\ngo 1.21\n\nrequire (\n" + requires + ")\n",
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n" + imports + ")\n\nfunc main() { fmt.Println(" + call + ") }\n",
	}
}

var (
	importsNorm   = []scan.VulnerableImport{{Path: modXText + "/unicode/norm"}}
	importsPrecis = []scan.VulnerableImport{{Path: modXText + "/secure/precis"}}
	importsLang   = []scan.VulnerableImport{{Path: modXText + "/language"}}
	importsHBTool = []scan.VulnerableImport{{Path: modHB + "/tool"}}
)

// vulnImportsOf is ModrootRequest.VulnImports for a fake scanner's
// advisories (the analysis scan's metadata).
func vulnImportsOf(sc *fakeScanner) map[string][]string {
	imports := make(map[string][]string)
	for _, adv := range sc.advisories {
		for _, imp := range adv.imports {
			imports[adv.id] = append(imports[adv.id], imp.Path)
		}
	}
	return imports
}

// hygieneCase builds a kubeconform-shaped replay case. seeds are the
// analysis seeds (nil derives them from the baseline scan, the way
// FilterBumps + seedCandidates would with no existing pins).
func hygieneCase(name string, overrides map[string]textVariant, advisories []fakeAdvisory, withHB bool, seeds []Candidate) replayCase {
	baseline := map[string]string{modXText: "v0.20.0", modXSys: "v0.1.0"}
	if withHB {
		baseline[modHB] = "v1.0.0"
	}
	sc := func() *fakeScanner { return &fakeScanner{advisories: advisories} }
	c := replayCase{
		name:    name,
		modules: hygieneModules(overrides),
		main:    kubeconformMain("v0.20.0", withHB),
		sc:      sc,
		req: ModrootRequest{
			Modroot:     ".",
			Baseline:    baseline,
			Tags:        replayTags,
			VulnImports: vulnImportsOf(sc()),
		},
	}
	if seeds == nil {
		seeds = baselineSeeds(c, nil)
	}
	c.req.Seeds = seeds
	return c
}

// baselineSeeds derives seeds from the baseline scan plus existing pins
// (module -> version), as gobump's analysis does (see nextRunSeeds).
func baselineSeeds(c replayCase, pins map[string]string) []Candidate {
	result, _ := c.sc().ScanPackages(context.Background(), packagesFor(c.req.Baseline))
	var seeds []Candidate
	for _, bump := range result.SecurityBumps {
		version := bump.FixedVersion
		also := []string{version}
		if pin, ok := pins[bump.Name]; ok {
			also = append(also, pin)
			if semver.Compare(pin, version) > 0 {
				version = pin
			}
		}
		candidate := Candidate{Module: bump.Name, Version: version, FromCVE: true, VulnIDs: bump.VulnIDs, Severity: bump.Severity}
		if rungs := FixRungs(result.Vulnerabilities, bump.Name, bump.VulnIDs, also...); len(rungs) > 1 {
			candidate.Rungs = rungs
		}
		seeds = append(seeds, candidate)
	}
	return seeds
}

var (
	normAdvisories = []fakeAdvisory{
		{module: modXText, id: advNorm, fixed: "v0.21.0", severity: "MEDIUM", imports: importsNorm},
		{module: modXText, id: advPrecis, fixed: "v0.21.0", severity: "MEDIUM", imports: importsPrecis},
	}
	siblingAt = textVariant{requires: map[string]string{modXSys: "v0.2.0"}}
)

func hygieneFreeCase() replayCase {
	c := hygieneCase("hygiene-free", nil, normAdvisories, false, nil)
	c.noTidyVariant = true
	return c
}

func hygieneSiblingCase() replayCase {
	return hygieneCase("hygiene-sibling", map[string]textVariant{"v0.21.0": siblingAt}, normAdvisories, false, nil)
}

func hygieneMixedCase(fixVariant textVariant, name string) replayCase {
	advisories := append([]fakeAdvisory{{module: modXText, id: advLang, fixed: "v0.20.5", severity: "HIGH", imports: importsLang}},
		normAdvisories...)
	return hygieneCase(name, map[string]textVariant{"v0.21.0": fixVariant}, advisories, false, nil)
}

func hygieneBatchCase() replayCase {
	advisories := append([]fakeAdvisory{{module: modHB, id: advHBTool, fixed: "v1.1.0", severity: "HIGH", imports: importsHBTool}},
		normAdvisories...)
	return hygieneCase("hygiene-batch", nil, advisories, true, nil)
}

func hygienePinKeptCase() replayCase {
	c := hygieneCase("hygiene-pin-kept", nil, normAdvisories, false, []Candidate{})
	c.req.Seeds = baselineSeeds(c, map[string]string{modXText: "v0.21.5"})
	return c
}

func hygieneReplayCases() []replayCase {
	return []replayCase{hygieneFreeCase(), hygieneSiblingCase(), hygieneMixedCase(siblingAt, "hygiene-mixed"),
		hygieneBatchCase(), hygienePinKeptCase()}
}

func hygieneDrop(result *ModrootResult, module string) (DroppedCandidate, bool) {
	i := slices.IndexFunc(result.Dropped, func(d DroppedCandidate) bool { return d.Module == module && d.Hygiene })
	if i < 0 {
		return DroppedCandidate{}, false
	}
	return result.Dropped[i], true
}

// TestReplay_HygieneFree: kubeconform's shape - the x/text advisories'
// packages are not linked, the module is, and the fix changes nothing else:
// the bump is proposed as scanner hygiene (written, but not CVE-backed),
// and its applied deps compile.
func TestReplay_HygieneFree(t *testing.T) {
	for _, noTidy := range []bool{false, true} {
		t.Run(fmt.Sprintf("notidy=%v", noTidy), func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, eng Engine) {
				c := hygieneFreeCase()
				f := c.fixture(t)
				trace := &traceCapture{}
				result, err := c.runCtx(logging.Into(t.Context(), slog.New(trace)), f, eng, noTidy)
				require.NoError(t, err)
				logResult(t, result)
				if !noTidy {
					assertGolden(t, "kubeconform-hygiene-"+eng.String(), result)
				}

				assert.Equal(t, []string{modXText + "@v0.21.0"}, result.FinalDeps)
				assert.Empty(t, result.CVEBackedModules, "a hygiene bump is never a security fix")
				assert.Equal(t, []HygieneModule{{Module: modXText, Version: "v0.21.0", VulnIDs: []string{advNorm, advPrecis}}}, result.HygieneModules)
				assert.Empty(t, result.Dropped, "the seed shed as unlinked is kept after all")
				assert.Empty(t, result.Residuals)
				assert.Equal(t, 1, countTrials(trace, "hygiene: "), "one trial for one target")
				if !noTidy {
					assert.Empty(t, f.compileFailuresWith(t, eng, result.FinalDeps))
				}
			})
		})
	}
}

func countTrials(trace *traceCapture, prefix string) int {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	n := 0
	for _, rec := range trace.records {
		if purpose, _ := rec.attrs["purpose"].(string); rec.msg == trialLogMsg && strings.HasPrefix(purpose, prefix) {
			n++
		}
	}
	return n
}

// TestReplay_HygieneNotFree: a hygiene fix that raises the go floor, adds a
// module or raises a sibling is not free: no bump is written, and the
// seed's pin is reported as shed with the precise reason.
func TestReplay_HygieneNotFree(t *testing.T) {
	cases := []struct {
		name    string
		variant textVariant
		reason  string
	}{
		{"go-floor", textVariant{goVersion: "1.22"}, `raises dependency Go 1\.21->1\.22|go/toolchain lines`},
		{"adds-module", textVariant{requires: map[string]string{modExtra: "v1.0.0"}, importsExtra: true}, `adds ` + modExtra + `@v1\.0\.0`},
		{"sibling", siblingAt, `changes ` + modXSys + ` v0\.1\.0->v0\.2\.0`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			forEachEngine(t, func(t *testing.T, eng Engine) {
				c := hygieneCase("hygiene-"+tc.name, map[string]textVariant{"v0.21.0": tc.variant}, normAdvisories, false, nil)
				f := c.fixture(t)
				result, err := c.run(t, f, eng, false)
				require.NoError(t, err)
				logResult(t, result)

				assert.Empty(t, result.FinalDeps)
				assert.Empty(t, result.HygieneModules)
				assert.Equal(t, "v0.20.0", result.Resolved[modXText])
				drop, ok := hygieneDrop(result, modXText)
				require.True(t, ok, "the not-free bump is reported")
				assert.Equal(t, "v0.21.0", drop.Version)
				assert.Contains(t, drop.Reason, "shed: scanner hygiene pin "+modXText+"@v0.21.0 not free (")
				assert.Regexp(t, tc.reason, drop.Reason)
				assert.Len(t, result.Dropped, 1, "the shed seed's record is reworded, not duplicated")
			})
		})
	}
}

// TestReplay_HygieneUnlinkedModule: an advisory in a module that is not
// linked at all is still just dropped - no hygiene bump.
func TestReplay_HygieneUnlinkedModule(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		advisories := append([]fakeAdvisory{{module: modExtra, id: advExtra, fixed: "v1.0.1", severity: "HIGH"}}, normAdvisories...)
		c := hygieneCase("hygiene-unlinked-module", map[string]textVariant{"v0.20.0": {requires: map[string]string{modExtra: "v1.0.0"}}},
			advisories, false, nil)
		c.req.Baseline[modExtra] = "v1.0.0"
		c.req.Seeds = baselineSeeds(c, nil)
		f := c.fixture(t)
		result, err := c.run(t, f, eng, false)
		require.NoError(t, err)
		logResult(t, result)

		assert.NotContains(t, strings.Join(result.FinalDeps, " "), modExtra)
		assert.False(t, slices.ContainsFunc(result.HygieneModules, func(h HygieneModule) bool { return h.Module == modExtra }))
		i := slices.IndexFunc(result.Dropped, func(d DroppedCandidate) bool { return d.Module == modExtra })
		require.GreaterOrEqual(t, i, 0)
		assert.Contains(t, result.Dropped[i].Reason, "module not linked")
		assert.False(t, result.Dropped[i].Hygiene)
	})
}

// TestReplay_HygienePins: an existing pin above the fix is kept when free;
// one that is not free falls back to the (free) minimal fix; and once
// upstream itself is at the fix, the pin goes (nothing needs it).
func TestReplay_HygienePins(t *testing.T) {
	t.Run("kept", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T, eng Engine) {
			c := hygienePinKeptCase()
			result, err := c.run(t, c.fixture(t), eng, false)
			require.NoError(t, err)
			logResult(t, result)
			assert.Equal(t, []string{modXText + "@v0.21.5"}, result.FinalDeps)
			assert.Equal(t, []HygieneModule{{Module: modXText, Version: "v0.21.5", VulnIDs: []string{advNorm, advPrecis}}}, result.HygieneModules)
			assert.Empty(t, result.Dropped)
		})
	})
	t.Run("pin-not-free", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T, eng Engine) {
			c := hygieneCase("hygiene-pin-not-free", map[string]textVariant{"v0.21.5": siblingAt}, normAdvisories, false, []Candidate{})
			c.req.Seeds = baselineSeeds(c, map[string]string{modXText: "v0.21.5"})
			result, err := c.run(t, c.fixture(t), eng, false)
			require.NoError(t, err)
			logResult(t, result)
			assert.Equal(t, []string{modXText + "@v0.21.0"}, result.FinalDeps, "the pin falls back to the free minimal fix")
			assert.Equal(t, []HygieneModule{{Module: modXText, Version: "v0.21.0", VulnIDs: []string{advNorm, advPrecis}}}, result.HygieneModules)
			assert.Empty(t, result.Dropped)
		})
	})
	t.Run("upstream-caught-up", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T, eng Engine) {
			c := hygieneFreeCase()
			c.main = kubeconformMain("v0.21.0", false)
			c.req.Baseline[modXText] = "v0.21.0"
			c.req.Seeds = []Candidate{{Module: modXText, Version: "v0.21.0"}} // last run's hygiene pin
			result, err := c.run(t, c.fixture(t), eng, false)
			require.NoError(t, err)
			logResult(t, result)
			assert.Empty(t, result.FinalDeps)
			assert.Empty(t, result.HygieneModules)
			require.Len(t, result.Dropped, 1, "the pin goes: no advisory needs it")
			assert.False(t, result.Dropped[0].Hygiene)
		})
	})
}

// TestReplay_HygieneMixedModule: x/text has a linked advisory fixed at
// v0.20.5 and unlinked ones fixed at v0.21.0. The security target stops at
// the linked advisory's fix; v0.21.0 is hygiene - written when free, shed
// (and the security fix kept) when not.
func TestReplay_HygieneMixedModule(t *testing.T) {
	t.Run("not-free", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T, eng Engine) {
			c := hygieneMixedCase(siblingAt, "hygiene-mixed")
			result, err := c.run(t, c.fixture(t), eng, false)
			require.NoError(t, err)
			logResult(t, result)
			assert.Equal(t, []string{modXText + "@v0.20.5"}, result.FinalDeps, "the security target is the linked advisory's fix")
			assert.Equal(t, []string{modXText}, result.CVEBackedModules)
			assert.Empty(t, result.HygieneModules)
			assert.Empty(t, result.Residuals, "unlinked advisories are never residual")
			assert.Equal(t, "v0.1.0", result.Resolved[modXSys], "the sibling is not raised")
			drop, ok := hygieneDrop(result, modXText)
			require.True(t, ok)
			assert.Contains(t, drop.Reason, "shed: scanner hygiene pin "+modXText+"@v0.21.0 not free (changes "+modXSys)
		})
	})
	t.Run("free", func(t *testing.T) {
		forEachEngine(t, func(t *testing.T, eng Engine) {
			c := hygieneMixedCase(textVariant{}, "hygiene-mixed-free")
			result, err := c.run(t, c.fixture(t), eng, false)
			require.NoError(t, err)
			logResult(t, result)
			assert.Equal(t, []string{modXText + "@v0.21.0"}, result.FinalDeps)
			assert.Equal(t, []string{modXText}, result.CVEBackedModules)
			assert.Equal(t, []HygieneModule{{Module: modXText, Version: "v0.21.0", VulnIDs: []string{advNorm, advPrecis}}}, result.HygieneModules)
			assert.Empty(t, result.Dropped)
		})
	})
}

// TestReplay_HygieneBatchThenSingles: two hygiene targets, one not free
// (example.com/hb's fix raises x/sys). The batch trial fails; the targets
// are then tried alone, most severe first, and exactly the free one is
// accepted.
func TestReplay_HygieneBatchThenSingles(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		c := hygieneBatchCase()
		trace := &traceCapture{}
		result, err := c.runCtx(logging.Into(t.Context(), slog.New(trace)), c.fixture(t), eng, false)
		require.NoError(t, err)
		logResult(t, result)

		assert.Equal(t, []string{modXText + "@v0.21.0"}, result.FinalDeps)
		assert.Equal(t, []HygieneModule{{Module: modXText, Version: "v0.21.0", VulnIDs: []string{advNorm, advPrecis}}}, result.HygieneModules)
		drop, ok := hygieneDrop(result, modHB)
		require.True(t, ok)
		assert.Contains(t, drop.Reason, "changes "+modXSys+" v0.1.0->v0.2.0")
		assert.Equal(t, 1, countTrials(trace, "hygiene: batch"))
		assert.Equal(t, 1, countTrials(trace, "hygiene: "+modHB))
		assert.Equal(t, 1, countTrials(trace, "hygiene: "+modXText))
	})
}

// TestReplay_HygieneSkippedWithoutCompileGate: without the compile gate no
// bump can be proven free, so none is proposed and the skip is reported.
func TestReplay_HygieneSkippedWithoutCompileGate(t *testing.T) {
	c := hygieneFreeCase()
	f := c.fixture(t)
	result, err := RunLoop(t.Context(), f.tc, c.sc(), f.dir, c.req, Options{NoCompile: true})
	require.NoError(t, err)
	assert.Empty(t, result.FinalDeps)
	assert.Empty(t, result.HygieneModules)
	assert.Equal(t, "compile gate disabled ("+modXText+"@v0.21.0)", result.HygieneSkipped)
}
