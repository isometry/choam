package simulate

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/isometry/choam/internal/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Replay fixtures for the opentofu-1.12 otel regression: offline (file://
// GOPROXY stub modules), real go toolchain, fake scanner. The stubs carry
// the requirement edges of the real releases (proxy.golang.org .mod files):
// otel/log v0.21.0 removed KeyValue/Value, sdk/log and the log exporters
// moved to it in lockstep, and the trace SDK/exporters and grpc are
// independent of otel/log.

const (
	modLog       = "go.opentelemetry.io/otel/log"
	modSDKLog    = "go.opentelemetry.io/otel/sdk/log"
	modSDK       = "go.opentelemetry.io/otel/sdk"
	modLogHTTP   = "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	modLogGRPC   = "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	modStdoutLog = "go.opentelemetry.io/otel/exporters/stdout/stdoutlog"
	modTraceHTTP = "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	modGRPC      = "google.golang.org/grpc"
	modXNet      = "golang.org/x/net"

	advSDKHigh   = "GHSA-hfvc-g4fc-pqhx" // otel/sdk, fixed v1.43.0
	advSDKLow    = "GHSA-8wmf-6v46-5gfg" // otel/sdk, fixed v1.45.0
	advTraceHigh = "GO-TEST-TRACE-143"
	advTraceLow  = "GO-TEST-TRACE-145"
	advGRPC      = "GO-TEST-GRPC"
	advSDKLog    = "GO-TEST-SDKLOG"
	advLogGRPC   = "GO-TEST-OTLPLOGGRPC"
	advLogHTTP   = "GO-TEST-OTLPLOGHTTP"
)

var replayTags = []string{"netgo", "osusergo"}

// replayFixture is a tidied main module plus a pristine copy of it (for
// re-verifying a final deps list from scratch).
type replayFixture struct {
	tc       *GoToolchain
	dir      string
	pristine string
}

// stubModule renders one stub module version: go.mod with the given
// requires (module -> version) plus one source file.
func stubModule(path, file, src string, requires map[string]string) map[string]string {
	var b strings.Builder
	b.WriteString("module " + path + "\n\ngo 1.21\n")
	if len(requires) > 0 {
		b.WriteString("\nrequire (\n")
		for _, mod := range sortedKeys(requires) {
			b.WriteString("\t" + mod + " " + requires[mod] + "\n")
		}
		b.WriteString(")\n")
	}
	return map[string]string{"go.mod": b.String(), file: src}
}

// newReplayFixture serves modules from a file:// proxy, writes and tidies
// the main module, and snapshots it.
func newReplayFixture(t *testing.T, modules map[string]map[string]string, main map[string]string) replayFixture {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping go toolchain integration test in -short mode")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain unavailable: %v", err)
	}
	useFileProxy(t, writeFileProxy(t, modules))
	dir := newFixtureModule(t, main)
	pristine := t.TempDir()
	for name := range main {
		copyFile(t, filepath.Join(dir, name), filepath.Join(pristine, name))
	}
	copyFile(t, filepath.Join(dir, "go.mod"), filepath.Join(pristine, "go.mod"))
	copyFile(t, filepath.Join(dir, "go.sum"), filepath.Join(pristine, "go.sum"))
	tc, err := NewToolchain(t.Context(), 2*time.Minute)
	require.NoError(t, err)
	return replayFixture{tc: tc, dir: dir, pristine: pristine}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	content, err := os.ReadFile(from)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(to, content, 0o644))
}

// forEachEngine runs fn once per apply engine, as named sub-tests.
func forEachEngine(t *testing.T, fn func(t *testing.T, eng Engine)) {
	t.Helper()
	for _, eng := range []Engine{EngineGobump, EngineOmnibump} {
		t.Run(eng.String(), func(t *testing.T) { fn(t, eng) })
	}
}

// compileFailuresWith applies deps to a fresh copy of the pristine module the
// way the build's bump step does (gobump: tidy, go get each, tidy; omnibump:
// its filter and DoUpdate) and returns the compile failures ("" when the
// result compiles).
func (f replayFixture) compileFailuresWith(t tb, eng Engine, deps []string) string {
	t.Helper()
	ctx := t.Context()
	dir, err := os.MkdirTemp("", "choam-replay-verify-")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(dir) }()
	entries, err := os.ReadDir(f.pristine)
	require.NoError(t, err)
	for _, e := range entries {
		content, err := os.ReadFile(filepath.Join(f.pristine, e.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, e.Name()), content, 0o644))
	}
	if eng == EngineOmnibump {
		require.NoError(t, omnibumpApply(ctx, f.tc, dir, ModrootRequest{Engine: eng}, deps))
	} else {
		require.NoError(t, f.tc.ModTidy(ctx, dir))
		for _, dep := range deps {
			require.NoError(t, f.tc.Get(ctx, dir, dep))
		}
		require.NoError(t, f.tc.ModTidy(ctx, dir))
	}
	report, err := f.tc.Compile(ctx, dir, nil, replayTags)
	require.NoError(t, err)
	if len(report.Failed) == 0 {
		return ""
	}
	return firstCompileError(report.Failed)
}

// traceRecord is one captured simulate trace record (see logTrial).
type traceRecord struct {
	msg   string
	attrs map[string]any
}

// traceCapture is a Debug-level slog handler recording every record, so a
// test can assert what each simulation trial applied.
type traceCapture struct {
	mu      sync.Mutex
	records []traceRecord
}

func (h *traceCapture) Enabled(context.Context, slog.Level) bool { return true }

func (h *traceCapture) Handle(_ context.Context, r slog.Record) error {
	rec := traceRecord{msg: r.Message, attrs: make(map[string]any)}
	r.Attrs(func(a slog.Attr) bool {
		rec.attrs[a.Key] = a.Value.Any()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, rec)
	return nil
}

func (h *traceCapture) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *traceCapture) WithGroup(string) slog.Handler      { return h }

// trials returns the captured trial records' pin lists, in order, each pin
// reduced to "module@version" (role suffix stripped).
func (h *traceCapture) trials() [][]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var trials [][]string
	for _, rec := range h.records {
		if rec.msg != trialLogMsg {
			continue
		}
		raw, _ := rec.attrs["pins"].([]string)
		pins := make([]string, 0, len(raw))
		for _, p := range raw {
			coord, _, _ := strings.Cut(p, "(")
			pins = append(pins, coord)
		}
		trials = append(trials, pins)
	}
	return trials
}

func containsPinFor(pins []string, module string) bool {
	return slices.ContainsFunc(pins, func(p string) bool { return strings.HasPrefix(p, module+"@") })
}

func residualIDs(residuals []Residual, module string) []string {
	var ids []string
	for _, r := range residuals {
		if r.Module == module {
			ids = append(ids, r.VulnIDs...)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

// otelFamilyModules builds the otel stub family. Old-train code (log
// <= v0.20.0) uses log.KeyValue/log.Value; v0.21.0 removed them.
func otelFamilyModules() map[string]map[string]string {
	oldLog := "package log\n\ntype Value struct{ s string }\n\nfunc StringValue(s string) Value { return Value{s} }\n\n" +
		"type KeyValue struct {\n\tKey   string\n\tValue Value\n}\n\nfunc String(k, v string) KeyValue { return KeyValue{k, StringValue(v)} }\n\n" +
		"func Name() string { return \"log\" }\n"
	newLog := "package log\n\ntype Attr struct{ Key, Val string }\n\nfunc Attribute(k, v string) Attr { return Attr{k, v} }\n\n" +
		"func Name() string { return \"log\" }\n"

	sdkLogSrc := func(newAPI bool) string {
		attr := "api.String(\"service\", \"tofu\")"
		typ := "api.KeyValue"
		if newAPI {
			attr, typ = "api.Attribute(\"service\", \"tofu\")", "api.Attr"
		}
		return "package log\n\nimport api \"" + modLog + "\"\n\ntype Provider struct{ attrs []" + typ + " }\n\n" +
			"func NewProvider() *Provider { return &Provider{attrs: []" + typ + "{" + attr + "}} }\n"
	}
	// exporterSrc: v0.18.0 uses only otel/log (+ sdk); later versions also
	// build on sdk/log.
	exporterSrc := func(pkg string, newAPI, usesSDKLog bool) string {
		kv := "log.String(\"k\", \"v\").Key"
		if newAPI {
			kv = "log.Attribute(\"k\", \"v\").Key"
		}
		imports := "\t\"" + modLog + "\"\n\t\"" + modSDK + "\"\n"
		body := "func New() string { return " + kv + " + sdk.Version()"
		if usesSDKLog {
			imports += "\tsdklog \"" + modSDKLog + "\"\n"
			body += " + sdklog.NewProvider().String()"
		}
		return "package " + pkg + "\n\nimport (\n" + imports + ")\n\n" + body + " }\n"
	}
	exporter := func(path, pkg string) map[string]map[string]string {
		return map[string]map[string]string{
			path + "@v0.18.0": stubModule(path, "exporter.go", exporterSrc(pkg, false, false),
				map[string]string{modLog: "v0.18.0", modSDK: "v1.42.0"}),
			path + "@v0.19.0": stubModule(path, "exporter.go", exporterSrc(pkg, false, true),
				map[string]string{modLog: "v0.19.0", modSDKLog: "v0.19.0", modSDK: "v1.43.0"}),
			path + "@v0.21.0": stubModule(path, "exporter.go", exporterSrc(pkg, true, true),
				map[string]string{modLog: "v0.21.0", modSDKLog: "v0.21.0", modSDK: "v1.45.0"}),
		}
	}
	sdkSrc := func(v string) string { return "package sdk\n\nfunc Version() string { return \"" + v + "\" }\n" }
	traceSrc := "package otlptracehttp\n\nimport \"" + modSDK + "\"\n\nfunc New() string { return sdk.Version() }\n"
	grpcSrc := "package grpc\n\nfunc Version() string { return \"grpc\" }\n"

	modules := map[string]map[string]string{
		modLog + "@v0.18.0": stubModule(modLog, "log.go", oldLog, nil),
		modLog + "@v0.19.0": stubModule(modLog, "log.go", oldLog, nil),
		modLog + "@v0.20.0": stubModule(modLog, "log.go", oldLog, nil),
		modLog + "@v0.21.0": stubModule(modLog, "log.go", newLog, nil),

		modSDKLog + "@v0.18.0": stubModule(modSDKLog, "provider.go", sdkLogSrc(false)+providerString, map[string]string{modLog: "v0.18.0"}),
		modSDKLog + "@v0.19.0": stubModule(modSDKLog, "provider.go", sdkLogSrc(false)+providerString, map[string]string{modLog: "v0.19.0"}),
		modSDKLog + "@v0.21.0": stubModule(modSDKLog, "provider.go", sdkLogSrc(true)+providerString, map[string]string{modLog: "v0.21.0"}),

		modSDK + "@v1.42.0": stubModule(modSDK, "sdk.go", sdkSrc("1.42.0"), nil),
		modSDK + "@v1.43.0": stubModule(modSDK, "sdk.go", sdkSrc("1.43.0"), nil),
		modSDK + "@v1.45.0": stubModule(modSDK, "sdk.go", sdkSrc("1.45.0"), nil),

		modTraceHTTP + "@v1.42.0": stubModule(modTraceHTTP, "exporter.go", traceSrc, map[string]string{modSDK: "v1.42.0"}),
		modTraceHTTP + "@v1.43.0": stubModule(modTraceHTTP, "exporter.go", traceSrc, map[string]string{modSDK: "v1.43.0"}),
		modTraceHTTP + "@v1.45.0": stubModule(modTraceHTTP, "exporter.go", traceSrc, map[string]string{modSDK: "v1.45.0"}),

		modGRPC + "@v1.79.3": stubModule(modGRPC, "grpc.go", grpcSrc, nil),
		modGRPC + "@v1.83.2": stubModule(modGRPC, "grpc.go", grpcSrc, nil),
	}
	for _, e := range [][2]string{{modLogHTTP, "otlploghttp"}, {modLogGRPC, "otlploggrpc"}, {modStdoutLog, "stdoutlog"}} {
		for coord, files := range exporter(e[0], e[1]) {
			modules[coord] = files
		}
	}
	return modules
}

// providerString gives every sdk/log version a stable String method the
// exporters can call regardless of train.
const providerString = "\nfunc (p *Provider) String() string { return \"provider\" }\n"

// opentofuMain is the "opentofu" main module at the baseline versions.
func opentofuMain() map[string]string {
	return map[string]string{
		"go.mod": "module github.com/opentofu/opentofu\n\ngo 1.21\n\nrequire (\n" +
			"\t" + modLog + " v0.18.0\n" +
			"\t" + modSDKLog + " v0.18.0\n" +
			"\t" + modLogHTTP + " v0.18.0\n" +
			"\t" + modLogGRPC + " v0.18.0\n" +
			"\t" + modStdoutLog + " v0.18.0\n" +
			"\t" + modSDK + " v1.42.0\n" +
			"\t" + modTraceHTTP + " v1.42.0\n" +
			"\t" + modGRPC + " v1.79.3\n" +
			")\n",
		"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n" +
			"\t\"" + modLogGRPC + "\"\n" +
			"\t\"" + modLogHTTP + "\"\n" +
			"\t\"" + modTraceHTTP + "\"\n" +
			"\t\"" + modStdoutLog + "\"\n" +
			"\totellog \"" + modLog + "\"\n" +
			"\t\"" + modSDK + "\"\n" +
			"\tsdklog \"" + modSDKLog + "\"\n" +
			"\t\"" + modGRPC + "\"\n" +
			")\n\nfunc main() {\n\tfmt.Println(otellog.Name(), sdklog.NewProvider().String(), otlploghttp.New(), otlploggrpc.New(),\n" +
			"\t\tstdoutlog.New(), sdk.Version(), otlptracehttp.New(), grpc.Version())\n}\n",
	}
}

// otelFamilyAdvisories mirrors the OSV picture for opentofu-1.12's graph:
// two fix rungs for otel/sdk and otlptracehttp, a CVE fix for otlploghttp
// below the breaking v0.21 train, and none for stdoutlog.
func otelFamilyAdvisories() *fakeScanner {
	return &fakeScanner{advisories: []fakeAdvisory{
		{module: modSDK, id: advSDKHigh, fixed: "v1.43.0", severity: "HIGH"},
		{module: modSDK, id: advSDKLow, fixed: "v1.45.0", severity: "LOW"},
		{module: modTraceHTTP, id: advTraceHigh, fixed: "v1.43.0", severity: "HIGH"},
		{module: modTraceHTTP, id: advTraceLow, fixed: "v1.45.0", severity: "LOW"},
		{module: modGRPC, id: advGRPC, fixed: "v1.83.2", severity: "HIGH"},
		{module: modSDKLog, id: advSDKLog, fixed: "v0.21.0", severity: "MEDIUM"},
		{module: modLogGRPC, id: advLogGRPC, fixed: "v0.21.0", severity: "MEDIUM"},
		{module: modLogHTTP, id: advLogHTTP, fixed: "v0.19.0", severity: "MEDIUM"},
	}}
}

// sdkRungs is otel/sdk's fix ladder as seedCandidates builds it: the
// v1.45.0 (LOW) and v1.43.0 (HIGH, also the existing YAML pin) fixes.
var sdkRungs = []Rung{
	{Version: "v1.45.0", VulnIDs: []string{advSDKLow}, Severity: "LOW"},
	{Version: "v1.43.0", VulnIDs: []string{advSDKHigh}, Severity: "HIGH"},
}

// opentofuSeeds are the seeds the analysis hands the loop for the spec's
// existing deps (sdk@v1.43.0, otlploghttp@v0.19.0, otlptracehttp@v1.43.0)
// merged with the baseline scan's bumps: FilterBumps keeps the higher
// version per module, seedCandidates marks every module with a bump as
// CVE-backed with all of its advisory IDs and keeps the per-advisory fix
// rungs.
func opentofuSeeds() []Candidate {
	return []Candidate{
		{Module: modSDK, Version: "v1.45.0", FromCVE: true, VulnIDs: []string{advSDKLow, advSDKHigh}, Severity: "HIGH", Rungs: sdkRungs},
		{Module: modLogHTTP, Version: "v0.19.0", FromCVE: true, VulnIDs: []string{advLogHTTP}, Severity: "MEDIUM"},
		{Module: modTraceHTTP, Version: "v1.45.0", FromCVE: true, VulnIDs: []string{advTraceHigh, advTraceLow}, Severity: "HIGH", Rungs: []Rung{
			{Version: "v1.45.0", VulnIDs: []string{advTraceLow}, Severity: "LOW"},
			{Version: "v1.43.0", VulnIDs: []string{advTraceHigh}, Severity: "HIGH"},
		}},
		{Module: modGRPC, Version: "v1.83.2", FromCVE: true, VulnIDs: []string{advGRPC}, Severity: "HIGH"},
		{Module: modSDKLog, Version: "v0.21.0", FromCVE: true, VulnIDs: []string{advSDKLog}, Severity: "MEDIUM"},
		{Module: modLogGRPC, Version: "v0.21.0", FromCVE: true, VulnIDs: []string{advLogGRPC}, Severity: "MEDIUM"},
	}
}

func logResult(t tb, result *ModrootResult) {
	t.Logf("final deps: %v", result.FinalDeps)
	for _, r := range result.Residuals {
		t.Logf("residual: %s resolved=%s fixed=%s vulns=%v reason=%q", r.Module, r.ResolvedVersion, r.FixedVersion, r.VulnIDs, r.Reason)
	}
	for _, d := range result.Dropped {
		t.Logf("dropped: %s@%s reason=%q", d.Module, d.Version, d.Reason)
	}
}

// TestReplay_OpentofuOtelFamily (a): the whole opentofu otel picture. The
// correct end state moves the log train together (sdk/log and every log
// exporter, including the advisory-free stdoutlog, at v0.21.0), takes the
// trace side and grpc to their top fixes, leaves no "breaks compile"
// residual, and the written deps compile from scratch.
func TestReplay_OpentofuOtelFamily(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		f := newReplayFixture(t, otelFamilyModules(), opentofuMain())

		assertFixed(t, defectFamilyCoUpdate, func(t tb) {
			result, err := RunLoop(t.Context(), f.tc, otelFamilyAdvisories(), f.dir, ModrootRequest{
				Modroot: ".",
				Seeds:   opentofuSeeds(),
				Baseline: map[string]string{
					modLog: "v0.18.0", modSDKLog: "v0.18.0", modLogHTTP: "v0.18.0", modLogGRPC: "v0.18.0",
					modStdoutLog: "v0.18.0", modSDK: "v1.42.0", modTraceHTTP: "v1.42.0", modGRPC: "v1.79.3",
				},
				Tags:   replayTags,
				Engine: eng,
			}, Options{})
			require.NoError(t, err)
			logResult(t, result)

			want := map[string]string{
				modSDK: "v1.45.0", modTraceHTTP: "v1.45.0", modGRPC: "v1.83.2",
				modLog: "v0.21.0", modSDKLog: "v0.21.0", modLogGRPC: "v0.21.0", modLogHTTP: "v0.21.0", modStdoutLog: "v0.21.0",
			}
			for module, version := range want {
				assert.Equal(t, version, result.Resolved[module], "resolved %s", module)
			}
			for _, r := range result.Residuals {
				assert.NotContains(t, r.Reason, "breaks compile", "no family member may be left as a compile residual: %s", r.Module)
			}
			assert.Empty(t, result.Residuals)
			assert.Empty(t, f.compileFailuresWith(t, eng, result.FinalDeps), "the written deps must compile")
		})
	})
}

// TestReplay_RungFallback (b): otel/sdk has fixes at v1.43.0 (HIGH) and
// v1.45.0 (LOW), and v1.45.0 does not compile. The candidate must relax one
// rung to v1.43.0 - never stay at the v1.42.0 baseline - leaving only the
// v1.45.0-only advisory residual.
func TestReplay_RungFallback(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		sdkSrc := func(body string) string { return "package sdk\n\nfunc Version() string { return " + body + " }\n" }
		f := newReplayFixture(t, map[string]map[string]string{
			modSDK + "@v1.42.0": stubModule(modSDK, "sdk.go", sdkSrc(`"1.42.0"`), nil),
			modSDK + "@v1.43.0": stubModule(modSDK, "sdk.go", sdkSrc(`"1.43.0"`), nil),
			modSDK + "@v1.45.0": stubModule(modSDK, "sdk.go", sdkSrc(`145`), nil), // type error: does not compile
		}, map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire " + modSDK + " v1.42.0\n",
			"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"" + modSDK + "\"\n)\n\nfunc main() { fmt.Println(sdk.Version()) }\n",
		})
		sc := &fakeScanner{advisories: []fakeAdvisory{
			{module: modSDK, id: advSDKHigh, fixed: "v1.43.0", severity: "HIGH"},
			{module: modSDK, id: advSDKLow, fixed: "v1.45.0", severity: "LOW"},
		}}

		assertFixed(t, defectRungFallback, func(t tb) {
			result, err := RunLoop(t.Context(), f.tc, sc, f.dir, ModrootRequest{
				Modroot: ".",
				Seeds: []Candidate{
					{Module: modSDK, Version: "v1.45.0", FromCVE: true, VulnIDs: []string{advSDKLow, advSDKHigh}, Severity: "HIGH", Rungs: sdkRungs},
				},
				Baseline: map[string]string{modSDK: "v1.42.0"},
				Tags:     replayTags,
				Engine:   eng,
			}, Options{})
			require.NoError(t, err)
			logResult(t, result)

			assert.Equal(t, "v1.43.0", result.Resolved[modSDK], "one rung down from the uncompilable v1.45.0")
			assert.Equal(t, []string{modSDK + "@v1.43.0"}, result.FinalDeps)
			assert.Equal(t, []string{advSDKLow}, residualIDs(result.Residuals, modSDK),
				"only the advisory fixed solely in v1.45.0 remains")
			assert.Empty(t, f.compileFailuresWith(t, eng, result.FinalDeps))
		})
	})
}

// TestReplay_NoCrossContamination (c): A (fix compiles, but a lagging
// sibling S requires A, so the gate blames it) and B (fix raises an API
// whose break the sibling L cannot follow) are independent. S's coherence
// raise only supports B (S v0.2.0 is the first release built against the
// raised API), so it must never be attached to a trial without B, and A
// must be admitted.
func TestReplay_NoCrossContamination(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		const (
			modAPI = "example.com/api"
			modA   = "example.com/a"
			modB   = "example.com/b"
			modS   = "example.com/s"
			modL   = "example.com/l"
		)
		oldAPI := "package api\n\ntype KeyValue struct{ Key string }\n\nfunc Name() string { return \"api\" }\n"
		newAPI := "package api\n\ntype Attr struct{ Key string }\n\nfunc Name() string { return \"api\" }\n"
		aSrc := "package a\n\nfunc Name() string { return \"a\" }\n"
		userSrc := func(pkg, typ string, importsA bool) string {
			imports := "import \"" + modAPI + "\"\n"
			body := "api." + typ + "{Key: \"" + pkg + "\"}.Key"
			if importsA {
				imports = "import (\n\t\"" + modA + "\"\n\t\"" + modAPI + "\"\n)\n"
				body += " + a.Name()"
			}
			return "package " + pkg + "\n\n" + imports + "\nfunc Name() string { return " + body + " }\n"
		}
		f := newReplayFixture(t, map[string]map[string]string{
			modAPI + "@v0.1.0": stubModule(modAPI, "api.go", oldAPI, nil),
			modAPI + "@v0.2.0": stubModule(modAPI, "api.go", newAPI, nil),
			modA + "@v1.0.0":   stubModule(modA, "a.go", aSrc, nil),
			modA + "@v1.1.0":   stubModule(modA, "a.go", aSrc, nil),
			modB + "@v0.1.0":   stubModule(modB, "b.go", userSrc("b", "KeyValue", false), map[string]string{modAPI: "v0.1.0"}),
			modB + "@v0.2.0":   stubModule(modB, "b.go", userSrc("b", "Attr", false), map[string]string{modAPI: "v0.2.0"}),
			modS + "@v0.1.0":   stubModule(modS, "s.go", userSrc("s", "KeyValue", true), map[string]string{modAPI: "v0.1.0", modA: "v1.0.0"}),
			modS + "@v0.2.0":   stubModule(modS, "s.go", userSrc("s", "Attr", true), map[string]string{modAPI: "v0.2.0", modA: "v1.1.0"}),
			modL + "@v0.1.0":   stubModule(modL, "l.go", userSrc("l", "KeyValue", false), map[string]string{modAPI: "v0.1.0"}),
		}, map[string]string{
			"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire (\n\t" + modA + " v1.0.0\n\t" + modB + " v0.1.0\n\t" +
				modS + " v0.1.0\n\t" + modL + " v0.1.0\n)\n",
			"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"" + modA + "\"\n\t\"" + modB + "\"\n\t\"" + modL + "\"\n\t\"" + modS + "\"\n)\n\n" +
				"func main() { fmt.Println(a.Name(), b.Name(), s.Name(), l.Name()) }\n",
		})
		sc := &fakeScanner{advisories: []fakeAdvisory{
			{module: modA, id: "GO-TEST-A", fixed: "v1.1.0", severity: "HIGH"},
			{module: modB, id: "GO-TEST-B", fixed: "v0.2.0", severity: "HIGH"},
		}}

		assertFixed(t, defectTrialPollution, func(t tb) {
			trace := &traceCapture{}
			ctx := logging.Into(t.Context(), slog.New(trace))
			result, err := RunLoop(ctx, f.tc, sc, f.dir, ModrootRequest{
				Modroot: ".",
				Seeds: []Candidate{
					{Module: modA, Version: "v1.1.0", FromCVE: true, VulnIDs: []string{"GO-TEST-A"}, Severity: "HIGH"},
					{Module: modB, Version: "v0.2.0", FromCVE: true, VulnIDs: []string{"GO-TEST-B"}, Severity: "HIGH"},
				},
				Baseline: map[string]string{modA: "v1.0.0", modB: "v0.1.0", modS: "v0.1.0", modL: "v0.1.0", modAPI: "v0.1.0"},
				Tags:     replayTags,
				Engine:   eng,
			}, Options{})
			require.NoError(t, err)
			logResult(t, result)

			trials := trace.trials()
			require.NotEmpty(t, trials, "trial trace records must be emitted")
			for i, pins := range trials {
				t.Logf("trial %d: %v", i, pins)
				if slices.Contains(pins, modS+"@v0.2.0") {
					assert.True(t, containsPinFor(pins, modB), "trial %d carries B's repair %s@v0.2.0 without B: %v", i, modS, pins)
				}
			}
			assert.Contains(t, result.FinalDeps, modA+"@v1.1.0", "the independent, compiling fix must be admitted")
			assert.Equal(t, "v1.1.0", result.Resolved[modA])
			assert.Equal(t, []string{"GO-TEST-B"}, residualIDs(result.Residuals, modB), "B cannot be fixed without breaking L")
			assert.Empty(t, f.compileFailuresWith(t, eng, result.FinalDeps))
		})
	})
}

// TestReplay_RedundantPinsRemoved (e, regression guard - passes today): a
// pin below the baseline-resolved version (x/net@v0.55.0 against v0.57.0)
// is removed, while a pin above baseline that still fixes a live advisory
// is kept.
func TestReplay_RedundantPinsRemoved(t *testing.T) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		netSrc := "package net\n\nfunc Name() string { return \"net\" }\n"
		grpcSrc := "package grpc\n\nimport \"" + modXNet + "\"\n\nfunc Version() string { return net.Name() }\n"
		f := newReplayFixture(t, map[string]map[string]string{
			modXNet + "@v0.55.0": stubModule(modXNet, "net.go", netSrc, nil),
			modXNet + "@v0.57.0": stubModule(modXNet, "net.go", netSrc, nil),
			modGRPC + "@v1.79.3": stubModule(modGRPC, "grpc.go", grpcSrc, map[string]string{modXNet: "v0.57.0"}),
			modGRPC + "@v1.83.2": stubModule(modGRPC, "grpc.go", grpcSrc, map[string]string{modXNet: "v0.57.0"}),
		}, map[string]string{
			"go.mod": "module example.com/app\n\ngo 1.21\n\nrequire (\n\t" + modGRPC + " v1.79.3\n\t" + modXNet + " v0.57.0\n)\n",
			"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"" + modXNet + "\"\n\t\"" + modGRPC + "\"\n)\n\n" +
				"func main() { fmt.Println(net.Name(), grpc.Version()) }\n",
		})
		sc := &fakeScanner{advisories: []fakeAdvisory{{module: modGRPC, id: advGRPC, fixed: "v1.83.2", severity: "HIGH"}}}

		result, err := RunLoop(t.Context(), f.tc, sc, f.dir, ModrootRequest{
			Modroot: ".",
			Seeds: []Candidate{
				{Module: modXNet, Version: "v0.55.0"}, // existing YAML pin, below upstream
				{Module: modGRPC, Version: "v1.83.2", FromCVE: true, VulnIDs: []string{advGRPC}, Severity: "HIGH"},
			},
			Baseline: map[string]string{modXNet: "v0.57.0", modGRPC: "v1.79.3"},
			Tags:     replayTags,
			Engine:   eng,
		}, Options{})
		require.NoError(t, err)
		logResult(t, result)

		assert.Equal(t, []string{modGRPC + "@v1.83.2"}, result.FinalDeps, "redundant x/net pin removed, needed grpc pin kept")
		assert.Equal(t, "v0.57.0", result.Resolved[modXNet], "never regressed below upstream")
		assert.Empty(t, result.Residuals)
		assert.True(t, slices.ContainsFunc(result.Dropped, func(d DroppedCandidate) bool { return d.Module == modXNet }),
			"the redundant pin is reported as dropped")
	})
}

// TestReplay_ImpliedPinRemovedBothEngines: b@v1.1.0 is implied by a@v1.1.0
// (whose go.mod requires it), so under either engine the final tidied go.mod
// is identical without the b entry: it is removed as redundant, naming a,
// and its advisory stays fixed. Applying the remaining entry alone still
// compiles.
//
// With `tidy: false` nothing tidies: omnibump sets a's version in place, so
// the b entry is the only thing raising b in go.mod and must stay; gobump's
// `go get a` writes the raise itself, so b is still redundant there.
func TestReplay_ImpliedPinRemovedBothEngines(t *testing.T) {
	for _, noTidy := range []bool{false, true} {
		t.Run(fmt.Sprintf("notidy=%v", noTidy), func(t *testing.T) { impliedPinReplay(t, noTidy) })
	}
}

func impliedPinReplay(t *testing.T, noTidy bool) {
	forEachEngine(t, func(t *testing.T, eng Engine) {
		src := func(pkg string) string {
			return "package " + pkg + "\n\nfunc Name() string { return \"" + pkg + "\" }\n"
		}
		f := newReplayFixture(t, map[string]map[string]string{
			"example.com/a@v1.0.0": stubModule("example.com/a", "a.go", src("a"), map[string]string{"example.com/b": "v1.0.0"}),
			"example.com/a@v1.1.0": stubModule("example.com/a", "a.go", src("a"), map[string]string{"example.com/b": "v1.1.0"}),
			"example.com/b@v1.0.0": stubModule("example.com/b", "b.go", src("b"), nil),
			"example.com/b@v1.1.0": stubModule("example.com/b", "b.go", src("b"), nil),
		}, map[string]string{
			"go.mod":  "module example.com/app\n\ngo 1.21\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n",
			"main.go": "package main\n\nimport (\n\t\"fmt\"\n\n\t\"example.com/a\"\n\t\"example.com/b\"\n)\n\nfunc main() { fmt.Println(a.Name(), b.Name()) }\n",
		})
		sc := &fakeScanner{advisories: []fakeAdvisory{
			{module: "example.com/a", id: "GO-A", fixed: "v1.1.0", severity: "HIGH"},
			{module: "example.com/b", id: "GO-B", fixed: "v1.1.0", severity: "LOW"},
		}}
		result, err := RunLoop(t.Context(), f.tc, sc, f.dir, ModrootRequest{
			Modroot: ".",
			Seeds: []Candidate{
				{Module: "example.com/a", Version: "v1.1.0", FromCVE: true, VulnIDs: []string{"GO-A"}, Severity: "HIGH"},
				{Module: "example.com/b", Version: "v1.1.0", FromCVE: true, VulnIDs: []string{"GO-B"}, Severity: "LOW"},
			},
			Baseline: map[string]string{"example.com/a": "v1.0.0", "example.com/b": "v1.0.0"},
			Engine:   eng,
			NoTidy:   noTidy,
		}, Options{})
		require.NoError(t, err)
		logResult(t, result)
		if noTidy && eng == EngineOmnibump {
			assert.ElementsMatch(t, []string{"example.com/a@v1.1.0", "example.com/b@v1.1.0"}, result.FinalDeps)
			assert.Empty(t, result.Dropped)
			return
		}
		assert.Equal(t, []string{"example.com/a@v1.1.0"}, result.FinalDeps)
		assert.Equal(t, "v1.1.0", result.Resolved["example.com/b"])
		assert.Empty(t, result.Residuals)
		require.Len(t, result.Dropped, 1)
		assert.True(t, result.Dropped[0].Redundant)
		assert.Contains(t, result.Dropped[0].Reason, "implied by example.com/a@v1.1.0")
		if !noTidy {
			assert.Empty(t, f.compileFailuresWith(t, eng, result.FinalDeps))
		}
	})
}
