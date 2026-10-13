package gobump

import (
	"context"
	"fmt"
	"os"

	"github.com/isometry/choam/internal/goproxy"
	"github.com/isometry/choam/internal/goversion"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
)

// GoVersionFallbackStage is the Go-only best-effort go-version fallback:
// for Go modroots the simulation did not prove (--no-validate, a degraded
// simulation, or per-modroot skips) it derives RequiredGoVersion from the
// candidate deps' own go.mod files on the module proxy (see
// fallbackRequiredGoVersion). It runs before the applier, whose go-version
// edits (fastPathGoVersion) and the go-package pin floors (goPinFloors) read
// RequiredGoVersion.
type GoVersionFallbackStage struct {
	processor.BaseStage
	Analyzer *Analyzer

	// goProxyURL is the module proxy the best-effort go-version fallback
	// queries; tests point it at an httptest server.
	goProxyURL string

	// probeDisabled mirrors GOPROXY=off: the best-effort go-version fallback
	// probe is entirely skipped (it would just fail every fetch) and each
	// affected modroot gets one explanatory message instead.
	probeDisabled bool

	// goPrivate/goNoProxy are GOPRIVATE/GONOPROXY captured once at
	// construction (see internal/goproxy.IsPrivate) so the fallback probe
	// never sends a private module's name/version to a public proxy.
	goPrivate string
	goNoProxy string

	// goProxyIsPublic is true when goProxyURL is (or falls back to) the
	// public https://proxy.golang.org - either because GOPROXY named it
	// directly, or because GOPROXY's first entry was unusable ("direct",
	// "off", unset, or garbage) and the probe fell back to it. See
	// skipPrivateModule for why this changes which modules get skipped.
	goProxyIsPublic bool
}

func NewGoVersionFallbackStage(analyzer *Analyzer) *GoVersionFallbackStage {
	proxyURL, ok := goproxy.FirstURL(os.Getenv("GOPROXY"))
	if !ok {
		proxyURL = defaultGoProxyURL
	}
	return &GoVersionFallbackStage{
		BaseStage: processor.BaseStage{
			StageName:        "go_version_fallback",
			StageDescription: "Best-effort required Go version for modroots simulation did not prove",
		},
		Analyzer:        analyzer,
		goProxyURL:      proxyURL,
		probeDisabled:   goproxy.Disabled(os.Getenv("GOPROXY")),
		goPrivate:       os.Getenv("GOPRIVATE"),
		goNoProxy:       os.Getenv("GONOPROXY"),
		goProxyIsPublic: proxyURL == defaultGoProxyURL,
	}
}

// skipPrivateModule reports whether modulePath is private per the stage's
// captured GOPRIVATE/GONOPROXY - the skip func the best-effort go-version
// fallback probe uses to avoid leaking private module names/versions to a
// public proxy.
//
// When the probe queries the user's own configured proxy, Go's own
// GONOPROXY-precedence rule applies (a non-empty GONOPROXY governs
// exclusively; GOPRIVATE is only consulted as its default) - that precedence
// exists to let a private proxy see modules that are GOPRIVATE-only but not
// GONOPROXY-listed. But when goProxyIsPublic is true there is no private
// proxy in play: the probe is talking to the public proxy.golang.org
// regardless, so applying the same precedence would leak a module that
// matches GOPRIVATE but not a (possibly unrelated, non-empty) GONOPROXY.
// Skip on the UNION of GOPRIVATE and GONOPROXY instead, expressed by
// consulting goproxy.IsPrivate once per pattern list with the other left
// empty.
func (s *GoVersionFallbackStage) skipPrivateModule(modulePath string) bool {
	if s.goProxyIsPublic {
		return goproxy.IsPrivate(modulePath, s.goPrivate, "") || goproxy.IsPrivate(modulePath, "", s.goNoProxy)
	}
	return goproxy.IsPrivate(modulePath, s.goPrivate, s.goNoProxy)
}

// ShouldRun: the apply phase runs (bumpActionsPending) and at least one Go
// modroot needs the fallback (see needsGoVersionFallback) - exactly the
// modroots fallbackGoVersions acts on.
func (s *GoVersionFallbackStage) ShouldRun(_ context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
	}
	if !bumpActionsPending(gp) {
		return false, nil
	}
	for _, lang := range gp.VulnerabilityAnalysis.ByLanguage {
		if lang.Language != "go" {
			continue
		}
		for mi := range lang.ByModroot {
			if needsGoVersionFallback(&lang.ByModroot[mi]) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (s *GoVersionFallbackStage) Apply(ctx context.Context, p processor.Processor) error {
	gp, err := asBump(p)
	if err != nil {
		return err
	}
	return s.fallbackGoVersions(ctx, gp, gp.VulnerabilityAnalysis)
}

// needsGoVersionFallback reports whether a Go modroot's required Go version
// is still unknown and there is something to derive it from: not simulated
// (so not proven), no RequiredGoVersion yet, and desired deps or replaces.
func needsGoVersionFallback(m *ModrootAnalysis) bool {
	return !m.Simulated && m.RequiredGoVersion == "" &&
		(len(m.DesiredDeps) > 0 || len(m.DesiredReplaces) > 0)
}

// fallbackGoVersions populates RequiredGoVersion for go modroots the
// simulation didn't cover, from the best-effort proxy probe (see
// fallbackRequiredGoVersion), gated against the pristine baseline exactly
// like the simulation path. Fail-open throughout: any failure just leaves
// RequiredGoVersion empty (with a warning), never blocks the apply - except
// a cancellation, which is returned. When GOPROXY=off (probeDisabled), the
// probe is skipped entirely - it would only fail every fetch - and each
// affected modroot gets one message instead.
func (s *GoVersionFallbackStage) fallbackGoVersions(ctx context.Context, gp *Processor, analysis *VulnerabilityAnalysis) error {
	for li := range analysis.ByLanguage {
		lang := &analysis.ByLanguage[li]
		if lang.Language != "go" {
			continue
		}
		for mi := range lang.ByModroot {
			m := &lang.ByModroot[mi]
			if !needsGoVersionFallback(m) {
				continue
			}
			if s.probeDisabled {
				logging.From(ctx).Debug("go-version fallback: probe disabled (GOPROXY=off) - skipping", "modroot", m.Modroot)
				gp.AddMessage(fmt.Sprintf("modroot %s: GOPROXY=off - skipping best-effort Go version probe", m.Modroot))
				continue
			}
			required, unfetched, err := fallbackRequiredGoVersion(ctx, s.Analyzer.client(), s.goProxyURL, m, s.skipPrivateModule)
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if err == nil && unfetched > 0 {
				logging.From(ctx).Warn("best-effort Go version probe incomplete - the required Go version may be higher",
					"modroot", m.Modroot, "unfetched", unfetched)
				gp.AddMessage(fmt.Sprintf("modroot %s: best-effort Go version probe incomplete (%d candidate go.mod file(s) could not be fetched) - the required Go version may be higher", m.Modroot, unfetched))
			}
			if err != nil {
				logging.From(ctx).Warn("could not determine required Go version (best-effort probe failed)",
					"modroot", m.Modroot, "error", err)
				gp.AddMessage(fmt.Sprintf("modroot %s: could not determine required Go version (best-effort probe failed): %v", m.Modroot, err))
				continue
			}
			if required == "" || goversion.Compare(required, pristineGoBaseline(m)) <= 0 {
				continue
			}

			// The probed floor is unvalidated external input (a remote
			// go.mod's go directive): before it can become RequiredGoVersion
			// - which feeds both the go-version field and the go-package pin
			// floor - confirm it names a real Go release.
			valid, offlineErr := validateGoVersionFloor(ctx, s.Analyzer.releaseIndex(), goversion.Minor(required))
			if cerr := ctx.Err(); cerr != nil {
				return cerr
			}
			if offlineErr != nil {
				logging.From(ctx).Warn("could not validate required Go version against known releases (index unavailable) - proceeding",
					"modroot", m.Modroot, "version", required, "error", offlineErr)
				gp.AddMessage(fmt.Sprintf("modroot %s: could not validate required Go %s against known releases (index unavailable) - proceeding without validation: %v",
					m.Modroot, required, offlineErr))
			}
			if !valid {
				logging.From(ctx).Warn("candidate dependencies claim to require an unknown Go release - ignoring",
					"modroot", m.Modroot, "version", required)
				gp.AddMessage(fmt.Sprintf("modroot %s: candidate dependencies claim to require Go %s, which is not a known Go release — ignoring (check the dependency's go.mod)",
					m.Modroot, required))
				continue
			}

			m.RequiredGoVersion = required
			gp.AddMessage(fmt.Sprintf("modroot %s: candidate dependencies require Go %s (module baseline %s) - best-effort (direct candidates only); run with simulation for a proven result",
				m.Modroot, required, baselineWord(pristineGoBaseline(m))))
		}
	}
	return nil
}
