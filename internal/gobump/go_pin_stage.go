package gobump

import (
	"context"
	"fmt"

	"github.com/isometry/choam/internal/processor"
)

// GoPackagePinStage is the Go-only go-package pin reconciliation: it raises
// too-old go-package toolchain pins on go/build|go/install steps to the
// per-modroot Go floors (see reconcileGoPackagePins and goPinFloors). It runs
// after the applier - it edits the YAML the applier rewrote, and its floors
// include the RequiredGoVersion the fallback/simulation recorded - and
// before StdlibStage, which reads the RaisedPinMinors it records.
type GoPackagePinStage struct {
	processor.BaseStage
	Analyzer *Analyzer
}

func NewGoPackagePinStage(analyzer *Analyzer) *GoPackagePinStage {
	return &GoPackagePinStage{
		BaseStage: processor.BaseStage{
			StageName:        "go_package_pins",
			StageDescription: "Raise too-old go-package toolchain pins",
		},
		Analyzer: analyzer,
	}
}

// goPackagePinsPending reports whether the pin stage will act on this
// package: the apply phase ran (bumpActionsPending) and the analysis has Go
// modroots, i.e. pin floors to reconcile against.
func goPackagePinsPending(gp *Processor) bool {
	return bumpActionsPending(gp) && len(goPinFloors(gp.VulnerabilityAnalysis)) > 0
}

func (s *GoPackagePinStage) ShouldRun(_ context.Context, p processor.Processor) (bool, error) {
	gp, err := asBump(p)
	if err != nil {
		return false, err
	}
	return goPackagePinsPending(gp), nil
}

// Apply reconciles the pins.
func (s *GoPackagePinStage) Apply(ctx context.Context, p processor.Processor) error {
	gp, err := asBump(p)
	if err != nil {
		return err
	}
	if err := s.reconcileGoPackagePins(ctx, gp, goPinFloors(gp.VulnerabilityAnalysis)); err != nil {
		return fmt.Errorf("reconciling go-package pins: %w", err)
	}
	return nil
}
