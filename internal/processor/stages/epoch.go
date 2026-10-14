package stages

import (
	"context"
	"fmt"

	melangeConfig "github.com/isometry/choam/internal/config"
	"github.com/isometry/choam/internal/logging"
	"github.com/isometry/choam/internal/processor"
)

// EpochStrategy defines how epoch should be handled
type EpochStrategy interface {
	ShouldUpdateEpoch(p processor.Processor) bool
	CalculateNewEpoch(p processor.Processor) int64
	GetReason() string
}

// ResetOnVersionChangeStrategy resets epoch to 0 when version changes
type ResetOnVersionChangeStrategy struct{}

func (r *ResetOnVersionChangeStrategy) ShouldUpdateEpoch(p processor.Processor) bool {
	return p.IsVersionChanged()
}

func (r *ResetOnVersionChangeStrategy) CalculateNewEpoch(p processor.Processor) int64 {
	return 0
}

func (r *ResetOnVersionChangeStrategy) GetReason() string {
	return "version changed"
}

// epochCommenter is an optional extension of EpochStrategy: a strategy that
// can state WHY the epoch changes gets its text written as an inline comment
// on the epoch line. GetReason cannot serve this purpose - it is a constant
// per strategy, not derived from what actually happened.
type epochCommenter interface {
	EpochComment(p processor.Processor) string
}

// BumpOnSecurityFixStrategy bumps epoch by 1 for security fixes
type BumpOnSecurityFixStrategy struct {
	CheckFunc func(p processor.Processor) bool
	// CommentFunc, when set, composes the inline intent comment written on
	// the epoch line (e.g. "updated bumps; fixes: ..."). Empty result or nil
	// func leaves the epoch line comment-free.
	CommentFunc func(p processor.Processor) string
	// EpochFunc, when set, computes the new epoch; nil means current + 1.
	EpochFunc func(p processor.Processor) int64
}

// EpochComment implements epochCommenter.
func (b *BumpOnSecurityFixStrategy) EpochComment(p processor.Processor) string {
	if b.CommentFunc == nil {
		return ""
	}
	return b.CommentFunc(p)
}

func (b *BumpOnSecurityFixStrategy) ShouldUpdateEpoch(p processor.Processor) bool {
	if b.CheckFunc != nil {
		return b.CheckFunc(p)
	}
	// Default: check if there are security-related changes
	for _, change := range p.GetChanges() {
		if change.Type == "security" {
			return true
		}
	}
	return false
}

func (b *BumpOnSecurityFixStrategy) CalculateNewEpoch(p processor.Processor) int64 {
	if b.EpochFunc != nil {
		return b.EpochFunc(p)
	}
	return p.GetCurrentEpoch() + 1
}

func (b *BumpOnSecurityFixStrategy) GetReason() string {
	return "security fixes applied"
}

// EpochStage handles epoch updates using a configurable strategy
type EpochStage struct {
	processor.BaseStage
	Strategy EpochStrategy
}

// NewEpochStage creates a new epoch stage with the given strategy
func NewEpochStage(strategy EpochStrategy) *EpochStage {
	return &EpochStage{
		BaseStage: processor.BaseStage{
			StageName:        "epoch",
			StageDescription: "Handle epoch updates based on configured strategy",
		},
		Strategy: strategy,
	}
}

func (e *EpochStage) ShouldRun(ctx context.Context, p processor.Processor) (bool, error) {
	return e.Strategy.ShouldUpdateEpoch(p), nil
}

func (e *EpochStage) Apply(ctx context.Context, p processor.Processor) error {
	logger := logging.From(ctx)

	newEpoch := e.Strategy.CalculateNewEpoch(p)
	oldEpoch := p.GetCurrentEpoch()

	// Inline intent comment when the strategy can compose one; it is also the
	// reason shown in logs and messages (it states what actually happened,
	// unlike the per-strategy constant GetReason).
	var comment string
	if commenter, ok := e.Strategy.(epochCommenter); ok {
		comment = commenter.EpochComment(p)
	}
	reason := comment
	if reason == "" {
		reason = e.Strategy.GetReason()
	}

	if p.GetOptions().DryRun {
		logger.Info("Dry run - would update epoch",
			"old", oldEpoch, "new", newEpoch, "reason", reason)
		p.SetEpochUpdate(oldEpoch, newEpoch)
		p.AddMessage(fmt.Sprintf("would update epoch: %d -> %d (%s)", oldEpoch, newEpoch, reason))
		return nil
	}

	loader := melangeConfig.NewLoader()
	updatedYAML, err := loader.SetEpochWithComment(p.GetCurrentYAML(), newEpoch, comment)
	if err != nil {
		return fmt.Errorf("setting epoch: %w", err)
	}

	p.SetCurrentYAML(updatedYAML)
	p.SetEpochUpdate(oldEpoch, newEpoch)
	p.AddMessage(fmt.Sprintf("epoch updated: %d -> %d (%s)",
		oldEpoch, newEpoch, reason))

	logger.Info("Epoch updated", "old", oldEpoch, "new", newEpoch, "reason", reason)
	return nil
}
