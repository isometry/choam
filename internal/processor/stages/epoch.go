package stages

import (
	"context"
	"fmt"

	melangeConfig "github.com/isometry/choam/internal/config"
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
	return p.GetCurrentEpoch() + 1
}

func (b *BumpOnSecurityFixStrategy) GetReason() string {
	return "security fixes applied"
}

// BumpOnFileChangeStrategy bumps epoch only when actual file changes are made
type BumpOnFileChangeStrategy struct {
	CheckFunc func(p processor.Processor) bool
}

func (b *BumpOnFileChangeStrategy) ShouldUpdateEpoch(p processor.Processor) bool {
	if b.CheckFunc != nil {
		return b.CheckFunc(p)
	}
	// Default: check if actual file changes were made
	return p.HasFileChanges()
}

func (b *BumpOnFileChangeStrategy) CalculateNewEpoch(p processor.Processor) int64 {
	return p.GetCurrentEpoch() + 1
}

func (b *BumpOnFileChangeStrategy) GetReason() string {
	return "file changes applied"
}

// CompositeEpochStrategy combines multiple strategies with priority order
type CompositeEpochStrategy struct {
	Strategies []EpochStrategy
}

func (c *CompositeEpochStrategy) ShouldUpdateEpoch(p processor.Processor) bool {
	for _, strategy := range c.Strategies {
		if strategy.ShouldUpdateEpoch(p) {
			return true
		}
	}
	return false
}

func (c *CompositeEpochStrategy) CalculateNewEpoch(p processor.Processor) int64 {
	// Return the epoch from the first strategy that wants to update
	for _, strategy := range c.Strategies {
		if strategy.ShouldUpdateEpoch(p) {
			return strategy.CalculateNewEpoch(p)
		}
	}
	return p.GetCurrentEpoch()
}

func (c *CompositeEpochStrategy) GetReason() string {
	// Note: This method doesn't have access to processor, so it returns a generic reason.
	// In practice, GetReason is called after ShouldUpdateEpoch has already determined
	// which strategy should be used.
	return "composite strategy triggered"
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
	logger := p.GetLogger().With("stage", e.Name())

	newEpoch := e.Strategy.CalculateNewEpoch(p)
	oldEpoch := p.GetCurrentEpoch()
	reason := e.Strategy.GetReason()

	if p.GetOptions().DryRun {
		logger.Info("Dry run - would update epoch",
			"old", oldEpoch, "new", newEpoch, "reason", reason)
		p.SetEpochUpdate(oldEpoch, newEpoch)
		p.AddMessage(fmt.Sprintf("would update epoch: %d -> %d (%s)",
			oldEpoch, newEpoch, reason))
		return nil
	}

	// Actually update the YAML, with an inline intent comment when the
	// strategy can compose one.
	var comment string
	if commenter, ok := e.Strategy.(epochCommenter); ok {
		comment = commenter.EpochComment(p)
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
