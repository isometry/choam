package updater

// UpdateResult represents the result of an update check (used by CLI)
type UpdateResult struct {
	PackageName    string `json:"package_name" yaml:"package_name"`
	FilePath       string `json:"file_path" yaml:"file_path"`
	CurrentVersion string `json:"current_version" yaml:"current_version"`
	LatestVersion  string `json:"latest_version" yaml:"latest_version"`
	HasUpdate      bool   `json:"has_update" yaml:"has_update"`
	UpdateSource   string `json:"update_source" yaml:"update_source"`
	IsManual       bool   `json:"is_manual" yaml:"is_manual"`
	Error          string `json:"error,omitempty" yaml:"error,omitempty"`
}

// ApplyResult represents the result of an update application (used by CLI)
type ApplyResult struct {
	PackageName    string   `json:"package_name" yaml:"package_name"`
	FilePath       string   `json:"file_path" yaml:"file_path"`
	OldVersion     string   `json:"old_version" yaml:"old_version"`
	NewVersion     string   `json:"new_version" yaml:"new_version"`
	OldEpoch       int64    `json:"old_epoch" yaml:"old_epoch"`
	NewEpoch       int64    `json:"new_epoch" yaml:"new_epoch"`
	UpdatesApplied []string `json:"updates_applied" yaml:"updates_applied"`
	SharedUpdates  []string `json:"shared_updates,omitempty" yaml:"shared_updates,omitempty"`
	BackupCreated  string   `json:"backup_created,omitempty" yaml:"backup_created,omitempty"`
	FileWasWritten bool     `json:"file_was_written" yaml:"file_was_written"`
	IsManual       bool     `json:"is_manual" yaml:"is_manual"`
	Error          string   `json:"error,omitempty" yaml:"error,omitempty"`
}

// PipelineChange represents a modification made to a pipeline
type PipelineChange struct {
	Type        string `json:"type" yaml:"type"`               // "insert", "update", "remove"
	Index       int    `json:"index" yaml:"index"`             // pipeline index
	Field       string `json:"field" yaml:"field"`             // specific field changed
	OldValue    string `json:"old_value" yaml:"old_value"`     // previous value
	NewValue    string `json:"new_value" yaml:"new_value"`     // new value
	Description string `json:"description" yaml:"description"` // human-readable description
	Reason      string `json:"reason" yaml:"reason"`           // why the change was made
}

// ProcessorOptions configures processor behavior
type ProcessorOptions struct {
	DryRun        bool   `json:"dry_run" yaml:"dry_run"`
	Force         bool   `json:"force" yaml:"force"`
	SharedUpdates bool   `json:"shared_updates" yaml:"shared_updates"`
	BackupSuffix  string `json:"backup_suffix" yaml:"backup_suffix"`
	TempDir       string `json:"temp_dir" yaml:"temp_dir"`
}
