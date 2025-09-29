package updater

// UpdateResult represents the result of an update check (used by CLI)
type UpdateResult struct {
	PackageName    string `json:"package_name"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	HasUpdate      bool   `json:"has_update"`
	UpdateSource   string `json:"update_source"`
	IsManual       bool   `json:"is_manual"`
	Error          string `json:"error,omitempty"`
}

// ApplyResult represents the result of an update application (used by CLI)
type ApplyResult struct {
	PackageName    string   `json:"package_name"`
	FilePath       string   `json:"file_path"`
	OldVersion     string   `json:"old_version"`
	NewVersion     string   `json:"new_version"`
	OldEpoch       int64    `json:"old_epoch"`
	NewEpoch       int64    `json:"new_epoch"`
	UpdatesApplied []string `json:"updates_applied"`
	SharedUpdates  []string `json:"shared_updates,omitempty"`
	BackupCreated  string   `json:"backup_created,omitempty"`
	FileWasWritten bool     `json:"file_was_written"`
	IsManual       bool     `json:"is_manual"`
	Error          string   `json:"error,omitempty"`
}

// PipelineChange represents a modification made to a pipeline
type PipelineChange struct {
	Type        string `json:"type"`        // "insert", "update", "remove"
	Index       int    `json:"index"`       // pipeline index
	Field       string `json:"field"`       // specific field changed
	OldValue    string `json:"old_value"`   // previous value
	NewValue    string `json:"new_value"`   // new value
	Description string `json:"description"` // human-readable description
	Reason      string `json:"reason"`      // why the change was made
}

// ProcessorOptions configures processor behavior
type ProcessorOptions struct {
	DryRun        bool   `json:"dry_run"`
	Force         bool   `json:"force"`
	SharedUpdates bool   `json:"shared_updates"`
	BackupSuffix  string `json:"backup_suffix"`
	TempDir       string `json:"temp_dir"`
}
