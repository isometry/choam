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
	IsManual       bool     `json:"is_manual"`
	Error          string   `json:"error,omitempty"`
}
