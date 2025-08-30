package types

// VersionFilterFunc is a function that determines if a version passes all filtering criteria
// Returns true if the version is valid and should be used
type VersionFilterFunc func(version string) bool
