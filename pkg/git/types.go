package git

// TagInfo represents information about a Git tag
type TagInfo struct {
	Name       string
	SHA        string
	Message    string
	Tagger     string
	TaggerDate string
}

// Repository represents a Git repository
type Repository struct {
	URL    string
	Branch string
}

// CommitInfo represents information about a Git commit
type CommitInfo struct {
	SHA        string
	Repository string
	Message    string
	Author     string
	Date       string
}
