package vcs

type Tag struct {
	Name   string
	Commit string
}

type RepoClient interface {
	// ListTags returns all tags for the given repository, newest first.
	ListTags(owner, repo string) ([]Tag, error)

	// IsAncestor checks whether commitSHA is an ancestor of the given tag.
	// Returns true if the commit is reachable from the tag (i.e., included in that release).
	IsAncestor(owner, repo, tag, commitSHA string) (bool, error)

	// GetLatestRelease returns the latest release tag name, or empty string if none.
	GetLatestRelease(owner, repo string) (string, error)
}
