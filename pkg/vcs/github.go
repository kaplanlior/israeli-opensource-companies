package vcs

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v60/github"
)

type GitHubClient struct {
	client *github.Client
	ctx    context.Context
}

func NewGitHubClient(client *github.Client) *GitHubClient {
	return &GitHubClient{
		client: client,
		ctx:    context.Background(),
	}
}

func (g *GitHubClient) ListTags(owner, repo string) ([]Tag, error) {
	var allTags []Tag
	opts := &github.ListOptions{PerPage: 100}

	for {
		tags, resp, err := g.client.Repositories.ListTags(g.ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("list tags for %s/%s: %w", owner, repo, err)
		}
		for _, t := range tags {
			allTags = append(allTags, Tag{
				Name:   t.GetName(),
				Commit: t.GetCommit().GetSHA(),
			})
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return allTags, nil
}

func (g *GitHubClient) IsAncestor(owner, repo, tag, commitSHA string) (bool, error) {
	comparison, _, err := g.client.Repositories.CompareCommits(g.ctx, owner, repo, tag, commitSHA, nil)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return false, nil
		}
		return false, fmt.Errorf("compare %s...%s in %s/%s: %w", tag, commitSHA, owner, repo, err)
	}

	// If the commit is "behind" the tag or "identical", the fix is included in the tag.
	// The compare API returns status relative to base..head:
	//   - "behind" means head is behind base (commit is ancestor of tag)
	//   - "identical" means they point to the same commit
	status := comparison.GetStatus()
	return status == "behind" || status == "identical", nil
}

func (g *GitHubClient) GetLatestRelease(owner, repo string) (string, error) {
	release, _, err := g.client.Repositories.GetLatestRelease(g.ctx, owner, repo)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			return "", nil
		}
		return "", fmt.Errorf("get latest release for %s/%s: %w", owner, repo, err)
	}
	return release.GetTagName(), nil
}

func ParseGitHubRepo(repoURL string) (owner, repo string, err error) {
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")
	repoURL = strings.TrimPrefix(repoURL, "github.com/")
	repoURL = strings.TrimSuffix(repoURL, ".git")
	repoURL = strings.TrimSuffix(repoURL, "/")

	parts := strings.SplitN(repoURL, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("cannot parse GitHub repo from %q", repoURL)
	}
	return parts[0], parts[1], nil
}
