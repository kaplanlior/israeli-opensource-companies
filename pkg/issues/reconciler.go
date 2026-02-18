package issues

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/go-github/v60/github"
	"github.com/unreleased-security-fix-scanner/pkg/scanner"
)

const (
	LabelUnreleasedFix = "unreleased-fix"
	LabelFixReleased   = "fix-released"
)

type Reconciler struct {
	client *github.Client
	owner  string
	repo   string
	ctx    context.Context
}

func NewReconciler(client *github.Client, owner, repo string) *Reconciler {
	return &Reconciler{
		client: client,
		owner:  owner,
		repo:   repo,
		ctx:    context.Background(),
	}
}

// Reconcile compares the current set of findings against existing issues and
// creates, updates, or closes issues as needed.
func (r *Reconciler) Reconcile(findings []scanner.Finding) error {
	existing, err := r.listTrackedIssues()
	if err != nil {
		return fmt.Errorf("list tracked issues: %w", err)
	}

	findingKeys := make(map[string]bool)

	for _, f := range findings {
		key := issueKey(f.Advisory.ID, f.Package.Name)
		findingKeys[key] = true

		if issue, ok := existing[key]; ok {
			if f.FixReleased {
				if err := r.markReleased(issue, f); err != nil {
					return fmt.Errorf("mark released %s: %w", key, err)
				}
			}
			// Already tracked and still unreleased → no-op
		} else {
			if err := r.createIssue(f); err != nil {
				return fmt.Errorf("create issue for %s: %w", key, err)
			}
		}
	}

	// Close stale issues (dependency removed or advisory withdrawn)
	for key, issue := range existing {
		if !findingKeys[key] {
			if err := r.closeStaleIssue(issue); err != nil {
				return fmt.Errorf("close stale issue %d: %w", issue.GetNumber(), err)
			}
		}
	}

	return nil
}

func (r *Reconciler) listTrackedIssues() (map[string]*github.Issue, error) {
	issues := make(map[string]*github.Issue)
	opts := &github.IssueListByRepoOptions{
		Labels:      []string{LabelUnreleasedFix},
		State:       "open",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		page, resp, err := r.client.Issues.ListByRepo(r.ctx, r.owner, r.repo, opts)
		if err != nil {
			return nil, err
		}
		for _, issue := range page {
			key := extractIssueKey(issue)
			if key != "" {
				issues[key] = issue
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}
	return issues, nil
}

func (r *Reconciler) createIssue(f scanner.Finding) error {
	key := issueKey(f.Advisory.ID, f.Package.Name)
	title := fmt.Sprintf("[UNRELEASED FIX] %s — %s (%s)", f.Advisory.ID, f.Package.Name, f.Package.Ecosystem)
	body := RenderNewIssueBody(f)

	labels := []string{LabelUnreleasedFix, key}

	_, _, err := r.client.Issues.Create(r.ctx, r.owner, r.repo, &github.IssueRequest{
		Title:  &title,
		Body:   &body,
		Labels: &labels,
	})
	return err
}

func (r *Reconciler) markReleased(issue *github.Issue, f scanner.Finding) error {
	comment := RenderFixReleasedComment(f)
	_, _, err := r.client.Issues.CreateComment(r.ctx, r.owner, r.repo, issue.GetNumber(), &github.IssueComment{
		Body: &comment,
	})
	if err != nil {
		return err
	}

	newTitle := strings.Replace(issue.GetTitle(), "[UNRELEASED FIX]", "[RELEASED]", 1)
	labels := []string{LabelUnreleasedFix, LabelFixReleased, issueKeyFromIssue(issue)}
	_, _, err = r.client.Issues.Edit(r.ctx, r.owner, r.repo, issue.GetNumber(), &github.IssueRequest{
		Title:  &newTitle,
		Labels: &labels,
	})
	return err
}

func (r *Reconciler) closeStaleIssue(issue *github.Issue) error {
	comment := "This issue is being closed because the dependency is no longer detected or the advisory has been withdrawn."
	_, _, err := r.client.Issues.CreateComment(r.ctx, r.owner, r.repo, issue.GetNumber(), &github.IssueComment{
		Body: &comment,
	})
	if err != nil {
		return err
	}

	closed := "closed"
	_, _, err = r.client.Issues.Edit(r.ctx, r.owner, r.repo, issue.GetNumber(), &github.IssueRequest{
		State: &closed,
	})
	return err
}

// issueKey generates a deterministic label used to match issues to findings.
func issueKey(advisoryID, packageName string) string {
	return fmt.Sprintf("unreleased-fix:%s:%s", advisoryID, packageName)
}

// extractIssueKey finds the deterministic tracking label from an issue's labels.
func extractIssueKey(issue *github.Issue) string {
	for _, label := range issue.Labels {
		name := label.GetName()
		if strings.HasPrefix(name, "unreleased-fix:") && strings.Count(name, ":") >= 2 {
			return name
		}
	}
	return ""
}

func issueKeyFromIssue(issue *github.Issue) string {
	return extractIssueKey(issue)
}
