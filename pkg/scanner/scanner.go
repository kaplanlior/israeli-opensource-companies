package scanner

import (
	"fmt"
	"strings"

	"github.com/unreleased-security-fix-scanner/pkg/advisory"
	"github.com/unreleased-security-fix-scanner/pkg/config"
	"github.com/unreleased-security-fix-scanner/pkg/lockfile"
	"github.com/unreleased-security-fix-scanner/pkg/registry"
	"github.com/unreleased-security-fix-scanner/pkg/vcs"
)

type Finding struct {
	Advisory    advisory.Advisory
	Package     lockfile.Dependency
	FixCommit   string
	FixReleased bool
	FixRelease  string
	SourceRepo  string
}

type Scanner struct {
	advisorySource advisory.Source
	repoClient     vcs.RepoClient
	config         *config.Config
}

func New(advisorySource advisory.Source, repoClient vcs.RepoClient, cfg *config.Config) *Scanner {
	return &Scanner{
		advisorySource: advisorySource,
		repoClient:     repoClient,
		config:         cfg,
	}
}

func (s *Scanner) Scan(deps []lockfile.Dependency) ([]Finding, error) {
	queries := make([]advisory.PackageQuery, 0, len(deps))
	for _, d := range deps {
		queries = append(queries, advisory.PackageQuery{
			Ecosystem: d.Ecosystem,
			Name:      d.Name,
			Version:   d.Version,
		})
	}

	advisoriesByPkg, err := s.advisorySource.QueryBatch(queries)
	if err != nil {
		return nil, fmt.Errorf("query advisories: %w", err)
	}

	var findings []Finding
	for _, dep := range deps {
		key := dep.Ecosystem + ":" + dep.Name
		advs, ok := advisoriesByPkg[key]
		if !ok || len(advs) == 0 {
			continue
		}

		for _, adv := range advs {
			if s.isIgnored(adv, dep) {
				continue
			}
			if !meetsMinSeverity(adv.Severity, s.config.Severity) {
				continue
			}

			finding := Finding{
				Advisory:  adv,
				Package:   dep,
				FixCommit: adv.FixCommit,
			}

			reg := registry.NewRegistry(dep.Ecosystem)
			if reg != nil {
				info, err := reg.LookupSourceRepo(dep.Name)
				if err == nil {
					finding.SourceRepo = info.SourceRepo
				}
			}

			if finding.FixCommit != "" && finding.SourceRepo != "" && strings.Contains(finding.SourceRepo, "github.com") {
				released, releaseName, err := s.checkFixReleased(finding.SourceRepo, finding.FixCommit)
				if err == nil {
					finding.FixReleased = released
					finding.FixRelease = releaseName
				}
			}

			if !finding.FixReleased {
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func (s *Scanner) checkFixReleased(sourceRepo, commitSHA string) (bool, string, error) {
	owner, repo, err := vcs.ParseGitHubRepo(sourceRepo)
	if err != nil {
		return false, "", err
	}

	tags, err := s.repoClient.ListTags(owner, repo)
	if err != nil {
		return false, "", err
	}

	for _, tag := range tags {
		isAnc, err := s.repoClient.IsAncestor(owner, repo, tag.Name, commitSHA)
		if err != nil {
			continue
		}
		if isAnc {
			return true, tag.Name, nil
		}
	}

	return false, "", nil
}

func (s *Scanner) isIgnored(adv advisory.Advisory, dep lockfile.Dependency) bool {
	for _, id := range s.config.Ignore.Advisories {
		if id == adv.ID {
			return true
		}
		for _, alias := range adv.Aliases {
			if id == alias {
				return true
			}
		}
	}
	for _, pkg := range s.config.Ignore.Packages {
		if pkg == dep.Name {
			return true
		}
	}
	return false
}

var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

func meetsMinSeverity(severity, minimum string) bool {
	if severity == "" {
		return true // unknown severity passes through
	}
	return severityRank[strings.ToLower(severity)] >= severityRank[strings.ToLower(minimum)]
}
