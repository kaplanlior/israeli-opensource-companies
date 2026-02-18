package advisory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const osvBaseURL = "https://api.osv.dev/v1"

type OSVClient struct {
	httpClient *http.Client
}

func NewOSVClient() *OSVClient {
	return &OSVClient{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *OSVClient) QueryPackage(ecosystem, name, version string) ([]Advisory, error) {
	reqBody := osvQuery{
		Package: osvPackage{
			Name:      name,
			Ecosystem: ecosystem,
		},
		Version: version,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal osv query: %w", err)
	}

	resp, err := c.httpClient.Post(osvBaseURL+"/query", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv query returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result osvResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	return convertOSVVulns(result.Vulns), nil
}

func (c *OSVClient) QueryBatch(queries []PackageQuery) (map[string][]Advisory, error) {
	var osvQueries []osvBatchEntry
	for _, q := range queries {
		osvQueries = append(osvQueries, osvBatchEntry{
			Package: osvPackage{
				Name:      q.Name,
				Ecosystem: q.Ecosystem,
			},
			Version: q.Version,
		})
	}

	body, err := json.Marshal(osvBatchRequest{Queries: osvQueries})
	if err != nil {
		return nil, fmt.Errorf("marshal osv batch query: %w", err)
	}

	resp, err := c.httpClient.Post(osvBaseURL+"/querybatch", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv batch query: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv batch query returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode osv batch response: %w", err)
	}

	advisories := make(map[string][]Advisory)
	for i, entry := range result.Results {
		if i >= len(queries) {
			break
		}
		key := queries[i].Ecosystem + ":" + queries[i].Name
		advisories[key] = convertOSVVulns(entry.Vulns)
	}
	return advisories, nil
}

func convertOSVVulns(vulns []osvVuln) []Advisory {
	var advisories []Advisory
	for _, v := range vulns {
		a := Advisory{
			ID:      v.ID,
			Aliases: v.Aliases,
			Summary: v.Summary,
			Details: v.Details,
		}

		for _, ref := range v.References {
			a.References = append(a.References, ref.URL)
		}

		if len(v.Severity) > 0 {
			a.Severity = normalizeSeverity(v.Severity[0].Score)
		}

		for _, affected := range v.Affected {
			for _, r := range affected.Ranges {
				if r.Type == "GIT" {
					for _, event := range r.Events {
						if event.Fixed != "" {
							a.FixCommit = event.Fixed
						}
					}
				}
				if r.Type == "ECOSYSTEM" {
					for _, event := range r.Events {
						if event.Fixed != "" {
							a.FixedIn = event.Fixed
						}
					}
				}
			}
		}

		if v.Published != "" {
			a.Published, _ = time.Parse(time.RFC3339, v.Published)
		}
		if v.Modified != "" {
			a.Modified, _ = time.Parse(time.RFC3339, v.Modified)
		}

		advisories = append(advisories, a)
	}
	return advisories
}

func normalizeSeverity(cvssScore string) string {
	// CVSS vector strings contain the score; for simplicity, extract from
	// database_specific or use the vector prefix. Full CVSS parsing is a
	// future enhancement.
	cvssScore = strings.ToUpper(cvssScore)
	if strings.Contains(cvssScore, "CRITICAL") {
		return "critical"
	}
	if strings.Contains(cvssScore, "HIGH") {
		return "high"
	}
	if strings.Contains(cvssScore, "MEDIUM") {
		return "medium"
	}
	return "low"
}

// OSV API request/response types

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchRequest struct {
	Queries []osvBatchEntry `json:"queries"`
}

type osvBatchEntry struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvBatchResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string       `json:"id"`
	Aliases   []string     `json:"aliases"`
	Summary   string       `json:"summary"`
	Details   string       `json:"details"`
	Severity  []osvSeverity `json:"severity"`
	Published string       `json:"published"`
	Modified  string       `json:"modified"`
	Affected  []osvAffected `json:"affected"`
	References []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package osvAffectedPkg `json:"package"`
	Ranges  []osvRange     `json:"ranges"`
}

type osvAffectedPkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}
