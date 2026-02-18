package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type PyPIRegistry struct {
	client *http.Client
}

func NewPyPIRegistry() *PyPIRegistry {
	return &PyPIRegistry{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (r *PyPIRegistry) LookupSourceRepo(name string) (PackageInfo, error) {
	url := fmt.Sprintf("https://pypi.org/pypi/%s/json", name)
	resp, err := r.client.Get(url)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("pypi lookup: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PackageInfo{}, fmt.Errorf("pypi returned %d for %s", resp.StatusCode, name)
	}

	var pkg struct {
		Info struct {
			Version     string            `json:"version"`
			HomePage    string            `json:"home_page"`
			ProjectURLs map[string]string `json:"project_urls"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return PackageInfo{}, fmt.Errorf("decode pypi response: %w", err)
	}

	sourceRepo := resolveSourceURL(pkg.Info.ProjectURLs, pkg.Info.HomePage)
	return PackageInfo{
		Name:          name,
		SourceRepo:    sourceRepo,
		LatestVersion: pkg.Info.Version,
	}, nil
}

func resolveSourceURL(projectURLs map[string]string, homePage string) string {
	// Try well-known keys in project_urls first
	for _, key := range []string{"Source", "Source Code", "Repository", "GitHub", "Code"} {
		if url, ok := projectURLs[key]; ok && strings.Contains(url, "github.com") {
			return normalizeGitURL(url)
		}
	}
	// Fall back to homepage if it's a GitHub URL
	if strings.Contains(homePage, "github.com") {
		return normalizeGitURL(homePage)
	}
	// Return whatever we have
	for _, url := range projectURLs {
		if strings.Contains(url, "github.com") {
			return normalizeGitURL(url)
		}
	}
	return ""
}
