package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type NPMRegistry struct {
	client *http.Client
}

func NewNPMRegistry() *NPMRegistry {
	return &NPMRegistry{
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (r *NPMRegistry) LookupSourceRepo(name string) (PackageInfo, error) {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	resp, err := r.client.Get(url)
	if err != nil {
		return PackageInfo{}, fmt.Errorf("npm registry lookup: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return PackageInfo{}, fmt.Errorf("npm registry returned %d for %s", resp.StatusCode, name)
	}

	var pkg struct {
		Repository struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"repository"`
		DistTags struct {
			Latest string `json:"latest"`
		} `json:"dist-tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return PackageInfo{}, fmt.Errorf("decode npm response: %w", err)
	}

	return PackageInfo{
		Name:          name,
		SourceRepo:    normalizeGitURL(pkg.Repository.URL),
		LatestVersion: pkg.DistTags.Latest,
	}, nil
}

func normalizeGitURL(raw string) string {
	raw = strings.TrimPrefix(raw, "git+")
	raw = strings.TrimPrefix(raw, "git://")
	raw = strings.TrimPrefix(raw, "ssh://git@")
	raw = strings.TrimSuffix(raw, ".git")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "http://")
	return raw
}
