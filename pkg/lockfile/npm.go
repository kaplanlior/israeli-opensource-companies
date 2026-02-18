package lockfile

import (
	"encoding/json"
	"os"
)

type NPMParser struct{}

func (p *NPMParser) Ecosystem() string { return "npm" }

func (p *NPMParser) Parse(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockfile struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lockfile); err != nil {
		return nil, err
	}

	seen := make(map[string]bool)
	var deps []Dependency

	// npm v3+ lockfile format (packages field)
	for key, pkg := range lockfile.Packages {
		if key == "" {
			continue // root package
		}
		name := extractNPMPackageName(key)
		if seen[name+"@"+pkg.Version] {
			continue
		}
		seen[name+"@"+pkg.Version] = true
		deps = append(deps, Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "npm",
		})
	}

	// npm v1/v2 lockfile format (dependencies field)
	for name, dep := range lockfile.Dependencies {
		if seen[name+"@"+dep.Version] {
			continue
		}
		seen[name+"@"+dep.Version] = true
		deps = append(deps, Dependency{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: "npm",
		})
	}

	return deps, nil
}

func extractNPMPackageName(key string) string {
	// Keys in packages are like "node_modules/@scope/pkg"
	const prefix = "node_modules/"
	for {
		idx := indexOf(key, prefix)
		if idx == -1 {
			return key
		}
		key = key[idx+len(prefix):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
