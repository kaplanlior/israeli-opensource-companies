package lockfile

import (
	"bufio"
	"os"
	"strings"
)

type PyPIParser struct{}

func (p *PyPIParser) Ecosystem() string { return "PyPI" }

func (p *PyPIParser) Parse(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []Dependency
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		name, version := parseRequirement(line)
		if name == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "PyPI",
		})
	}
	return deps, scanner.Err()
}

func parseRequirement(line string) (name, version string) {
	// Remove environment markers (e.g., "; python_version >= '3.6'")
	if idx := strings.Index(line, ";"); idx >= 0 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)

	for _, op := range []string{"==", ">=", "<=", "~=", "!=", ">", "<"} {
		if idx := strings.Index(line, op); idx >= 0 {
			name = strings.TrimSpace(line[:idx])
			version = strings.TrimSpace(line[idx+len(op):])
			// Strip trailing version constraints (e.g., ",<3.0")
			if commaIdx := strings.Index(version, ","); commaIdx >= 0 {
				version = version[:commaIdx]
			}
			return name, version
		}
	}

	return strings.TrimSpace(line), ""
}
