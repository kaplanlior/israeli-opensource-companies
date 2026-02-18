package lockfile

import (
	"bufio"
	"os"
	"strings"
)

type GoModParser struct{}

func (p *GoModParser) Ecosystem() string { return "Go" }

func (p *GoModParser) Parse(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := make(map[string]bool)
	var deps []Dependency

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		mod := fields[0]
		ver := fields[1]

		// go.sum has entries like "module v1.2.3 h1:..." and "module v1.2.3/go.mod h1:..."
		ver = strings.TrimSuffix(ver, "/go.mod")

		key := mod + "@" + ver
		if seen[key] {
			continue
		}
		seen[key] = true

		deps = append(deps, Dependency{
			Name:      mod,
			Version:   ver,
			Ecosystem: "Go",
		})
	}
	return deps, scanner.Err()
}
