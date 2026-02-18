package lockfile

import (
	"fmt"
	"path/filepath"
)

type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
}

type Parser interface {
	Parse(path string) ([]Dependency, error)
	Ecosystem() string
}

func NewParser(path string) (Parser, error) {
	base := filepath.Base(path)
	switch base {
	case "package-lock.json", "yarn.lock", "pnpm-lock.yaml":
		return &NPMParser{}, nil
	case "requirements.txt", "poetry.lock", "Pipfile.lock":
		return &PyPIParser{}, nil
	case "go.sum":
		return &GoModParser{}, nil
	default:
		return nil, fmt.Errorf("unsupported lockfile: %s", base)
	}
}
