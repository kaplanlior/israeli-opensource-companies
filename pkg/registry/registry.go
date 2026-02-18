package registry

type PackageInfo struct {
	Name       string
	SourceRepo string // e.g. "github.com/owner/repo"
	LatestVersion string
}

type Registry interface {
	// LookupSourceRepo returns the source repository URL for a given package.
	LookupSourceRepo(name string) (PackageInfo, error)
}

func NewRegistry(ecosystem string) Registry {
	switch ecosystem {
	case "npm":
		return NewNPMRegistry()
	case "PyPI":
		return NewPyPIRegistry()
	default:
		return nil
	}
}
