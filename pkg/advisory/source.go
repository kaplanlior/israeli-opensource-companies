package advisory

import "time"

type Advisory struct {
	ID        string
	Aliases   []string
	Summary   string
	Details   string
	Severity  string
	Published time.Time
	Modified  time.Time
	FixCommit string
	FixedIn   string // version string (may be empty if only commit is known)
	References []string
}

type Source interface {
	// QueryPackage returns advisories affecting the given package at the given version.
	QueryPackage(ecosystem, name, version string) ([]Advisory, error)

	// QueryBatch queries advisories for multiple packages in a single call.
	QueryBatch(queries []PackageQuery) (map[string][]Advisory, error)
}

type PackageQuery struct {
	Ecosystem string
	Name      string
	Version   string
}
