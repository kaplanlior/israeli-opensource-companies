package reporter

import (
	"github.com/unreleased-security-fix-scanner/pkg/scanner"
)

type Reporter interface {
	Report(findings []scanner.Finding) error
}

func New(format string) Reporter {
	switch format {
	case "json":
		return &JSONReporter{}
	case "sarif":
		return &SARIFReporter{}
	default:
		return &TableReporter{}
	}
}
