package reporter

import (
	"encoding/json"
	"os"

	"github.com/unreleased-security-fix-scanner/pkg/scanner"
)

type JSONReporter struct{}

func (r *JSONReporter) Report(findings []scanner.Finding) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	type output struct {
		Count    int               `json:"count"`
		Findings []scanner.Finding `json:"findings"`
	}

	return enc.Encode(output{
		Count:    len(findings),
		Findings: findings,
	})
}
