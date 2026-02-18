package reporter

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/unreleased-security-fix-scanner/pkg/scanner"
)

type SARIFReporter struct{}

func (r *SARIFReporter) Report(findings []scanner.Finding) error {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "unreleased-security-fix-scanner",
						"informationUri": "https://github.com/unreleased-security-fix-scanner",
						"rules":          buildRules(findings),
					},
				},
				"results": buildResults(findings),
			},
		},
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(sarif)
}

func buildRules(findings []scanner.Finding) []map[string]interface{} {
	var rules []map[string]interface{}
	for _, f := range findings {
		rules = append(rules, map[string]interface{}{
			"id":               f.Advisory.ID,
			"shortDescription": map[string]string{"text": f.Advisory.Summary},
			"helpUri":          firstReference(f.Advisory.References),
		})
	}
	return rules
}

func buildResults(findings []scanner.Finding) []map[string]interface{} {
	var results []map[string]interface{}
	for _, f := range findings {
		results = append(results, map[string]interface{}{
			"ruleId":  f.Advisory.ID,
			"level":   mapSeverity(f.Advisory.Severity),
			"message": map[string]string{"text": fmt.Sprintf("Unreleased fix for %s in %s (commit %s)", f.Advisory.ID, f.Package.Name, shortSHA(f.FixCommit))},
		})
	}
	return results
}

func mapSeverity(s string) string {
	switch s {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func firstReference(refs []string) string {
	if len(refs) > 0 {
		return refs[0]
	}
	return ""
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
