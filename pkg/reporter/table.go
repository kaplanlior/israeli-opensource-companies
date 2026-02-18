package reporter

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/unreleased-security-fix-scanner/pkg/scanner"
)

type TableReporter struct{}

func (r *TableReporter) Report(findings []scanner.Finding) error {
	if len(findings) == 0 {
		fmt.Println("No unreleased security fixes found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ADVISORY\tSEVERITY\tPACKAGE\tVERSION\tFIX COMMIT\tSOURCE REPO")
	fmt.Fprintln(w, "--------\t--------\t-------\t-------\t----------\t-----------")

	for _, f := range findings {
		commitDisplay := shortSHA(f.FixCommit)
		if commitDisplay == "" {
			commitDisplay = "(unknown)"
		}
		repoDisplay := f.SourceRepo
		if repoDisplay == "" {
			repoDisplay = "(unknown)"
		}
		severity := strings.ToUpper(f.Advisory.Severity)
		if severity == "" {
			severity = "UNKNOWN"
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Advisory.ID,
			severity,
			f.Package.Name,
			f.Package.Version,
			commitDisplay,
			repoDisplay,
		)
	}
	return w.Flush()
}
