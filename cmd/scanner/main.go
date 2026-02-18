package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/unreleased-security-fix-scanner/pkg/config"
)

var (
	version = "dev"
	commit  = "none"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "unreleased-security-fix-scanner",
		Short:   "Detect upstream security fixes that haven't been released yet",
		Long:    `Scans dependency lockfiles to find upstream packages with committed security fixes that are not yet included in a published release.`,
		Version: fmt.Sprintf("%s (%s)", version, commit),
		RunE:    run,
	}

	rootCmd.Flags().StringSlice("lockfile", nil, "Path(s) to lockfile (auto-detected if omitted)")
	rootCmd.Flags().String("ecosystem", "", "Force ecosystem: npm | pypi | go")
	rootCmd.Flags().String("repo", os.Getenv("GITHUB_REPOSITORY"), "GitHub repo (owner/repo) to manage issues in")
	rootCmd.Flags().String("github-token", os.Getenv("GITHUB_TOKEN"), "GitHub token for API access")
	rootCmd.Flags().String("output", "table", "Output format: json | sarif | table")
	rootCmd.Flags().Bool("dry-run", false, "Print findings without creating/updating issues")
	rootCmd.Flags().String("config", ".unreleased-fix-scanner.yml", "Path to config file")
	rootCmd.Flags().String("severity", "medium", "Minimum severity: low | medium | high | critical")
	rootCmd.Flags().StringSlice("issue-labels", nil, "Additional labels to add to created issues")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(2)
	}
}

func run(cmd *cobra.Command, args []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not load config file: %v (using defaults)\n", err)
		cfg = config.Default()
	}

	cfg = config.MergeFlags(cfg, cmd.Flags())

	if cfg.DryRun {
		fmt.Println("dry-run mode: no issues will be created or updated")
	}

	fmt.Printf("scanning with config: severity >= %s, ecosystems: %v\n", cfg.Severity, cfg.Ecosystems)

	// Step 1: Detect and parse lockfiles
	lockfiles := cfg.Lockfiles
	if len(lockfiles) == 0 {
		lockfiles = detectLockfiles(".")
	}
	if len(lockfiles) == 0 {
		return fmt.Errorf("no lockfiles found; specify --lockfile or add lockfiles to config")
	}
	fmt.Printf("lockfiles: %v\n", lockfiles)

	// Steps 2-6 are implemented in pkg/scanner.Scanner
	// This is the orchestration skeleton:
	//
	//   deps := lockfile.Parse(lockfiles)
	//   advisories := advisory.QueryBatch(deps)
	//   findings := scanner.Analyze(deps, advisories)
	//   reporter.Report(findings, cfg.Output)
	//   issues.Reconcile(findings, cfg)

	fmt.Println("scanner implementation pending — see DESIGN.md for architecture")
	return nil
}

func detectLockfiles(dir string) []string {
	candidates := []string{
		"package-lock.json",
		"yarn.lock",
		"pnpm-lock.yaml",
		"requirements.txt",
		"poetry.lock",
		"Pipfile.lock",
		"go.sum",
	}
	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(dir + "/" + c); err == nil {
			found = append(found, dir+"/"+c)
		}
	}
	return found
}
