package config

import (
	"os"

	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Severity   string   `yaml:"severity"`
	Ecosystems []string `yaml:"ecosystems"`
	Lockfiles  []string `yaml:"lockfiles"`
	DryRun     bool     `yaml:"-"`
	Output     string   `yaml:"-"`
	Repo       string   `yaml:"-"`
	Token      string   `yaml:"-"`
	Ignore     Ignore   `yaml:"ignore"`
	Issues     Issues   `yaml:"issues"`
}

type Ignore struct {
	Advisories []string `yaml:"advisories"`
	Packages   []string `yaml:"packages"`
}

type Issues struct {
	Labels    []string `yaml:"labels"`
	Assignees []string `yaml:"assignees"`
}

func Default() *Config {
	return &Config{
		Severity:   "medium",
		Ecosystems: []string{"npm", "pypi", "go"},
		Issues: Issues{
			Labels: []string{"security", "unreleased-fix"},
		},
	}
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func MergeFlags(cfg *Config, flags *pflag.FlagSet) *Config {
	if v, err := flags.GetString("severity"); err == nil && v != "" {
		cfg.Severity = v
	}
	if v, err := flags.GetString("ecosystem"); err == nil && v != "" {
		cfg.Ecosystems = []string{v}
	}
	if v, err := flags.GetStringSlice("lockfile"); err == nil && len(v) > 0 {
		cfg.Lockfiles = v
	}
	if v, err := flags.GetBool("dry-run"); err == nil {
		cfg.DryRun = v
	}
	if v, err := flags.GetString("output"); err == nil && v != "" {
		cfg.Output = v
	}
	if v, err := flags.GetString("repo"); err == nil && v != "" {
		cfg.Repo = v
	}
	if v, err := flags.GetString("github-token"); err == nil && v != "" {
		cfg.Token = v
	}
	if v, err := flags.GetStringSlice("issue-labels"); err == nil && len(v) > 0 {
		cfg.Issues.Labels = append(cfg.Issues.Labels, v...)
	}
	return cfg
}
