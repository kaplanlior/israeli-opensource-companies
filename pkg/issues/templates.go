package issues

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/unreleased-security-fix-scanner/pkg/scanner"
)

var newIssueTmpl = template.Must(template.New("new_issue").Parse(`## ⚠️ Unreleased Security Fix: {{ .Advisory.ID }}

**Package:** ` + "`{{ .Package.Name }}`" + ` ({{ .Package.Ecosystem }})
**Your version:** ` + "`{{ .Package.Version }}`" + `
**Severity:** {{ .Advisory.Severity }}

### Summary

{{ .Advisory.Summary }}

### Details

A fix for this vulnerability was committed to the upstream source repository
but has **not yet been included in a published release**.

| Detail | Value |
|--------|-------|
| Fix commit | ` + "`{{ .ShortCommit }}`" + `{{ if .CommitURL }} ([link]({{ .CommitURL }})){{ end }} |
| Source repo | {{ if .SourceRepo }}[{{ .SourceRepo }}](https://{{ .SourceRepo }}){{ else }}(unknown){{ end }} |
| Advisory | {{ range .Advisory.References }}[{{ $.Advisory.ID }}]({{ . }}) {{ end }} |

### Recommended Actions

1. **Watch** the upstream repo for a new release.
2. **Vendor** the fix commit directly if you need an immediate resolution.
3. **Open an issue** upstream requesting a release that includes the fix.

---

<sub>Detected by [unreleased-security-fix-scanner](https://github.com/unreleased-security-fix-scanner)</sub>
`))

var fixReleasedTmpl = template.Must(template.New("fix_released").Parse(`## ✅ Fix Released

The fix for **{{ .Advisory.ID }}** is now included in **` + "`{{ .Package.Name }}@{{ .FixRelease }}`" + `**.

Upgrade your dependency to ` + "`>= {{ .FixRelease }}`" + ` to resolve this vulnerability.

| Detail | Value |
|--------|-------|
| Fix release | ` + "`{{ .FixRelease }}`" + ` |
| Source repo | {{ if .SourceRepo }}[{{ .SourceRepo }}](https://{{ .SourceRepo }}){{ else }}(unknown){{ end }} |

---

<sub>Updated by [unreleased-security-fix-scanner](https://github.com/unreleased-security-fix-scanner)</sub>
`))

type templateData struct {
	scanner.Finding
	ShortCommit string
	CommitURL   string
}

func RenderNewIssueBody(f scanner.Finding) string {
	data := templateData{
		Finding:     f,
		ShortCommit: shortSHA(f.FixCommit),
	}
	if f.SourceRepo != "" && f.FixCommit != "" {
		data.CommitURL = fmt.Sprintf("https://%s/commit/%s", f.SourceRepo, f.FixCommit)
	}

	var buf bytes.Buffer
	if err := newIssueTmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("Error rendering issue template: %v", err)
	}
	return buf.String()
}

func RenderFixReleasedComment(f scanner.Finding) string {
	data := templateData{
		Finding:     f,
		ShortCommit: shortSHA(f.FixCommit),
	}

	var buf bytes.Buffer
	if err := fixReleasedTmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("Error rendering comment template: %v", err)
	}
	return buf.String()
}

func shortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
