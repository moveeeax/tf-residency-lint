package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/policy"
)

// PolicyMeta is what the policy renderers need beyond the result.
type PolicyMeta struct {
	Plan    string
	Version string
	FailOn  check.Severity
	Rules   *policy.Set
}

const policyHelp = informationURI + "#plan-policy"

// PolicyPretty writes a human-readable policy report.
func PolicyPretty(w io.Writer, res policy.Result, planPath string) {
	counts := res.Counts()
	fmt.Fprintf(w, "tf-residency-lint policy  %s\n", res.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "  plan     %s\n", planPath)
	fmt.Fprintf(w, "  rules    %d\n", res.Rules)
	fmt.Fprintf(w, "  changes  %d resource change(s)\n\n", res.Changes)

	if len(res.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return
	}
	for _, f := range res.Findings {
		fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Rule)
		fmt.Fprintf(w, "      resource   %s (%s)\n", f.Address, f.ResourceType)
		fmt.Fprintf(w, "      action     %s\n", f.Action)
		fmt.Fprintf(w, "      %s\n", wrapIndent(f.Message, 72, "      "))
		for _, c := range f.Failed {
			fmt.Fprintf(w, "      failed     %s\n", c)
		}
		if f.ExemptionReason != "" {
			fmt.Fprintf(w, "      exemption  %s (expires %s)\n", f.ExemptionReason, f.ExemptionExpires)
		}
		if f.RuleFile != "" {
			fmt.Fprintf(w, "      rule       %s:%d\n", f.RuleFile, f.RuleLine)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%d denied, %d warning(s), %d exempted\n",
		counts[check.Violation], counts[check.Warning], counts[check.Info])
}

// PolicyJSON writes the machine-readable policy report.
func PolicyJSON(w io.Writer, res policy.Result, planPath string) error {
	if res.Findings == nil {
		res.Findings = []policy.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Tool   string        `json:"tool"`
		Mode   string        `json:"mode"`
		Plan   string        `json:"plan"`
		Result policy.Result `json:"result"`
	}{"tf-residency-lint", "policy", planPath, res})
}

// PolicySARIF writes the policy result as SARIF 2.1.0. Every loaded rule is a
// SARIF rule; each result is located at the line of the rules file where the
// rule that produced it starts, with the resource address as a logical
// location.
func PolicySARIF(w io.Writer, res policy.Result, meta PolicyMeta) error {
	var rules []sarifRule
	index := map[string]int{}
	if meta.Rules != nil {
		for i, r := range meta.Rules.Rules {
			index[r.ID] = i
			rules = append(rules, sarifRule{
				ID:               r.ID,
				Name:             r.ID,
				ShortDescription: sarifMessage{Text: r.Description},
				HelpURI:          policyHelp,
			})
		}
	}
	if rules == nil {
		rules = []sarifRule{}
	}

	results := make([]sarifResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		line := f.RuleLine
		if line < 1 {
			line = 1
		}
		props := map[string]any{"severity": string(f.Severity), "action": f.Action, "resource_type": f.ResourceType}
		if len(f.Failed) > 0 {
			props["failed_conditions"] = f.Failed
		}
		if len(f.Unknown) > 0 {
			props["unknown_paths"] = f.Unknown
		}
		if f.ExemptionReason != "" {
			props["exemption_reason"] = f.ExemptionReason
			props["exemption_expires_on"] = f.ExemptionExpires
		}
		msg := f.Address + " (" + f.Action + "): " + f.Message + "."
		if len(f.Failed) > 0 {
			msg += " Failed: " + strings.Join(f.Failed, "; ") + "."
		}
		sum := sha256.Sum256([]byte(strings.Join([]string{"policy", f.Rule, f.Address}, "\x00")))
		results = append(results, sarifResult{
			RuleID:    f.Rule,
			RuleIndex: index[f.Rule],
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: msg},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: filepath.ToSlash(filepath.Clean(f.RuleFile))},
					Region:           sarifRegion{StartLine: line},
				},
				LogicalLocations: []sarifLogical{{FullyQualifiedName: f.Address, Kind: "resource"}},
			}},
			PartialFingerprints: map[string]string{"primaryLocationLineHash": hex.EncodeToString(sum[:16])},
			Properties:          props,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tf-residency-lint",
				Version:        meta.Version,
				InformationURI: informationURI,
				Rules:          rules,
			}},
			Results:    results,
			Properties: map[string]any{"mode": "policy", "plan": meta.Plan},
		}},
	})
}

// PolicyJUnit writes one testsuite per rule and one testcase per resource
// change the rule selected, passes included. A testcase fails when its
// finding is at or above meta.FailOn, so the test view agrees with the exit
// code.
func PolicyJUnit(w io.Writer, res policy.Result, meta PolicyMeta) error {
	type key struct{ rule, address string }
	findings := map[key]policy.Finding{}
	for _, f := range res.Findings {
		findings[key{f.Rule, f.Address}] = f
	}
	bySuite := map[string][]junitCase{}
	for _, e := range res.Evaluated {
		tc := junitCase{Name: e.Address, ClassName: "tf-residency-lint.policy." + e.Rule}
		if f, ok := findings[key{e.Rule, e.Address}]; ok {
			text := policyFindingText(f)
			if f.Severity.AtLeast(meta.FailOn) {
				tc.Failure = &junitFailure{
					Message: fmt.Sprintf("%s: %s", f.Rule, f.Message),
					Type:    string(f.Severity),
					Text:    text,
				}
			} else {
				tc.SystemOut = &junitText{Text: text}
			}
		}
		bySuite[e.Rule] = append(bySuite[e.Rule], tc)
	}

	names := make([]string, 0, len(bySuite))
	for n := range bySuite {
		names = append(names, n)
	}
	sort.Strings(names)

	out := junitSuites{Name: "tf-residency-lint policy"}
	stamp := res.GeneratedAt.UTC().Format("2006-01-02T15:04:05")
	for _, n := range names {
		tcs := bySuite[n]
		sort.Slice(tcs, func(i, j int) bool { return tcs[i].Name < tcs[j].Name })
		suite := junitSuite{
			Name:      n,
			Tests:     len(tcs),
			Timestamp: stamp,
			Properties: []junitProperty{
				{Name: "plan", Value: meta.Plan},
				{Name: "fail-on", Value: string(meta.FailOn)},
			},
			Cases: tcs,
		}
		for _, tc := range tcs {
			if tc.Failure != nil {
				suite.Failures++
			}
		}
		out.Tests += suite.Tests
		out.Failures += suite.Failures
		out.Suites = append(out.Suites, suite)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func policyFindingText(f policy.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] %s\n%s\naction: %s\n", f.Severity, f.Rule, f.Message, f.Action)
	for _, c := range f.Failed {
		fmt.Fprintf(&b, "failed: %s\n", c)
	}
	if f.ExemptionReason != "" {
		fmt.Fprintf(&b, "exemption: %s (expires %s)\n", f.ExemptionReason, f.ExemptionExpires)
	}
	if f.RuleFile != "" {
		fmt.Fprintf(&b, "rule: %s:%d\n", f.RuleFile, f.RuleLine)
	}
	return b.String()
}
