package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/moveeeax/tf-residency-lint/internal/check"
)

// estateWide names the suite for findings that belong to no jurisdiction.
const estateWide = "(estate-wide)"

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name       string          `xml:"name,attr"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Errors     int             `xml:"errors,attr"`
	Skipped    int             `xml:"skipped,attr"`
	Timestamp  string          `xml:"timestamp,attr"`
	Properties []junitProperty `xml:"properties>property"`
	Cases      []junitCase     `xml:"testcase"`
}

type junitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type junitCase struct {
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	SystemOut *junitText    `xml:"system-out,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",cdata"`
}

type junitText struct {
	Text string `xml:",cdata"`
}

// JUnit writes the result as JUnit XML: one testsuite per jurisdiction and one
// testcase per (jurisdiction, resource). A testcase fails when it carries a
// finding at or above meta.FailOn, so the test report agrees with the exit
// code; findings below the threshold go to system-out. Pairs that were checked
// and produced nothing appear as passing testcases.
func JUnit(w io.Writer, res check.Result, meta Meta) error {
	type key struct{ suite, name string }
	cases := map[key][]check.Finding{}
	for _, e := range res.Evaluated {
		k := key{e.Jurisdiction, e.Address}
		if _, ok := cases[k]; !ok {
			cases[k] = nil
		}
	}
	for _, f := range res.Findings {
		k := key{f.Jurisdiction, f.Address}
		if k.suite == "" {
			k.suite = estateWide
		}
		if k.name == "" {
			// Ruleset-level findings (stale-rule) have no resource.
			k.name = "ruleset " + f.Jurisdiction + "/" + f.DataClass
		}
		cases[k] = append(cases[k], f)
	}

	bySuite := map[string][]junitCase{}
	for k, findings := range cases {
		tc := junitCase{Name: k.name, ClassName: "tf-residency-lint." + k.suite}
		var failing, other []check.Finding
		for _, f := range findings {
			if f.Severity.AtLeast(meta.FailOn) {
				failing = append(failing, f)
			} else {
				other = append(other, f)
			}
		}
		if len(failing) > 0 {
			rules := make([]string, 0, len(failing))
			for _, f := range failing {
				rules = append(rules, f.Rule)
			}
			tc.Failure = &junitFailure{
				Message: fmt.Sprintf("%s: %s", strings.Join(rules, ", "), failing[0].Message),
				Type:    string(failing[0].Severity),
				Text:    findingsText(failing),
			}
		}
		if len(other) > 0 {
			tc.SystemOut = &junitText{Text: findingsText(other)}
		}
		bySuite[k.suite] = append(bySuite[k.suite], tc)
	}

	names := make([]string, 0, len(bySuite))
	for n := range bySuite {
		names = append(names, n)
	}
	sort.Strings(names)

	out := junitSuites{Name: "tf-residency-lint"}
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
				{Name: "disclaimer", Value: Disclaimer},
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

// findingsText renders findings as the plain-text block a CI test view shows.
func findingsText(fs []check.Finding) string {
	var b strings.Builder
	for i, f := range fs {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "[%s] %s\n%s\n", f.Severity, f.Rule, f.Message)
		if f.Region != "" {
			fmt.Fprintf(&b, "region: %s / %s (from %s)\n", f.Cloud, f.Region, f.RegionSource)
		}
		if f.DataClass != "" {
			fmt.Fprintf(&b, "data class: %s", f.DataClass)
			if f.DeclaredBy != "" {
				fmt.Fprintf(&b, " (declared by %q)", f.DeclaredBy)
			}
			b.WriteString("\n")
		}
		if f.TransferMechanism != "" {
			fmt.Fprintf(&b, "mechanism: %s\n", f.TransferMechanism)
		}
		if f.WaiverReason != "" {
			fmt.Fprintf(&b, "waiver: %s\n", f.WaiverReason)
		}
		if f.SourceURL != "" {
			fmt.Fprintf(&b, "source: %s (checked %s)\n", f.SourceURL, f.CheckedOn)
		}
	}
	return b.String()
}
