package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/config"
)

const configYAML = `version: 1
jurisdictions: [EX]
declarations:
  - name: customer documents
    data_class: personal
    match:
      addresses: ["aws_s3_bucket.docs"]

  - name: payments
    data_class: financial
    match:
      addresses: ["aws_sqs_queue.*"]
`

func fixture(t *testing.T) (check.Result, Meta) {
	t.Helper()
	cfg, err := config.Parse([]byte(configYAML))
	if err != nil {
		t.Fatal(err)
	}
	res := check.Result{
		GeneratedAt:   time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC),
		Jurisdictions: []string{"EX"},
		Scanned:       4,
		InScope:       3,
		Findings: []check.Finding{
			{
				Rule: check.RuleResidencyViolation, Severity: check.Violation,
				Address: "aws_s3_bucket.docs", ResourceType: "aws_s3_bucket",
				Cloud: "aws", Region: "eu-west-1", RegionSource: "resource attribute",
				Jurisdiction: "EX", DataClass: "personal", DeclaredBy: "customer documents",
				Message:   "personal data must stay in EX but this resource is in eu-west-1",
				SourceURL: "https://example.invalid/ex#art-19", CheckedOn: "2026-07-20",
			},
			{
				Rule: check.RuleConditional, Severity: check.Warning,
				Address: "aws_sqs_queue.settlement", Jurisdiction: "EX", DataClass: "financial",
				DeclaredBy: "payments", Message: "transfer only via the named mechanism",
				SourceURL: "https://example.invalid/ex#para-4", CheckedOn: "2026-07-20",
			},
			{
				Rule: check.RuleStaleRule, Severity: check.Warning,
				Jurisdiction: "EX", DataClass: "personal", Message: "rule last verified 108 days ago",
				SourceURL: "https://example.invalid/ex#art-19", CheckedOn: "2026-07-20",
			},
			{
				Rule: check.RuleUnclassified, Severity: check.Warning,
				Address: "aws_efs_file_system.scratch", Message: "no declaration covers it",
			},
		},
		Evaluated: []check.Evaluation{
			{Address: "aws_s3_bucket.docs", Jurisdiction: "EX"},
			{Address: "aws_sqs_queue.settlement", Jurisdiction: "EX"},
			{Address: "aws_dynamodb_table.ok", Jurisdiction: "EX"},
		},
	}
	return res, Meta{
		Plan: "plan.json", Config: "./infra/residency.yaml", Version: "v1.2.3",
		FailOn: check.Violation, Declarations: cfg,
	}
}

func TestSARIF(t *testing.T) {
	res, meta := fixture(t)
	var buf bytes.Buffer
	if err := SARIF(&buf, res, meta); err != nil {
		t.Fatal(err)
	}

	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
						Kind               string `json:"kind"`
					} `json:"logicalLocations"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
				Properties          map[string]any    `json:"properties"`
			} `json:"results"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("version %q, runs %d", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "tf-residency-lint" || run.Tool.Driver.Version != "v1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}
	if run.Properties["disclaimer"] != Disclaimer {
		t.Errorf("run.properties must carry the disclaimer, got %v", run.Properties)
	}

	// One rule per distinct finding rule, sorted, each with help.
	var ids []string
	for _, r := range run.Tool.Driver.Rules {
		ids = append(ids, r.ID)
		if r.HelpURI == "" {
			t.Errorf("rule %s has no helpUri", r.ID)
		}
	}
	if got := strings.Join(ids, ","); got != "conditional-transfer,residency-violation,stale-rule,unclassified-stateful-resource" {
		t.Errorf("rules = %s", got)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(run.Results))
	}

	fps := map[string]bool{}
	for _, r := range run.Results {
		if ids[r.RuleIndex] != r.RuleID {
			t.Errorf("%s: ruleIndex %d points at %s", r.RuleID, r.RuleIndex, ids[r.RuleIndex])
		}
		if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "infra/residency.yaml" {
			t.Errorf("%s: uri = %q", r.RuleID, r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		fp := r.PartialFingerprints["primaryLocationLineHash"]
		if fp == "" || fps[fp] {
			t.Errorf("%s: fingerprint %q missing or duplicated", r.RuleID, fp)
		}
		fps[fp] = true
	}

	v := run.Results[0]
	if v.RuleID != "residency-violation" || v.Level != "error" {
		t.Errorf("first result = %s/%s", v.RuleID, v.Level)
	}
	// The declaration "customer documents" starts on line 4 of configYAML.
	if v.Locations[0].PhysicalLocation.Region.StartLine != 4 {
		t.Errorf("violation line = %d, want 4", v.Locations[0].PhysicalLocation.Region.StartLine)
	}
	if ll := v.Locations[0].LogicalLocations; len(ll) != 1 || ll[0].FullyQualifiedName != "aws_s3_bucket.docs" {
		t.Errorf("logical location = %+v", ll)
	}
	if !strings.Contains(v.Message.Text, "https://example.invalid/ex#art-19 (checked 2026-07-20)") {
		t.Errorf("message must carry the citation: %q", v.Message.Text)
	}
	if v.Properties["source_url"] != "https://example.invalid/ex#art-19" {
		t.Errorf("properties = %v", v.Properties)
	}

	byRule := map[string]int{}
	for i, r := range run.Results {
		byRule[r.RuleID] = i
	}
	if r := run.Results[byRule["conditional-transfer"]]; r.Level != "warning" || r.Locations[0].PhysicalLocation.Region.StartLine != 9 {
		t.Errorf("conditional-transfer: level %s line %d", r.Level, r.Locations[0].PhysicalLocation.Region.StartLine)
	}
	// No declaration, no resource: line 1, no logical location.
	if r := run.Results[byRule["stale-rule"]]; r.Locations[0].PhysicalLocation.Region.StartLine != 1 || len(r.Locations[0].LogicalLocations) != 0 {
		t.Errorf("stale-rule location = %+v", r.Locations[0])
	}
}

func TestSARIFLevels(t *testing.T) {
	for sev, want := range map[check.Severity]string{check.Violation: "error", check.Warning: "warning", check.Info: "note"} {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%s) = %s, want %s", sev, got, want)
		}
	}
}

func TestSARIFNoFindings(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, check.Result{Jurisdictions: []string{"EX"}}, Meta{Config: "residency.yaml"}); err != nil {
		t.Fatal(err)
	}
	// Code scanning needs empty arrays, not null, to close old alerts.
	if !strings.Contains(buf.String(), `"results": []`) || !strings.Contains(buf.String(), `"rules": []`) {
		t.Errorf("empty run should carry empty arrays:\n%s", buf.String())
	}
}

type junitDoc struct {
	Tests    int `xml:"tests,attr"`
	Failures int `xml:"failures,attr"`
	Suites   []struct {
		Name       string `xml:"name,attr"`
		Tests      int    `xml:"tests,attr"`
		Failures   int    `xml:"failures,attr"`
		Properties []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"properties>property"`
		Cases []struct {
			Name      string `xml:"name,attr"`
			ClassName string `xml:"classname,attr"`
			Failure   *struct {
				Message string `xml:"message,attr"`
				Type    string `xml:"type,attr"`
				Text    string `xml:",chardata"`
			} `xml:"failure"`
			SystemOut string `xml:"system-out"`
		} `xml:"testcase"`
	} `xml:"testsuite"`
}

func junit(t *testing.T, res check.Result, meta Meta) junitDoc {
	t.Helper()
	var buf bytes.Buffer
	if err := JUnit(&buf, res, meta); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "<?xml") {
		t.Errorf("missing XML header")
	}
	var doc junitDoc
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid XML: %v\n%s", err, buf.String())
	}
	return doc
}

func TestJUnit(t *testing.T) {
	res, meta := fixture(t)
	doc := junit(t, res, meta)

	if len(doc.Suites) != 2 || doc.Suites[0].Name != "(estate-wide)" || doc.Suites[1].Name != "EX" {
		t.Fatalf("suites = %+v", doc.Suites)
	}
	if doc.Tests != 5 || doc.Failures != 1 {
		t.Errorf("totals = %d tests, %d failures; want 5, 1", doc.Tests, doc.Failures)
	}

	ex := doc.Suites[1]
	var names []string
	for _, c := range ex.Cases {
		names = append(names, c.Name)
		if c.ClassName != "tf-residency-lint.EX" {
			t.Errorf("%s: classname %q", c.Name, c.ClassName)
		}
	}
	want := "aws_dynamodb_table.ok,aws_s3_bucket.docs,aws_sqs_queue.settlement,ruleset EX/personal"
	if got := strings.Join(names, ","); got != want {
		t.Errorf("cases = %s, want %s", got, want)
	}

	pass, fail, warn := ex.Cases[0], ex.Cases[1], ex.Cases[2]
	if pass.Failure != nil || pass.SystemOut != "" {
		t.Errorf("clean pair should pass silently: %+v", pass)
	}
	if fail.Failure == nil || fail.Failure.Type != "violation" ||
		!strings.HasPrefix(fail.Failure.Message, "residency-violation:") ||
		!strings.Contains(fail.Failure.Text, "source: https://example.invalid/ex#art-19 (checked 2026-07-20)") {
		t.Errorf("violation case = %+v", fail.Failure)
	}
	if warn.Failure != nil || !strings.Contains(warn.SystemOut, "conditional-transfer") {
		t.Errorf("a warning below --fail-on should not fail: %+v", warn)
	}

	var disclaimer bool
	for _, p := range ex.Properties {
		if p.Name == "disclaimer" && p.Value == Disclaimer {
			disclaimer = true
		}
	}
	if !disclaimer {
		t.Error("every suite must carry the disclaimer")
	}
}

func TestJUnitFailOnWarning(t *testing.T) {
	res, meta := fixture(t)
	meta.FailOn = check.Warning
	doc := junit(t, res, meta)
	if doc.Failures != 4 {
		t.Errorf("failures = %d, want 4 with --fail-on warning", doc.Failures)
	}
}
