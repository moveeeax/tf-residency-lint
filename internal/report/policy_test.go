package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/policy"
)

func policyFixture(t *testing.T) (policy.Result, PolicyMeta) {
	t.Helper()
	f, err := policy.Parse([]byte(`version: 1
rules:
  - id: protected-destroy
    description: resource tagged protected=true would be destroyed
    severity: deny
    match: {actions: [delete], tags: {protected: "true"}}
  - id: ebs-volume-encrypted
    description: new EBS volume is not encrypted at rest
    severity: deny
    match: {actions: [create], resource_types: [aws_ebs_volume]}
    require: [{path: encrypted, equals: true}]
`))
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Rules {
		f.Rules[i].Path = "./policy/rules.yaml"
	}
	res := policy.Result{
		GeneratedAt: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC),
		Rules:       2,
		Changes:     3,
		Findings: []policy.Finding{
			{Rule: "protected-destroy", Severity: check.Violation, Address: "aws_s3_bucket.audit",
				ResourceType: "aws_s3_bucket", Action: "delete", Message: "resource tagged protected=true would be destroyed",
				RuleFile: "./policy/rules.yaml", RuleLine: 3},
			{Rule: "ebs-volume-encrypted", Severity: check.Warning, Address: "aws_ebs_volume.cache",
				ResourceType: "aws_ebs_volume", Action: "create", Message: "new EBS volume is not encrypted at rest (undetermined)",
				Unknown: []string{"encrypted"}, RuleFile: "./policy/rules.yaml", RuleLine: 7},
		},
		Evaluated: []policy.Evaluation{
			{Rule: "protected-destroy", Address: "aws_s3_bucket.audit"},
			{Rule: "ebs-volume-encrypted", Address: "aws_ebs_volume.cache"},
			{Rule: "ebs-volume-encrypted", Address: "aws_ebs_volume.data"},
		},
	}
	return res, PolicyMeta{Plan: "plan.json", Version: "v1.2.3", FailOn: check.Violation, Rules: &policy.Set{Rules: f.Rules}}
}

func TestPolicySARIF(t *testing.T) {
	res, meta := policyFixture(t)
	var buf bytes.Buffer
	if err := PolicySARIF(&buf, res, meta); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, buf.String())
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("every loaded rule should be a SARIF rule, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	r := run.Results[0]
	if r.Level != "error" || r.RuleID != "protected-destroy" {
		t.Errorf("first result = %+v", r)
	}
	if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
		t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
	}
	loc := r.Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != "policy/rules.yaml" || loc.PhysicalLocation.Region.StartLine != 3 {
		t.Errorf("location = %+v, want policy/rules.yaml:3", loc.PhysicalLocation)
	}
	if loc.LogicalLocations[0].FullyQualifiedName != "aws_s3_bucket.audit" {
		t.Errorf("logical location = %+v", loc.LogicalLocations)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("undetermined finding level = %q, want warning", run.Results[1].Level)
	}
	if run.Results[0].PartialFingerprints["primaryLocationLineHash"] == run.Results[1].PartialFingerprints["primaryLocationLineHash"] {
		t.Error("distinct findings share a fingerprint")
	}
}

func TestPolicyJUnit(t *testing.T) {
	res, meta := policyFixture(t)
	var buf bytes.Buffer
	if err := PolicyJUnit(&buf, res, meta); err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not XML: %v\n%s", err, buf.String())
	}
	// Three evaluated pairs; only the deny finding is at --fail-on violation.
	if doc.Tests != 3 || doc.Failures != 1 {
		t.Errorf("tests = %d, failures = %d, want 3 and 1", doc.Tests, doc.Failures)
	}
	if len(doc.Suites) != 2 || doc.Suites[0].Name != "ebs-volume-encrypted" {
		t.Fatalf("suites = %+v", doc.Suites)
	}
	ebs := doc.Suites[0]
	if ebs.Cases[0].Name != "aws_ebs_volume.cache" || ebs.Cases[0].Failure != nil || ebs.Cases[0].SystemOut == nil {
		t.Errorf("a warning below --fail-on goes to system-out: %+v", ebs.Cases[0])
	}
	if ebs.Cases[1].Failure != nil || ebs.Cases[1].SystemOut != nil {
		t.Errorf("a pass has no output: %+v", ebs.Cases[1])
	}

	meta.FailOn = check.Warning
	buf.Reset()
	if err := PolicyJUnit(&buf, res, meta); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `failures="2"`) {
		t.Errorf("--fail-on warning should fail both:\n%s", buf.String())
	}
}

func TestPolicyPrettyAndJSON(t *testing.T) {
	res, _ := policyFixture(t)
	var buf bytes.Buffer
	PolicyPretty(&buf, res, "plan.json")
	out := buf.String()
	for _, want := range []string{"[violation] protected-destroy", "rule       ./policy/rules.yaml:3", "1 denied, 1 warning(s), 0 exempted"} {
		if !strings.Contains(out, want) {
			t.Errorf("text report missing %q:\n%s", want, out)
		}
	}
	buf.Reset()
	if err := PolicyJSON(&buf, policy.Result{}, "plan.json"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) || !strings.Contains(buf.String(), `"mode": "policy"`) {
		t.Errorf("empty JSON report:\n%s", buf.String())
	}
}
