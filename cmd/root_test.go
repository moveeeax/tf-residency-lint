package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string, err error) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code, err = Run(args, &out, &errBuf)
	return code, out.String(), errBuf.String(), err
}

const (
	planFixture    = "../testdata/plan.json"
	configFixture  = "../testdata/residency.yaml"
	publishedRules = "../testdata/rulesets"
	exampleRules   = "../rulesets"
	staleRules     = "../testdata/rulesets_stale"
)

func TestCheckExitsNonZeroOnViolation(t *testing.T) {
	code, out, _, err := run(t, "check",
		"--plan", planFixture,
		"--config", configFixture,
		"--rulesets", exampleRules,
		"--allow-unpublished")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d", code, exitFindings)
	}
	if !strings.Contains(out, "residency-violation") {
		t.Errorf("report does not mention a violation:\n%s", out)
	}
	// Every deliverable carries the disclaimer.
	if !strings.Contains(out, "not legal advice") {
		t.Errorf("report is missing the disclaimer:\n%s", out)
	}
	// Findings must be traceable to a source and a date.
	if !strings.Contains(out, "checked 2026-07-20") {
		t.Errorf("report is missing the citation date:\n%s", out)
	}
}

// Without --allow-unpublished the shipped example rulesets are fictional
// research and must not fail anybody's pipeline.
func TestCheckDoesNotGateOnExampleRulesetsByDefault(t *testing.T) {
	code, _, _, err := run(t, "check",
		"--plan", planFixture,
		"--config", configFixture,
		"--rulesets", exampleRules)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != exitOK {
		t.Errorf("exit = %d, want %d", code, exitOK)
	}
}

func TestCheckJSONOutput(t *testing.T) {
	code, out, _, err := run(t, "check",
		"--plan", planFixture,
		"--config", configFixture,
		"--rulesets", exampleRules,
		"--allow-unpublished",
		"--json")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d", code, exitFindings)
	}

	var doc struct {
		Tool   string `json:"tool"`
		Plan   string `json:"plan"`
		Result struct {
			Scanned  int `json:"resources_scanned"`
			InScope  int `json:"resources_in_scope"`
			Findings []struct {
				Rule      string `json:"rule"`
				Severity  string `json:"severity"`
				SourceURL string `json:"source_url"`
				CheckedOn string `json:"checked_on"`
			} `json:"findings"`
		} `json:"result"`
		Disclaimer string `json:"disclaimer"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if doc.Tool != "tf-residency-lint" || doc.Plan != planFixture {
		t.Errorf("header = %+v", doc)
	}
	if doc.Disclaimer == "" {
		t.Error("JSON output must carry the disclaimer too")
	}
	if doc.Result.Scanned != 11 {
		t.Errorf("resources_scanned = %d, want 11", doc.Result.Scanned)
	}
	if len(doc.Result.Findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range doc.Result.Findings {
		// Rules about a jurisdiction must cite; engine-level findings need not.
		if f.Rule == "residency-violation" && (f.SourceURL == "" || f.CheckedOn == "") {
			t.Errorf("violation without a citation: %+v", f)
		}
	}
}

func TestFailOnWarningTightensTheGate(t *testing.T) {
	// The published fixture ruleset produces warnings for the fixture estate.
	code, _, _, err := run(t, "check",
		"--plan", planFixture,
		"--config", configFixture,
		"--rulesets", publishedRules,
		"--fail-on", "warning")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d with --fail-on warning", code, exitFindings)
	}
}

func TestBadFailOnIsAUsageError(t *testing.T) {
	code, _, _, err := run(t, "check",
		"--plan", planFixture,
		"--config", configFixture,
		"--rulesets", publishedRules,
		"--fail-on", "critical")
	if err == nil {
		t.Fatal("expected an error")
	}
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
}

// A missing plan file must exit 2, never 0. Exit 0 here would be a false green.
func TestMissingPlanExitsWithError(t *testing.T) {
	code, _, _, err := run(t, "check",
		"--plan", "../testdata/does-not-exist.json",
		"--config", configFixture,
		"--rulesets", publishedRules)
	if err == nil {
		t.Fatal("expected an error")
	}
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
}

func TestInventoryNeedsNoRuleset(t *testing.T) {
	code, out, _, err := run(t, "inventory", "--plan", planFixture, "--stateful-only")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != exitOK {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out, "module.clinical.azurerm_storage_account.records") {
		t.Errorf("inventory is missing a stateful resource:\n%s", out)
	}
	if strings.Contains(out, "google_compute_instance") {
		t.Errorf("--stateful-only should exclude compute:\n%s", out)
	}
	if !strings.Contains(out, "9 resource(s) storing data at rest, of 11 total") {
		t.Errorf("inventory totals are wrong:\n%s", out)
	}
}

func TestInventoryJSON(t *testing.T) {
	_, out, _, err := run(t, "inventory", "--plan", planFixture, "--json")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var inv struct {
		Format    string `json:"format"`
		Terraform string `json:"terraform_version"`
		Resources []struct {
			Address      string `json:"address"`
			Cloud        string `json:"cloud"`
			Region       string `json:"region"`
			RegionSource string `json:"region_source"`
			Stateful     bool   `json:"stateful"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(out), &inv); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if inv.Format != "plan" || inv.Terraform != "1.9.5" {
		t.Errorf("format = %q, terraform = %q", inv.Format, inv.Terraform)
	}
	if len(inv.Resources) != 11 {
		t.Errorf("resources = %d, want 11", len(inv.Resources))
	}
	// The map must be honest about what it could not determine.
	var undetermined int
	for _, r := range inv.Resources {
		if r.Region == "" {
			if r.RegionSource != "undetermined" {
				t.Errorf("%s: empty region with source %q", r.Address, r.RegionSource)
			}
			undetermined++
		}
	}
	if undetermined == 0 {
		t.Error("fixture should contain at least one resource with no determinable region")
	}
}

func TestRulesetsValidateFlagsStaleResearch(t *testing.T) {
	code, out, _, err := run(t, "rulesets", "validate",
		"--rulesets", staleRules,
		"--max-age-days", "90")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d for an overdue review", code, exitFindings)
	}
	if !strings.Contains(out, "stale") || !strings.Contains(out, "missing-class") {
		t.Errorf("audit output is missing expected problems:\n%s", out)
	}
}

func TestRulesetsValidateJSON(t *testing.T) {
	_, out, _, err := run(t, "rulesets", "validate", "--rulesets", staleRules, "--json")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	var doc struct {
		Jurisdictions []string `json:"jurisdictions"`
		Problems      []struct {
			Kind string `json:"kind"`
		} `json:"problems"`
		Disclaimer string `json:"disclaimer"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, out)
	}
	if len(doc.Jurisdictions) != 1 || doc.Jurisdictions[0] != "ST" {
		t.Errorf("jurisdictions = %v, want [ST]", doc.Jurisdictions)
	}
	if len(doc.Problems) == 0 || doc.Disclaimer == "" {
		t.Errorf("problems = %d, disclaimer = %q", len(doc.Problems), doc.Disclaimer)
	}
}

// An uncited rule anywhere in the directory must stop the run rather than be
// skipped, or the gate would silently narrow.
func TestUncitedRulesetIsALoadError(t *testing.T) {
	code, _, _, err := run(t, "rulesets", "validate", "--rulesets", "../testdata/bad_rulesets")
	if err == nil {
		t.Fatal("expected a load error")
	}
	if !strings.Contains(err.Error(), "source_url is required") {
		t.Errorf("err = %q, want it to explain the missing citation", err)
	}
	if code != exitError {
		t.Errorf("exit = %d, want %d", code, exitError)
	}
}
