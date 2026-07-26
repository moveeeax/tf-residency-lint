package check

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/config"
	"github.com/moveeeax/tf-residency-lint/internal/plan"
	"github.com/moveeeax/tf-residency-lint/internal/ruleset"
)

// now is pinned so that staleness and waiver expiry are deterministic. The
// fixture rules are checked_on 2026-07-20, six days before this.
var now = time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)

func fixtures(t *testing.T, configPath, rulesetsPath string) (plan.Inventory, *config.Config, *ruleset.Set) {
	t.Helper()
	data, err := os.ReadFile("../../testdata/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := plan.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	set, err := ruleset.LoadDir(rulesetsPath)
	if err != nil {
		t.Fatal(err)
	}
	return inv, cfg, set
}

func byAddress(res Result, rule, address, jurisdiction string) *Finding {
	for i := range res.Findings {
		f := res.Findings[i]
		if f.Rule == rule && f.Address == address && (jurisdiction == "" || f.Jurisdiction == jurisdiction) {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestRunAgainstPublishedRuleset(t *testing.T) {
	inv, cfg, set := fixtures(t, "../../testdata/residency.yaml", "../../testdata/rulesets")
	// The fixture config names WM as well, and testdata/rulesets only has EX.
	cfg.Jurisdictions = []string{"EX"}

	res, err := Run(inv, cfg, set, Options{Now: now})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.Scanned != 11 {
		t.Errorf("scanned = %d, want 11", res.Scanned)
	}
	// In scope: customer_docs, core_db cluster, ledger, settlement queue,
	// clinical storage account, analytics bucket, legacy archive. The
	// observability bucket is excluded, the data source and the compute
	// instance are not declared.
	if res.InScope != 7 {
		t.Errorf("in scope = %d, want 7", res.InScope)
	}

	// Personal data in eu-west-1 while EX requires ex-central-1.
	f := byAddress(res, RuleResidencyViolation, "aws_s3_bucket.customer_docs", "EX")
	if f == nil {
		t.Fatal("expected a residency-violation for aws_s3_bucket.customer_docs")
	}
	if f.Severity != Violation {
		t.Errorf("severity = %q, want violation", f.Severity)
	}
	// The citation must travel with the finding — that is the whole deliverable.
	if !strings.HasPrefix(f.SourceURL, "https://example.invalid/") || f.CheckedOn != "2026-07-20" {
		t.Errorf("finding lost its citation: source=%q checked=%q", f.SourceURL, f.CheckedOn)
	}
	if f.DeclaredBy != "customer documents" {
		t.Errorf("declared_by = %q, want %q", f.DeclaredBy, "customer documents")
	}

	// The RDS cluster is already in ex-central-1 (via its AZ list): no finding.
	for _, r := range res.Findings {
		if r.Address == "module.core_db.aws_rds_cluster.primary" {
			t.Errorf("compliant resource produced a finding: %+v", r)
		}
	}

	// Health data with no approved region anywhere is a different finding from
	// "wrong region", and it must carry the in-country alternatives.
	nar := byAddress(res, RuleNoApprovedRegion, "module.clinical.azurerm_storage_account.records", "EX")
	if nar == nil {
		t.Fatal("expected no-approved-region for the clinical storage account")
	}
	if nar.Severity != Violation {
		t.Errorf("severity = %q, want violation", nar.Severity)
	}
	if len(nar.Alternatives) == 0 {
		t.Error("no-approved-region must offer the in-country alternatives")
	}

	// Financial data outside the list is conditional, so a warning plus the
	// mechanism the customer has to satisfy.
	cond := byAddress(res, RuleConditional, "module.payments.aws_dynamodb_table.ledger[0]", "EX")
	if cond == nil {
		t.Fatal("expected conditional-transfer for the ledger table")
	}
	if cond.Severity != Warning || cond.TransferMechanism == "" {
		t.Errorf("conditional finding = %+v, want a warning naming the mechanism", cond)
	}

	// The settlement queue resolved eu-west-1 from the provider block, so it is
	// also outside the list; the finding must say where the region came from.
	q := byAddress(res, RuleConditional, "module.payments.aws_sqs_queue.settlement", "EX")
	if q == nil || q.RegionSource != string(plan.FromProviderConfig) {
		t.Errorf("settlement queue finding = %+v, want region source %q", q, plan.FromProviderConfig)
	}

	// The OCI archive has no determinable region; that is a warning, never a
	// silent pass.
	unk := byAddress(res, RuleUnknownRegion, "module.legacy.oci_objectstorage_bucket.archive", "EX")
	if unk == nil || unk.Severity != Warning {
		t.Errorf("expected an unknown-region warning for the OCI archive, got %+v", unk)
	}

	// The excluded module must produce nothing at all.
	for _, r := range res.Findings {
		if strings.HasPrefix(r.Address, "module.observability.") {
			t.Errorf("excluded module produced a finding: %+v", r)
		}
	}

	if res.Worst() != Violation {
		t.Errorf("Worst = %q, want violation", res.Worst())
	}
}

// government data has must_stay_local: "no" in the fixture, so it must produce
// nothing — "researched, no obligation" has to be distinguishable from "not
// checked".
func TestNoObligationProducesNoFinding(t *testing.T) {
	inv, _, set := fixtures(t, "../../testdata/residency.yaml", "../../testdata/rulesets")
	cfg, err := config.Parse([]byte(`
version: 1
jurisdictions: [EX]
declarations:
  - name: state records
    data_class: government
    match:
      addresses: ["aws_s3_bucket.customer_docs"]
`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(inv, cfg, set, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none", res.Findings)
	}
	if res.InScope != 1 {
		t.Errorf("in scope = %d, want 1", res.InScope)
	}
}

func TestUnclassifiedStatefulResources(t *testing.T) {
	inv, cfg, set := fixtures(t, "../../testdata/residency.yaml", "../../testdata/rulesets")
	cfg.Jurisdictions = []string{"EX"}

	off, err := Run(inv, cfg, set, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if f := byAddress(off, RuleUnclassified, "aws_efs_file_system.scratch", ""); f != nil {
		t.Error("unclassified findings must be opt-in")
	}

	on, err := Run(inv, cfg, set, Options{Now: now, ReportUnclassified: true})
	if err != nil {
		t.Fatal(err)
	}
	f := byAddress(on, RuleUnclassified, "aws_efs_file_system.scratch", "")
	if f == nil || f.Severity != Warning {
		t.Fatalf("expected an unclassified warning for aws_efs_file_system.scratch, got %+v", f)
	}
	// An excluded module is a deliberate decision, not an oversight.
	if byAddress(on, RuleUnclassified, "module.observability.aws_s3_bucket.logs", "") != nil {
		t.Error("explicitly excluded resources must not be reported as unclassified")
	}
	// Compute is not storage.
	if byAddress(on, RuleUnclassified, "module.analytics.google_compute_instance.worker", "") != nil {
		t.Error("a compute instance stores nothing at rest")
	}
}

func TestWaiversSuppressAndExpire(t *testing.T) {
	inv, cfg, set := fixtures(t, "../../testdata/residency_waivers.yaml", "../../testdata/rulesets")

	res, err := Run(inv, cfg, set, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}

	// Live waiver: downgraded to info, carrying the reason and the original rule.
	waived := byAddress(res, RuleWaived, "module.payments.aws_dynamodb_table.ledger[0]", "EX")
	if waived == nil {
		t.Fatal("live waiver should have downgraded the ledger finding")
	}
	if waived.Severity != Info {
		t.Errorf("severity = %q, want info", waived.Severity)
	}
	if waived.WaivedFrom != RuleConditional {
		t.Errorf("waived_from = %q, want %q", waived.WaivedFrom, RuleConditional)
	}
	if !strings.Contains(waived.WaiverReason, "regulator notified") {
		t.Errorf("waiver reason lost: %q", waived.WaiverReason)
	}

	// Expired waiver: the underlying violation stands, and the expiry itself is
	// reported so the pipeline going red has a visible cause.
	if byAddress(res, RuleResidencyViolation, "aws_s3_bucket.customer_docs", "EX") == nil {
		t.Error("an expired waiver must not keep suppressing the violation")
	}
	exp := byAddress(res, RuleExpiredWaiver, "aws_s3_bucket.customer_docs", "EX")
	if exp == nil || !strings.Contains(exp.Message, "2026-01-31") {
		t.Errorf("expected an expired-waiver finding naming the date, got %+v", exp)
	}
	if res.Worst() != Violation {
		t.Errorf("Worst = %q, want violation", res.Worst())
	}
}

func TestStaleRuleIsReportedOncePerClass(t *testing.T) {
	inv, cfg, set := fixtures(t, "../../testdata/residency.yaml", "../../testdata/rulesets")
	cfg.Jurisdictions = []string{"EX"}

	// Six days after the rules were checked, with a five-day tolerance.
	res, err := Run(inv, cfg, set, Options{Now: now, MaxRuleAge: 5 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, f := range res.Findings {
		if f.Rule == RuleStaleRule {
			seen[f.Jurisdiction+"/"+f.DataClass]++
		}
	}
	if len(seen) == 0 {
		t.Fatal("expected stale-rule findings")
	}
	for key, n := range seen {
		if n != 1 {
			t.Errorf("stale rule %s reported %d times, want once", key, n)
		}
	}
	// Personal data covers four resources but must yield exactly one stale note.
	if seen["EX/personal"] != 1 {
		t.Errorf("EX/personal stale findings = %d, want 1", seen["EX/personal"])
	}
}

func TestUnpublishedRulesetsDoNotGateByDefault(t *testing.T) {
	inv, cfg, set := fixtures(t, "../../testdata/residency.yaml", "../../rulesets")

	quiet, err := Run(inv, cfg, set, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range quiet.Findings {
		if f.Severity == Violation {
			t.Errorf("an example ruleset must not produce violations by default: %+v", f)
		}
	}

	loud, err := Run(inv, cfg, set, Options{Now: now, AllowUnpublished: true})
	if err != nil {
		t.Fatal(err)
	}
	if loud.Worst() != Violation {
		t.Error("--allow-unpublished should let the example rulesets gate")
	}
	// Both jurisdictions must be evaluated, not just the first.
	seen := map[string]bool{}
	for _, f := range loud.Findings {
		seen[f.Jurisdiction] = true
	}
	if !seen["EX"] || !seen["WM"] {
		t.Errorf("jurisdictions in findings = %v, want both EX and WM", seen)
	}
}

// A residency.yaml naming a jurisdiction nobody has researched must fail loudly.
// Reporting it as clean is the one outcome that would make the gate worthless.
func TestMissingJurisdictionIsAnError(t *testing.T) {
	inv, _, set := fixtures(t, "../../testdata/residency.yaml", "../../testdata/rulesets")
	cfg, err := config.Parse([]byte(`
version: 1
jurisdictions: [EX, ZZ]
declarations:
  - name: docs
    data_class: personal
    match:
      addresses: ["aws_s3_bucket.customer_docs"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(inv, cfg, set, Options{Now: now}); err == nil {
		t.Fatal("expected an error for a jurisdiction with no ruleset")
	} else if !strings.Contains(err.Error(), "ZZ") {
		t.Errorf("err = %q, want it to name ZZ", err)
	}
}

func TestMissingRuleForDataClass(t *testing.T) {
	inv, _, set := fixtures(t, "../../testdata/residency.yaml", "../../rulesets")
	cfg, err := config.Parse([]byte(`
version: 1
jurisdictions: [WM]
declarations:
  - name: clinical
    data_class: health
    match:
      addresses: ["module.clinical.*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(inv, cfg, set, Options{Now: now, AllowUnpublished: true})
	if err != nil {
		t.Fatal(err)
	}
	f := byAddress(res, RuleMissingRule, "module.clinical.azurerm_storage_account.records", "WM")
	if f == nil || f.Severity != Warning {
		t.Fatalf("expected a missing-rule warning, got %+v", f)
	}
}

func TestSeverityGate(t *testing.T) {
	if !Violation.AtLeast(Warning) {
		t.Error("violation is at least a warning")
	}
	if Warning.AtLeast(Violation) {
		t.Error("a warning is not a violation")
	}
	if !Info.AtLeast(Info) {
		t.Error("info is at least info")
	}
	if _, ok := ParseSeverity("Violation"); !ok {
		t.Error("--fail-on should be case-insensitive")
	}
	if _, ok := ParseSeverity("critical"); ok {
		t.Error("critical is not a severity")
	}
}

func TestFindingsAreSortedBySeverity(t *testing.T) {
	inv, cfg, set := fixtures(t, "../../testdata/residency.yaml", "../../rulesets")
	res, err := Run(inv, cfg, set, Options{Now: now, AllowUnpublished: true, ReportUnclassified: true})
	if err != nil {
		t.Fatal(err)
	}
	rank := map[Severity]int{Violation: 2, Warning: 1, Info: 0}
	for i := 1; i < len(res.Findings); i++ {
		if rank[res.Findings[i-1].Severity] < rank[res.Findings[i].Severity] {
			t.Fatalf("findings not sorted by severity at %d: %q then %q",
				i, res.Findings[i-1].Severity, res.Findings[i].Severity)
		}
	}
}
