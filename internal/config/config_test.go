package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadFixture(t *testing.T) {
	cfg, err := Load("../../testdata/residency.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Jurisdictions) != 2 || cfg.Jurisdictions[0] != "EX" {
		t.Errorf("jurisdictions = %v, want [EX WM]", cfg.Jurisdictions)
	}
	if cfg.DefaultClass != "none" {
		t.Errorf("default_class = %q, want none", cfg.DefaultClass)
	}
	if len(cfg.Declarations) != 6 {
		t.Errorf("declarations = %d, want 6", len(cfg.Declarations))
	}
}

func TestClassifyMatchesAddressTypeAndTag(t *testing.T) {
	cfg, err := Load("../../testdata/residency.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		address      string
		resourceType string
		tags         map[string]string
		want         DataClass
		by           string
	}{
		{"exact address", "aws_s3_bucket.customer_docs", "aws_s3_bucket", nil, Personal, "customer documents"},
		{"module subtree", "module.core_db.aws_rds_cluster.primary", "aws_rds_cluster", nil, Personal, "core customer database"},
		{"module subtree with index", "module.clinical.azurerm_storage_account.records[0]", "azurerm_storage_account", nil, Health, "clinical records"},
		{"tag", "module.payments.aws_sqs_queue.settlement", "aws_sqs_queue", map[string]string{"data-class": "financial"}, Financial, "payments and settlement"},
		{"tag value is case-insensitive", "module.x.aws_sqs_queue.q", "aws_sqs_queue", map[string]string{"data-class": "Financial"}, Financial, "payments and settlement"},
		{"resource type", "module.analytics.google_storage_bucket.events", "google_storage_bucket", nil, Personal, "product analytics"},
		{"nothing matches", "module.other.aws_instance.web", "aws_instance", nil, None, "default_class"},
		// A prefix that is not a path boundary must not match: "module.core_db*"
		// is not declared, so a differently named module stays out of scope.
		{"near-miss module name", "module.core_db_replica.aws_rds_cluster.r", "aws_rds_cluster", nil, None, "default_class"},
	}
	for _, c := range cases {
		got, by := cfg.Classify(c.address, c.resourceType, c.tags)
		if got != c.want || by != c.by {
			t.Errorf("%s: Classify(%s) = %s via %q, want %s via %q", c.name, c.address, got, by, c.want, c.by)
		}
	}
}

func TestExclusions(t *testing.T) {
	cfg, err := Load("../../testdata/residency.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Excluded("module.observability.aws_s3_bucket.logs") {
		t.Error("observability module should be excluded")
	}
	if cfg.Excluded("module.core_db.aws_rds_cluster.primary") {
		t.Error("core_db must not be excluded")
	}
}

func TestWaiverCoverageAndExpiry(t *testing.T) {
	cfg, err := Load("../../testdata/residency_waivers.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Waivers) != 2 {
		t.Fatalf("waivers = %d, want 2", len(cfg.Waivers))
	}
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)

	live := cfg.Waivers[0]
	if !live.Covers("module.payments.aws_dynamodb_table.ledger[0]", "EX") {
		t.Error("live waiver should cover the indexed ledger table in EX")
	}
	if live.Covers("module.payments.aws_dynamodb_table.ledger[0]", "WM") {
		t.Error("a waiver scoped to EX must not cover WM")
	}
	if live.Expired(now) {
		t.Error("waiver expiring 2026-12-31 is not expired on 2026-07-26")
	}

	expired := cfg.Waivers[1]
	if !expired.Covers("aws_s3_bucket.customer_docs", "WM") {
		t.Error("jurisdiction \"*\" should cover any jurisdiction")
	}
	if !expired.Expired(now) {
		t.Error("waiver expiring 2026-01-31 is expired on 2026-07-26")
	}
}

func TestParseRejectsBadConfigs(t *testing.T) {
	cases := map[string]struct{ body, wantErr string }{
		"wrong version": {`
version: 2
jurisdictions: [EX]
declarations:
  - name: a
    data_class: personal
    match: {resource_types: [aws_s3_bucket]}
`, "version must be 1"},

		"no jurisdictions": {`
version: 1
jurisdictions: []
declarations:
  - name: a
    data_class: personal
    match: {resource_types: [aws_s3_bucket]}
`, "at least one jurisdiction"},

		"no declarations": {`
version: 1
jurisdictions: [EX]
declarations: []
`, "at least one declaration"},

		"unknown data class": {`
version: 1
jurisdictions: [EX]
declarations:
  - name: a
    data_class: telemetry
    match: {resource_types: [aws_s3_bucket]}
`, "is not known"},

		"empty match": {`
version: 1
jurisdictions: [EX]
declarations:
  - name: a
    data_class: personal
    match: {}
`, "match must set at least one"},

		// A typo'd key silently dropping a declaration would be a false green.
		"unknown key": {`
version: 1
jurisdictions: [EX]
declarations:
  - name: a
    data_class: personal
    matches: {resource_types: [aws_s3_bucket]}
`, "field matches not found"},

		"waiver without reason": {`
version: 1
jurisdictions: [EX]
declarations:
  - name: a
    data_class: personal
    match: {resource_types: [aws_s3_bucket]}
waivers:
  - address: "aws_s3_bucket.x"
    expires_on: "2030-01-01"
`, "reason is required"},

		"waiver without expiry": {`
version: 1
jurisdictions: [EX]
declarations:
  - name: a
    data_class: personal
    match: {resource_types: [aws_s3_bucket]}
waivers:
  - address: "aws_s3_bucket.x"
    reason: "because"
`, "expires_on is required"},

		"duplicate jurisdiction": {`
version: 1
jurisdictions: [EX, ex]
declarations:
  - name: a
    data_class: personal
    match: {resource_types: [aws_s3_bucket]}
`, "listed twice"},
	}

	for name, c := range cases {
		_, err := Parse([]byte(c.body))
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%s: err = %q, want it to contain %q", name, err, c.wantErr)
		}
	}
}

func TestDataClassAliases(t *testing.T) {
	for in, want := range map[string]DataClass{
		"PII": Personal, "phi": Health, "Payment": Financial, "state": Government, "none": None,
	} {
		got, ok := ParseDataClass(in)
		if !ok || got != want {
			t.Errorf("ParseDataClass(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if _, ok := ParseDataClass("telemetry"); ok {
		t.Error("telemetry must not parse as a data class")
	}
}

func TestDeclarationLines(t *testing.T) {
	cfg, err := Load("../../testdata/residency.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Lines of the "- name:" entries in testdata/residency.yaml.
	for name, want := range map[string]int{"customer documents": 14, "legacy archive": 44} {
		if got := cfg.DeclarationLine(name); got != want {
			t.Errorf("DeclarationLine(%q) = %d, want %d", name, got, want)
		}
	}
	if got := cfg.DeclarationLine("default_class"); got != 0 {
		t.Errorf("unknown declaration line = %d, want 0", got)
	}
}
