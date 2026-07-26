package plan

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, name string) Inventory {
	t.Helper()
	data, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return inv
}

func find(t *testing.T, inv Inventory, address string) Resource {
	t.Helper()
	for _, r := range inv.Resources {
		if r.Address == address {
			return r
		}
	}
	t.Fatalf("resource %q not found in inventory", address)
	return Resource{}
}

func TestParsePlanWalksNestedModules(t *testing.T) {
	inv := load(t, "plan.json")
	if inv.Format != "plan" {
		t.Errorf("Format = %q, want plan", inv.Format)
	}
	if inv.Terraform != "1.9.5" {
		t.Errorf("Terraform = %q, want 1.9.5", inv.Terraform)
	}
	// 3 root (one of them a data source) + 8 across the child modules.
	if len(inv.Resources) != 11 {
		var got []string
		for _, r := range inv.Resources {
			got = append(got, r.Address)
		}
		t.Fatalf("got %d resources, want 11: %v", len(inv.Resources), got)
	}
	if inv.Resources[0].Address != "aws_efs_file_system.scratch" {
		t.Errorf("inventory is not sorted by address, first = %q", inv.Resources[0].Address)
	}
}

func TestRegionResolution(t *testing.T) {
	inv := load(t, "plan.json")
	cases := []struct {
		address string
		cloud   Cloud
		region  string
		source  RegionSource
	}{
		// Explicit resource attribute wins.
		{"aws_s3_bucket.customer_docs", AWS, "eu-west-1", FromAttribute},
		{"module.payments.aws_dynamodb_table.ledger[0]", AWS, "us-east-1", FromAttribute},
		// Azure spells it `location` and uses display casing.
		{"module.clinical.azurerm_storage_account.records", Azure, "westeurope", FromLocation},
		// A multi-region GCP location is carried through verbatim, lowercased.
		{"module.analytics.google_storage_bucket.events", GCP, "eu", FromLocation},
		// AZ list on an RDS cluster collapses to its region.
		{"module.core_db.aws_rds_cluster.primary", AWS, "ex-central-1", FromAvailabilityZone},
		// No attribute at all: fall back to the provider block.
		{"module.payments.aws_sqs_queue.settlement", AWS, "eu-west-1", FromProviderConfig},
		// No attribute and no provider config for OCI: honestly undetermined.
		{"module.legacy.oci_objectstorage_bucket.archive", OCI, "", FromNone},
	}
	for _, c := range cases {
		r := find(t, inv, c.address)
		if r.Cloud != c.cloud {
			t.Errorf("%s: cloud = %q, want %q", c.address, r.Cloud, c.cloud)
		}
		if r.Region != c.region {
			t.Errorf("%s: region = %q, want %q", c.address, r.Region, c.region)
		}
		if r.RegionSource != c.source {
			t.Errorf("%s: region source = %q, want %q", c.address, r.RegionSource, c.source)
		}
	}
}

func TestStatefulClassification(t *testing.T) {
	inv := load(t, "plan.json")
	stateful := inv.Stateful()
	got := map[string]bool{}
	for _, r := range stateful {
		got[r.Address] = true
	}
	for _, want := range []string{
		"aws_s3_bucket.customer_docs",
		"aws_efs_file_system.scratch",
		"module.core_db.aws_rds_cluster.primary",
		"module.payments.aws_dynamodb_table.ledger[0]",
		"module.payments.aws_sqs_queue.settlement",
		"module.clinical.azurerm_storage_account.records",
		"module.analytics.google_storage_bucket.events",
		"module.legacy.oci_objectstorage_bucket.archive",
		"module.observability.aws_s3_bucket.logs",
	} {
		if !got[want] {
			t.Errorf("%s should be stateful", want)
		}
	}
	// Compute is not storage, and a data source stores nothing.
	for _, notWant := range []string{
		"module.analytics.google_compute_instance.worker",
		"data.aws_caller_identity.current",
	} {
		if got[notWant] {
			t.Errorf("%s should not be stateful", notWant)
		}
	}
}

func TestTagsAreCollectedPerProvider(t *testing.T) {
	inv := load(t, "plan.json")
	cases := map[string]map[string]string{
		// tags and tags_all merge; tags_all adds the provider default.
		"aws_s3_bucket.customer_docs":                    {"data-class": "personal", "owner": "platform"},
		"module.analytics.google_storage_bucket.events":  {"data-class": "personal"},
		"module.legacy.oci_objectstorage_bucket.archive": {"data-class": "personal"},
	}
	for addr, want := range cases {
		r := find(t, inv, addr)
		for k, v := range want {
			if r.Tags[k] != v {
				t.Errorf("%s: tag %q = %q, want %q", addr, k, r.Tags[k], v)
			}
		}
	}
}

// The parser reads attribute values to find a region and must then drop them.
// A residency report gets pasted into tickets; a password reaching one would be
// a far worse incident than the residency finding it accompanies.
func TestParseDropsAttributeValues(t *testing.T) {
	inv := load(t, "plan.json")
	blob := fmt.Sprintf("%#v", inv)
	for _, secret := range []string{"hunter2", "master_password", "primary_access_key", "REDACTED-BUT-PRESENT"} {
		if strings.Contains(blob, secret) {
			t.Errorf("inventory leaks %q", secret)
		}
	}
}

func TestParseStateDocument(t *testing.T) {
	inv := load(t, "state.json")
	if inv.Format != "state" {
		t.Errorf("Format = %q, want state", inv.Format)
	}
	r := find(t, inv, "azurerm_storage_account.records")
	if r.Region != "westeurope" {
		t.Errorf("region = %q, want westeurope", r.Region)
	}
	// A bare availability zone with no provider config still yields a region.
	v := find(t, inv, "aws_ebs_volume.cache")
	if v.Region != "ap-southeast-3" || v.RegionSource != FromAvailabilityZone {
		t.Errorf("ebs volume = %q from %q, want ap-southeast-3 from availability zone", v.Region, v.RegionSource)
	}
}

// Reporting "nothing in scope" for a file that is not a plan would be a silent
// false green in CI, which is the one failure mode this tool cannot have.
func TestParseRejectsNonTerraformJSON(t *testing.T) {
	cases := map[string]string{
		"empty object":   `{}`,
		"arbitrary json": `{"hello":"world"}`,
		"plan var file":  `{"region":"eu-west-1"}`,
		"format only":    `{"format_version":"1.2"}`,
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); !errors.Is(err, ErrNotTerraformJSON) {
			t.Errorf("%s: err = %v, want ErrNotTerraformJSON", name, err)
		}
	}
	// Shapes that cannot even unmarshal must error too, just not with the
	// sentinel: what matters is that nothing reports an empty estate.
	for _, body := range []string{`[]`, `"a string"`, `not json at all`} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("Parse(%s) should error", body)
		}
	}
}

func TestNormalizeRegionFoldsProviderSpellings(t *testing.T) {
	for _, in := range []string{"West Europe", "westeurope", "WestEurope", " WEST EUROPE "} {
		if got := NormalizeRegion(in); got != "westeurope" {
			t.Errorf("NormalizeRegion(%q) = %q, want westeurope", in, got)
		}
	}
}

func TestNormalizeAddressStripsIndices(t *testing.T) {
	cases := map[string]string{
		"module.app.aws_instance.worker[0]":             "module.app.aws_instance.worker",
		`module.s.aws_s3_bucket.this["eu-west-1|main"]`: "module.s.aws_s3_bucket.this",
		"aws_s3_bucket.plain":                           "aws_s3_bucket.plain",
	}
	for in, want := range cases {
		if got := NormalizeAddress(in); got != want {
			t.Errorf("NormalizeAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
