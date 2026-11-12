package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/plan"
)

var now = time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)

func loadChanges(t *testing.T) []Change {
	t.Helper()
	data, err := os.ReadFile("../../testdata/policy/plan.json")
	if err != nil {
		t.Fatal(err)
	}
	tf, changes, err := ParseChanges(data)
	if err != nil {
		t.Fatalf("ParseChanges: %v", err)
	}
	if tf != "1.9.5" {
		t.Errorf("terraform = %q, want 1.9.5", tf)
	}
	return changes
}

// starter runs the shipped starter rules plus the fixture exemptions.
func starter(t *testing.T) Result {
	t.Helper()
	set, err := Load([]string{"../../policies", "../../testdata/policy/exemptions.yaml"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, changes, err := ParseChanges(mustRead(t, "../../testdata/policy/plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	return Run("1.9.5", changes, set, now)
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func findingsFor(res Result, rule, address string) []Finding {
	var out []Finding
	for _, f := range res.Findings {
		if f.Rule == rule && f.Address == address {
			out = append(out, f)
		}
	}
	return out
}

func one(t *testing.T, res Result, rule, address string) Finding {
	t.Helper()
	fs := findingsFor(res, rule, address)
	if len(fs) != 1 {
		t.Fatalf("%s on %s: got %d findings, want 1: %+v", rule, address, len(fs), res.Findings)
	}
	return fs[0]
}

func none(t *testing.T, res Result, rule, address string) {
	t.Helper()
	if fs := findingsFor(res, rule, address); len(fs) != 0 {
		t.Errorf("%s on %s: want no finding, got %+v", rule, address, fs)
	}
}

func TestParseChangesActions(t *testing.T) {
	changes := loadChanges(t)
	if len(changes) != 13 {
		t.Fatalf("got %d changes, want 13", len(changes))
	}
	byAddr := map[string]Change{}
	for _, c := range changes {
		byAddr[c.Address] = c
	}
	db := byAddr["module.db.aws_db_instance.main"]
	if !db.Has(Replace) || !db.Has(Delete) || !db.Has(Create) || db.Has(Update) {
		t.Errorf("delete+create should count as replace, delete and create: %v", db.Actions)
	}
	if db.ActionLabel() != "replace" {
		t.Errorf("ActionLabel = %q, want replace", db.ActionLabel())
	}
	if c := byAddr["aws_ebs_volume.cache"]; c.Has(Replace) || !c.Has(Create) {
		t.Errorf("create alone is not a replace: %v", c.Actions)
	}
	if c := byAddr["data.aws_caller_identity.current"]; c.Mode != "data" || !c.Has(Read) {
		t.Errorf("data source = %+v", c)
	}
}

// A destroy rule must read the tags the resource has now, not the absent
// planned object.
func TestDestroyReadsPriorStateTags(t *testing.T) {
	changes := loadChanges(t)
	for _, c := range changes {
		if c.Address == "aws_s3_bucket.audit" {
			if c.Tags()["protected"] != "true" {
				t.Errorf("tags = %v, want protected=true from before", c.Tags())
			}
			return
		}
	}
	t.Fatal("aws_s3_bucket.audit not found")
}

func TestParseChangesRejectsStateAndNonTerraform(t *testing.T) {
	if _, _, err := ParseChanges(mustRead(t, "../../testdata/state.json")); !errors.Is(err, ErrNotPlan) {
		t.Errorf("state document: err = %v, want ErrNotPlan", err)
	}
	if _, _, err := ParseChanges([]byte(`{"hello":"world"}`)); !errors.Is(err, plan.ErrNotTerraformJSON) {
		t.Errorf("arbitrary json: err = %v, want ErrNotTerraformJSON", err)
	}
	if _, _, err := ParseChanges([]byte(`not json`)); err == nil {
		t.Error("garbage should not parse")
	}
	// An action this engine does not know might be a destroy; stop instead.
	future := `{"format_version":"1.2","planned_values":{"root_module":{}},
	  "resource_changes":[{"address":"a.b","type":"a","change":{"actions":["obliterate"]}}]}`
	if _, _, err := ParseChanges([]byte(future)); err == nil || !strings.Contains(err.Error(), "obliterate") {
		t.Errorf("unknown action: err = %v", err)
	}
	// A plan with no changes is valid and empty.
	_, changes, err := ParseChanges([]byte(`{"format_version":"1.2","planned_values":{"root_module":{}}}`))
	if err != nil || len(changes) != 0 {
		t.Errorf("empty plan: %v, %d changes", err, len(changes))
	}
}

func TestStarterRulesOnFixturePlan(t *testing.T) {
	res := starter(t)

	// protected-destroy: delete and replace of tagged resources.
	if f := one(t, res, "protected-destroy", "aws_s3_bucket.audit"); f.Severity != check.Violation || f.Action != "delete" {
		t.Errorf("audit bucket = %+v", f)
	}
	if f := one(t, res, "protected-destroy", "module.db.aws_db_instance.main"); f.Action != "replace" {
		t.Errorf("replace should be reported as such: %+v", f)
	}
	none(t, res, "protected-destroy", "aws_s3_bucket.tmp")

	// Encryption: definite failure, undetermined, pass.
	if f := one(t, res, "rds-storage-encrypted", "module.db.aws_db_instance.main"); f.Severity != check.Violation ||
		len(f.Failed) != 1 || f.Failed[0] != "storage_encrypted equals true" {
		t.Errorf("rds = %+v", f)
	}
	cache := one(t, res, "ebs-volume-encrypted", "aws_ebs_volume.cache")
	if cache.Severity != check.Warning || !cache.Undetermined() || cache.Unknown[0] != "encrypted" {
		t.Errorf("unknown encryption must be an undetermined warning, got %+v", cache)
	}
	none(t, res, "ebs-volume-encrypted", "aws_ebs_volume.data")
	if f := one(t, res, "opensearch-encrypted", "aws_opensearch_domain.search"); f.Severity != check.Violation {
		t.Errorf("a missing encrypt_at_rest block is a failure: %+v", f)
	}

	// Public exposure.
	pab := one(t, res, "s3-public-access-block", "aws_s3_bucket_public_access_block.site")
	if strings.Join(pab.Failed, ";") != "block_public_policy equals true;restrict_public_buckets equals true" {
		t.Errorf("failed conditions = %v", pab.Failed)
	}
	one(t, res, "rds-not-public", "module.db.aws_db_instance.main")
	if f := one(t, res, "azure-storage-no-public-blobs", "azurerm_storage_account.files"); f.Action != "update" {
		t.Errorf("azure = %+v", f)
	}
	if f := one(t, res, "gcs-public-access-prevention", "google_storage_bucket.assets"); f.Severity != check.Warning {
		t.Errorf("warn rules produce warnings: %+v", f)
	}

	counts := res.Counts()
	if counts[check.Violation] != 8 || counts[check.Warning] != 2 || counts[check.Info] != 1 {
		t.Errorf("counts = %v, want 8 violations, 2 warnings, 1 info", counts)
	}
}

func TestExemptions(t *testing.T) {
	res := starter(t)
	live := one(t, res, "protected-destroy", "aws_s3_bucket.old_logs")
	if live.Severity != check.Info || !live.Exempted || !strings.Contains(live.ExemptionReason, "TICKET-123") {
		t.Errorf("live exemption = %+v", live)
	}
	expired := one(t, res, "protected-destroy", "aws_s3_bucket.reports")
	if expired.Severity != check.Violation || expired.Exempted || !strings.Contains(expired.Message, "expired on 2026-01-31") {
		t.Errorf("an expired exemption must not suppress: %+v", expired)
	}
}

// Plan JSON carries passwords and keys in clear. Findings may name attribute
// paths but never values.
func TestFindingsCarryNoPlanValues(t *testing.T) {
	res := starter(t)
	blob := fmt.Sprintf("%#v", res.Findings)
	for _, secret := range []string{"hunter2", "REDACTED-BUT-PRESENT", "acme-audit", "inherited"} {
		if strings.Contains(blob, secret) {
			t.Errorf("findings leak %q", secret)
		}
	}
}

func TestEvaluatedListsPasses(t *testing.T) {
	res := starter(t)
	found := false
	for _, e := range res.Evaluated {
		if e.Rule == "ebs-volume-encrypted" && e.Address == "aws_ebs_volume.data" {
			found = true
		}
		if e.Address == "aws_instance.web" || e.Address == "data.aws_caller_identity.current" {
			t.Errorf("no starter rule selects %s", e.Address)
		}
	}
	if !found {
		t.Error("a passing (rule, change) pair should be in Evaluated")
	}
}

func rule(t *testing.T, yaml string) *Set {
	t.Helper()
	f, err := Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return &Set{Rules: f.Rules, Exemptions: f.Exemptions}
}

func change(actions []Action, before, after map[string]any, unknown any) Change {
	return Change{Address: "x_thing.this", Type: "x_thing", Mode: "managed", Actions: actions,
		before: before, after: after, afterUnknown: unknown}
}

func TestOperators(t *testing.T) {
	after := map[string]any{
		"name": "a", "size": float64(10), "flag": false,
		"rules": []any{map[string]any{"port": float64(22)}, map[string]any{"port": float64(443)}},
	}
	cases := []struct {
		cond string
		want bool // true = passes
	}{
		{"{path: name, exists: true}", true},
		{"{path: missing, exists: false}", true},
		{"{path: missing, exists: true}", false},
		{"{path: size, equals: 10}", true},
		{"{path: flag, equals: false}", true},
		{"{path: missing, equals: false}", false},
		{"{path: name, not_equals: b}", true},
		{"{path: missing, not_equals: true}", true},
		{"{path: name, in: [a, b]}", true},
		{"{path: name, not_in: [a]}", false},
		{"{path: rules.0.port, equals: 22}", true},
		{"{path: rules.5.port, exists: false}", true},
		{"{path: rules.*.port, not_in: [22, 3389]}", false},
		{"{path: rules.*.port, in: [22, 443]}", true},
	}
	for _, c := range cases {
		set := rule(t, "version: 1\nrules:\n  - id: r\n    description: d\n    severity: deny\n    match: {actions: [create]}\n    require:\n      - "+c.cond+"\n")
		res := Run("", []Change{change([]Action{Create}, nil, after, map[string]any{})}, set, now)
		if passed := len(res.Findings) == 0; passed != c.want {
			t.Errorf("%s: passed = %v, want %v", c.cond, passed, c.want)
		}
	}
}

func TestUnknownValues(t *testing.T) {
	set := rule(t, `version: 1
rules:
  - id: enc
    description: must be encrypted
    severity: deny
    match:
      actions: [create]
      tags: {tier: prod}
    require:
      - path: settings.*.encrypted
        equals: true
`)
	known := map[string]any{"tags": map[string]any{"tier": "prod"}}

	// The whole block is unknown.
	res := Run("", []Change{change([]Action{Create}, nil, known, map[string]any{"settings": true})}, set, now)
	if len(res.Findings) != 1 || !res.Findings[0].Undetermined() || res.Findings[0].Severity != check.Warning {
		t.Errorf("unknown require: %+v", res.Findings)
	}

	// The tag is unknown and the requirement fails: cannot tell if the rule applies.
	after := map[string]any{"settings": []any{map[string]any{"encrypted": false}}}
	res = Run("", []Change{change([]Action{Create}, nil, after, map[string]any{"tags": true})}, set, now)
	if len(res.Findings) != 1 || res.Findings[0].Unknown[0] != "tags.tier" || res.Findings[0].Severity != check.Warning {
		t.Errorf("unknown selector: %+v", res.Findings)
	}

	// The tag is unknown but the requirement holds: a pass either way.
	after = map[string]any{"settings": []any{map[string]any{"encrypted": true}}}
	res = Run("", []Change{change([]Action{Create}, nil, after, map[string]any{"tags": true})}, set, now)
	if len(res.Findings) != 0 {
		t.Errorf("requirement met, want no finding: %+v", res.Findings)
	}

	// A different tag value: the rule does not apply.
	other := map[string]any{"tags": map[string]any{"tier": "dev"}}
	res = Run("", []Change{change([]Action{Create}, nil, other, map[string]any{})}, set, now)
	if len(res.Findings) != 0 || len(res.Evaluated) != 0 {
		t.Errorf("rule should not select a dev resource: %+v", res)
	}
}

func TestMatchFilters(t *testing.T) {
	set := rule(t, `version: 1
rules:
  - id: r
    description: d
    severity: warn
    match:
      actions: [delete]
      resource_types: ["x_*"]
      addresses: ["module.keep.*"]
      tags: {owner: "*"}
`)
	c := change([]Action{Delete}, map[string]any{"labels": map[string]any{"owner": "anyone"}}, nil, nil)
	c.Address = "module.keep.x_thing.this[0]"
	if res := Run("", []Change{c}, set, now); len(res.Findings) != 1 || res.Findings[0].Severity != check.Warning {
		t.Errorf("all filters match: %+v", res.Findings)
	}
	c.Address = "module.other.x_thing.this"
	if res := Run("", []Change{c}, set, now); len(res.Findings) != 0 {
		t.Errorf("address filter should exclude: %+v", res.Findings)
	}
	c.Address = "module.keep.x_thing.this"
	c.Actions = []Action{Update}
	if res := Run("", []Change{c}, set, now); len(res.Findings) != 0 {
		t.Errorf("action filter should exclude: %+v", res.Findings)
	}
}

func TestRuleValidation(t *testing.T) {
	head := "version: 1\nrules:\n  - id: r\n    description: d\n    severity: deny\n"
	cases := map[string]string{
		"no actions":         head + "    match: {resource_types: [x]}\n",
		"bad action":         head + "    match: {actions: [destroy]}\n",
		"bad severity":       strings.Replace(head, "deny", "block", 1) + "    match: {actions: [create]}\n",
		"no description":     strings.Replace(head, "description: d", "description: ''", 1) + "    match: {actions: [create]}\n",
		"typo key":           head + "    match: {actions: [create], resource_type: [x]}\n",
		"two operators":      head + "    match: {actions: [create]}\n    require: [{path: a, equals: 1, exists: true}]\n",
		"no operator":        head + "    match: {actions: [create]}\n    require: [{path: a}]\n",
		"unknown operator":   head + "    match: {actions: [create]}\n    require: [{path: a, matches: x}]\n",
		"in needs list":      head + "    match: {actions: [create]}\n    require: [{path: a, in: x}]\n",
		"bad id":             strings.Replace(head, "id: r", "id: Bad Id", 1) + "    match: {actions: [create]}\n",
		"wrong version":      strings.Replace(head, "version: 1", "version: 2", 1) + "    match: {actions: [create]}\n",
		"exemption reason":   "version: 1\nexemptions: [{rule: r, address: a.b, expires_on: '2027-01-01'}]\n",
		"exemption expiry":   "version: 1\nexemptions: [{rule: r, address: a.b, reason: why}]\n",
		"exemption bad date": "version: 1\nexemptions: [{rule: r, address: a.b, reason: why, expires_on: soon}]\n",
	}
	for name, body := range cases {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: expected a validation error", name)
		}
	}
}

func TestLoadCrossFileChecks(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := dir + "/" + name
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a.yaml", "version: 1\nrules:\n  - id: r\n    description: d\n    severity: deny\n    match: {actions: [delete]}\n")
	b := write("b.yaml", "version: 1\nrules:\n  - id: r\n    description: d\n    severity: warn\n    match: {actions: [delete]}\n")
	if _, err := Load([]string{a, b}); err == nil || !strings.Contains(err.Error(), "defined twice") {
		t.Errorf("duplicate id across files: err = %v", err)
	}
	ex := write("ex.yml", "version: 1\nexemptions: [{rule: nope, address: a.b, reason: why, expires_on: '2027-01-01'}]\n")
	if _, err := Load([]string{a, ex}); err == nil || !strings.Contains(err.Error(), `rule "nope"`) {
		t.Errorf("exemption for an unknown rule: err = %v", err)
	}
	if _, err := Load([]string{ex}); err == nil {
		t.Error("exemptions alone are not a rule set")
	}
	if _, err := Load(nil); err == nil {
		t.Error("no paths should be an error")
	}
	set, err := Load([]string{a})
	if err != nil {
		t.Fatal(err)
	}
	if r := set.Rules[0]; r.Path != a || r.Line != 3 {
		t.Errorf("rule location = %s:%d, want %s:3", r.Path, r.Line, a)
	}
}
