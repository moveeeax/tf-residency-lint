package ruleset

import (
	"strings"
	"testing"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/plan"
)

func TestLoadShippedExampleRulesets(t *testing.T) {
	set, err := LoadDir("../../rulesets")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	got := set.Jurisdictions()
	if len(got) != 2 || got[0] != "EX" || got[1] != "WM" {
		t.Fatalf("jurisdictions = %v, want [EX WM]", got)
	}
	// Everything shipped in rulesets/ today is fictional. If a real
	// jurisdiction is ever added it must be marked published deliberately, and
	// this assertion is where that decision surfaces.
	for _, code := range got {
		rs, _ := set.Get(code)
		if rs.Status != StatusExample {
			t.Errorf("%s: status = %q, want example until real research lands", code, rs.Status)
		}
	}
}

func TestLookupAndRegionMatching(t *testing.T) {
	set, err := LoadDir("../../testdata/rulesets")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	_, entry, ok := set.Lookup("ex", "personal")
	if !ok || entry == nil {
		t.Fatal("EX/personal should resolve, and the code should be case-insensitive")
	}
	if entry.MustStayLocal != MustStayYes {
		t.Errorf("must_stay_local = %q, want yes", entry.MustStayLocal)
	}

	allowed, haveList := entry.RegionAllowed(plan.AWS, "ex-central-1")
	if !allowed || !haveList {
		t.Error("ex-central-1 should be allowed for aws")
	}
	// Region comparison folds the same way the plan parser folds regions.
	if allowed, _ := entry.RegionAllowed(plan.Azure, "Examplestan Central"); !allowed {
		t.Error("azure region should match regardless of casing and spaces")
	}
	if allowed, haveList := entry.RegionAllowed(plan.AWS, "us-east-1"); allowed || !haveList {
		t.Error("us-east-1 is not allowed, but aws does have an approved list")
	}

	// health lists no cloud at all: "no approved region exists" is a different
	// answer from "you picked the wrong one".
	_, health, _ := set.Lookup("EX", "health")
	if allowed, haveList := health.RegionAllowed(plan.AWS, "ex-central-1"); allowed || haveList {
		t.Error("EX/health should report no approved aws region list")
	}

	if _, _, ok := set.Lookup("EX", "telemetry"); ok {
		t.Error("an undeclared data class must not resolve")
	}
	if _, _, ok := set.Lookup("ZZ", "personal"); ok {
		t.Error("an unloaded jurisdiction must not resolve")
	}
}

func TestValidateReportsStalenessAndCoverage(t *testing.T) {
	set, err := LoadDir("../../testdata/rulesets_stale")
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	problems := set.Validate(now, 90*24*time.Hour, []string{"financial", "government", "health", "personal"})

	kinds := map[string][]string{}
	for _, p := range problems {
		kinds[p.Kind] = append(kinds[p.Kind], p.DataClass)
	}
	if len(kinds["stale"]) != 1 || kinds["stale"][0] != "personal" {
		t.Errorf("stale = %v, want [personal]", kinds["stale"])
	}
	// financial was checked recently, so it must not be flagged stale.
	for _, cls := range kinds["stale"] {
		if cls == "financial" {
			t.Error("financial was checked on 2026-07-20 and is not stale")
		}
	}
	if len(kinds["missing-class"]) != 2 {
		t.Errorf("missing-class = %v, want two entries (government, health)", kinds["missing-class"])
	}
	if len(kinds["not-published"]) != 0 {
		t.Errorf("not-published = %v, want none", kinds["not-published"])
	}
}

func TestValidateFlagsUnpublishedRulesets(t *testing.T) {
	set, err := LoadDir("../../rulesets")
	if err != nil {
		t.Fatal(err)
	}
	problems := set.Validate(time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC), 90*24*time.Hour, nil)
	n := 0
	for _, p := range problems {
		if p.Kind == "not-published" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("not-published problems = %d, want 2 (both example rulesets)", n)
	}
}

// The load-time invariants are the product. If any of these stop failing, the
// tool can ship an assertion about the law that nobody can trace to a source.
func TestParseRejectsUncitedAndMalformedRules(t *testing.T) {
	cases := map[string]struct{ body, wantErr string }{
		"missing source_url": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    checked_on: "2026-07-20"
`, "source_url is required"},

		"relative source_url": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    source_url: "personal-data-act.pdf"
    checked_on: "2026-07-20"
`, "must be an absolute URL"},

		"missing checked_on": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    source_url: "https://example.invalid/a"
`, "checked_on is required"},

		"unparseable checked_on": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    source_url: "https://example.invalid/a"
    checked_on: "July 2026"
`, "checked_on must be YYYY-MM-DD"},

		"bad obligation": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: probably
    source_url: "https://example.invalid/a"
    checked_on: "2026-07-20"
`, "must be yes, no or conditional"},

		"conditional without mechanism": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: conditional
    source_url: "https://example.invalid/a"
    checked_on: "2026-07-20"
`, "transfer_mechanism must name the condition"},

		"unknown cloud": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    allowed_regions:
      alibaba: ["cn-hangzhou"]
    source_url: "https://example.invalid/a"
    checked_on: "2026-07-20"
`, "unknown cloud"},

		"duplicate data class": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    source_url: "https://example.invalid/a"
    checked_on: "2026-07-20"
  - data_class: personal
    must_stay_local: "no"
    source_url: "https://example.invalid/b"
    checked_on: "2026-07-20"
`, "two entries for data class"},

		"missing status": {`
version: 1
jurisdiction: EX
name: Example
entries:
  - data_class: personal
    must_stay_local: "yes"
    source_url: "https://example.invalid/a"
    checked_on: "2026-07-20"
`, "status is required"},

		"unknown field": {`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "yes"
    source: "https://example.invalid/a"
    checked_on: "2026-07-20"
`, "field source not found"},
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

func TestEntryAge(t *testing.T) {
	rs, err := Parse([]byte(`
version: 1
jurisdiction: EX
name: Example
status: published
entries:
  - data_class: personal
    must_stay_local: "no"
    source_url: "https://example.invalid/a"
    checked_on: "2026-04-27"
`))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 26, 0, 0, 0, 0, time.UTC)
	if days := int(rs.Entries[0].Age(now).Hours() / 24); days != 90 {
		t.Errorf("age = %d days, want 90", days)
	}
}
