// Package check is the residency engine: it walks a parsed Terraform estate,
// applies the customer's residency.yaml classification, and evaluates each
// in-scope resource against every declared jurisdiction's ruleset.
//
// Every finding it emits carries the citation and the check date of the rule
// that produced it. A finding a reader cannot trace back to a primary source is
// a finding they cannot act on.
package check

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/config"
	"github.com/moveeeax/tf-residency-lint/internal/plan"
	"github.com/moveeeax/tf-residency-lint/internal/ruleset"
)

// Severity orders findings for the CI gate.
type Severity string

const (
	// Violation: the ruleset says this data may not be where Terraform puts it.
	Violation Severity = "violation"
	// Warning: exposure that needs a human, not necessarily a breach.
	Warning Severity = "warning"
	// Info: recorded for the report, never gates.
	Info Severity = "info"
)

var severityRank = map[Severity]int{Info: 0, Warning: 1, Violation: 2}

// AtLeast reports whether s is as severe as min.
func (s Severity) AtLeast(min Severity) bool { return severityRank[s] >= severityRank[min] }

// ParseSeverity resolves a --fail-on value.
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case Violation:
		return Violation, true
	case Warning:
		return Warning, true
	case Info:
		return Info, true
	}
	return "", false
}

// Rule identifiers. They are stable strings because people grep for them and
// put them in waivers and dashboards.
const (
	RuleResidencyViolation = "residency-violation"
	RuleNoApprovedRegion   = "no-approved-region"
	RuleConditional        = "conditional-transfer"
	RuleUnknownRegion      = "unknown-region"
	RuleUnclassified       = "unclassified-stateful-resource"
	RuleMissingRule        = "missing-rule"
	RuleStaleRule          = "stale-rule"
	RuleExpiredWaiver      = "expired-waiver"
	RuleWaived             = "waived"
)

// Finding is one problem with one resource in one jurisdiction.
type Finding struct {
	Rule         string   `json:"rule"`
	Severity     Severity `json:"severity"`
	Address      string   `json:"address,omitempty"`
	ResourceType string   `json:"resource_type,omitempty"`
	Cloud        string   `json:"cloud,omitempty"`
	Region       string   `json:"region,omitempty"`
	RegionSource string   `json:"region_source,omitempty"`
	Jurisdiction string   `json:"jurisdiction,omitempty"`
	DataClass    string   `json:"data_class,omitempty"`
	DeclaredBy   string   `json:"declared_by,omitempty"`
	Message      string   `json:"message"`

	TransferMechanism string   `json:"transfer_mechanism,omitempty"`
	Alternatives      []string `json:"in_country_alternatives,omitempty"`
	Penalty           string   `json:"penalty,omitempty"`
	SourceURL         string   `json:"source_url,omitempty"`
	CheckedOn         string   `json:"checked_on,omitempty"`

	// WaivedFrom names the rule that a live waiver downgraded to info.
	WaivedFrom   string `json:"waived_from,omitempty"`
	WaiverReason string `json:"waiver_reason,omitempty"`
}

// Result is one run of the engine.
type Result struct {
	GeneratedAt   time.Time `json:"generated_at"`
	Jurisdictions []string  `json:"jurisdictions"`
	Scanned       int       `json:"resources_scanned"`
	InScope       int       `json:"resources_in_scope"`
	Findings      []Finding `json:"findings"`

	// Evaluated lists every (jurisdiction, resource) pair a ruleset entry was
	// applied to, findings or not, so test-style reports can show the passes.
	// It stays out of the JSON report.
	Evaluated []Evaluation `json:"-"`
}

// Evaluation is one in-scope resource checked against one jurisdiction.
type Evaluation struct {
	Address      string
	ResourceType string
	Jurisdiction string
	DataClass    string
	DeclaredBy   string
}

// Counts returns the number of findings at each severity.
func (r Result) Counts() map[Severity]int {
	out := map[Severity]int{Violation: 0, Warning: 0, Info: 0}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// Worst returns the highest severity present, or Info when clean.
func (r Result) Worst() Severity {
	worst := Info
	for _, f := range r.Findings {
		if f.Severity.AtLeast(worst) {
			worst = f.Severity
		}
	}
	return worst
}

// Options tunes a run.
type Options struct {
	// Now is the clock; injected so tests and reports are deterministic.
	Now time.Time
	// MaxRuleAge is how long a ruleset entry may go unverified before the
	// findings it produces are flagged as resting on stale research.
	MaxRuleAge time.Duration
	// ReportUnclassified emits a warning for every stateful resource that no
	// declaration covers. This is the discovery half of the review.
	ReportUnclassified bool
	// AllowUnpublished lets draft and example rulesets gate. Off by default:
	// nobody should fail a pipeline on research that is not finished.
	AllowUnpublished bool
}

// Run evaluates an estate against the rulesets.
func Run(inv plan.Inventory, cfg *config.Config, set *ruleset.Set, opts Options) (Result, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.MaxRuleAge <= 0 {
		opts.MaxRuleAge = 90 * 24 * time.Hour
	}

	res := Result{
		GeneratedAt:   opts.Now,
		Jurisdictions: append([]string(nil), cfg.Jurisdictions...),
		Scanned:       len(inv.Resources),
	}

	// Fail loudly rather than silently checking nothing: a residency.yaml that
	// names a jurisdiction with no ruleset is a misconfiguration, and treating
	// it as "clean" is the worst outcome this tool can produce.
	for _, j := range cfg.Jurisdictions {
		if _, ok := set.Get(j); !ok {
			return Result{}, fmt.Errorf("no ruleset for jurisdiction %q (loaded: %s)",
				j, strings.Join(set.Jurisdictions(), ", "))
		}
	}

	staleSeen := map[string]bool{}
	for _, r := range inv.Resources {
		if r.Mode == "data" || cfg.Excluded(r.Address) {
			continue
		}
		class, declaredBy := cfg.Classify(r.Address, r.Type, r.Tags)
		if class == config.None {
			if r.Stateful && opts.ReportUnclassified {
				res.Findings = append(res.Findings, Finding{
					Rule:         RuleUnclassified,
					Severity:     Warning,
					Address:      r.Address,
					ResourceType: r.Type,
					Cloud:        string(r.Cloud),
					Region:       r.Region,
					RegionSource: string(r.RegionSource),
					Message:      "stores data at rest but no declaration in residency.yaml assigns it a data class",
				})
			}
			continue
		}
		res.InScope++

		for _, j := range cfg.Jurisdictions {
			rs, entry, ok := set.Lookup(j, string(class))
			if !ok || entry == nil {
				res.Findings = append(res.Findings, Finding{
					Rule:         RuleMissingRule,
					Severity:     Warning,
					Address:      r.Address,
					ResourceType: r.Type,
					Jurisdiction: j,
					DataClass:    string(class),
					DeclaredBy:   declaredBy,
					Message:      fmt.Sprintf("ruleset %s has no entry for data class %q", j, class),
				})
				continue
			}
			if rs.Status != ruleset.StatusPublished && !opts.AllowUnpublished {
				continue
			}
			res.Evaluated = append(res.Evaluated, Evaluation{
				Address:      r.Address,
				ResourceType: r.Type,
				Jurisdiction: j,
				DataClass:    string(class),
				DeclaredBy:   declaredBy,
			})
			if age := entry.Age(opts.Now); age > opts.MaxRuleAge {
				key := j + "/" + string(class)
				if !staleSeen[key] {
					staleSeen[key] = true
					res.Findings = append(res.Findings, Finding{
						Rule:         RuleStaleRule,
						Severity:     Warning,
						Jurisdiction: j,
						DataClass:    string(class),
						SourceURL:    entry.SourceURL,
						CheckedOn:    entry.CheckedOn,
						Message: fmt.Sprintf("rule last verified %d days ago; re-check the source before relying on findings from it",
							int(age.Hours()/24)),
					})
				}
			}

			if f, ok := evaluate(r, class, declaredBy, j, entry); ok {
				f.DeclaredBy = declaredBy
				res.Findings = append(res.Findings, applyWaivers(f, cfg, opts.Now)...)
			}
		}
	}

	sortFindings(res.Findings)
	return res, nil
}

// evaluate applies one ruleset entry to one resource.
func evaluate(r plan.Resource, class config.DataClass, declaredBy, jurisdiction string, e *ruleset.Entry) (Finding, bool) {
	base := Finding{
		Address:           r.Address,
		ResourceType:      r.Type,
		Cloud:             string(r.Cloud),
		Region:            r.Region,
		RegionSource:      string(r.RegionSource),
		Jurisdiction:      jurisdiction,
		DataClass:         string(class),
		DeclaredBy:        declaredBy,
		TransferMechanism: e.TransferMechanism,
		Alternatives:      e.InCountryAlternatives,
		Penalty:           e.Penalty,
		SourceURL:         e.SourceURL,
		CheckedOn:         e.CheckedOn,
	}

	if e.MustStayLocal == ruleset.MustStayNo {
		return Finding{}, false
	}

	if r.Region == "" {
		base.Rule = RuleUnknownRegion
		base.Severity = Warning
		base.Message = "carries in-scope data but no region could be determined from the plan or the provider configuration"
		return base, true
	}

	allowed, haveList := e.RegionAllowed(r.Cloud, r.Region)
	if allowed {
		return Finding{}, false
	}

	if !haveList {
		base.Rule = RuleNoApprovedRegion
		base.Severity = severityFor(e.MustStayLocal)
		base.Message = fmt.Sprintf("%s lists no approved %s region for %s data; %s is not covered by the ruleset",
			jurisdiction, r.Cloud, class, r.Region)
		return base, true
	}

	if e.MustStayLocal == ruleset.MustStayConditional {
		base.Rule = RuleConditional
		base.Severity = Warning
		base.Message = fmt.Sprintf("%s data in %s is outside the %s approved list; transfer is permitted only via the named mechanism",
			class, r.Region, jurisdiction)
		return base, true
	}

	base.Rule = RuleResidencyViolation
	base.Severity = Violation
	base.Message = fmt.Sprintf("%s data must stay in %s but this resource is in %s",
		class, jurisdiction, r.Region)
	return base, true
}

func severityFor(o ruleset.Obligation) Severity {
	if o == ruleset.MustStayYes {
		return Violation
	}
	return Warning
}

// applyWaivers downgrades a finding covered by a live waiver, and refuses to
// downgrade one covered by an expired waiver — emitting a second finding so the
// expiry itself is visible instead of quietly turning the gate red again with
// no explanation.
func applyWaivers(f Finding, cfg *config.Config, now time.Time) []Finding {
	for _, w := range cfg.Waivers {
		if !w.Covers(f.Address, f.Jurisdiction) {
			continue
		}
		if w.Expired(now) {
			expired := f
			expired.Rule = RuleExpiredWaiver
			expired.Severity = Warning
			expired.WaiverReason = w.Reason
			expired.Message = fmt.Sprintf("waiver expired on %s and no longer suppresses %s", w.ExpiresOn, f.Rule)
			return []Finding{f, expired}
		}
		waived := f
		waived.WaivedFrom = f.Rule
		waived.Rule = RuleWaived
		waived.Severity = Info
		waived.WaiverReason = w.Reason
		waived.Message = fmt.Sprintf("waived until %s: %s (was: %s)", w.ExpiresOn, w.Reason, f.Message)
		return []Finding{waived}
	}
	return []Finding{f}
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(a, b int) bool {
		if severityRank[f[a].Severity] != severityRank[f[b].Severity] {
			return severityRank[f[a].Severity] > severityRank[f[b].Severity]
		}
		if f[a].Jurisdiction != f[b].Jurisdiction {
			return f[a].Jurisdiction < f[b].Jurisdiction
		}
		if f[a].Address != f[b].Address {
			return f[a].Address < f[b].Address
		}
		return f[a].Rule < f[b].Rule
	})
}
