package policy

import (
	"fmt"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/config"
)

// Finding is one rule failing on one resource change. It carries the rule's
// expected conditions and the attribute paths involved, never a value read
// from the plan.
type Finding struct {
	Rule         string         `json:"rule"`
	Severity     check.Severity `json:"severity"`
	Address      string         `json:"address"`
	ResourceType string         `json:"resource_type"`
	Action       string         `json:"action"`
	Message      string         `json:"message"`
	// Failed lists the require conditions the change did not satisfy.
	Failed []string `json:"failed_conditions,omitempty"`
	// Unknown lists the attribute paths Terraform will only know after apply.
	// A finding with Unknown set is undetermined: it is downgraded to a warning
	// because the plan can neither prove nor disprove it.
	Unknown []string `json:"unknown_paths,omitempty"`

	RuleFile string `json:"rule_file,omitempty"`
	RuleLine int    `json:"rule_line,omitempty"`

	Exempted         bool   `json:"exempted,omitempty"`
	ExemptionReason  string `json:"exemption_reason,omitempty"`
	ExemptionExpires string `json:"exemption_expires_on,omitempty"`
}

// Undetermined reports whether the finding rests on values unknown until apply.
func (f Finding) Undetermined() bool { return len(f.Unknown) > 0 }

// Evaluation is one rule that selected one change, pass or fail.
type Evaluation struct {
	Rule    string
	Address string
}

// Result is one run of the policy engine.
type Result struct {
	GeneratedAt time.Time `json:"generated_at"`
	Terraform   string    `json:"terraform_version,omitempty"`
	Rules       int       `json:"rules"`
	Changes     int       `json:"resource_changes"`
	Findings    []Finding `json:"findings"`

	// Evaluated lists every (rule, change) pair the rule selected, so JUnit
	// can show the passes. It stays out of the JSON report.
	Evaluated []Evaluation `json:"-"`
}

// Counts returns the number of findings at each severity.
func (r Result) Counts() map[check.Severity]int {
	out := map[check.Severity]int{check.Violation: 0, check.Warning: 0, check.Info: 0}
	for _, f := range r.Findings {
		out[f.Severity]++
	}
	return out
}

// Run evaluates every rule against every change.
func Run(terraform string, changes []Change, set *Set, now time.Time) Result {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	res := Result{GeneratedAt: now, Terraform: terraform, Rules: len(set.Rules), Changes: len(changes)}
	for _, c := range changes {
		for _, r := range set.Rules {
			f, selected := evaluate(r, c)
			if !selected {
				continue
			}
			res.Evaluated = append(res.Evaluated, Evaluation{Rule: r.ID, Address: c.Address})
			if f != nil {
				res.Findings = append(res.Findings, applyExemptions(*f, set.Exemptions, now))
			}
		}
	}
	sort.SliceStable(res.Findings, func(a, b int) bool {
		fa, fb := res.Findings[a], res.Findings[b]
		if fa.Severity != fb.Severity {
			return fa.Severity.AtLeast(fb.Severity)
		}
		if fa.Rule != fb.Rule {
			return fa.Rule < fb.Rule
		}
		return fa.Address < fb.Address
	})
	return res
}

// tri is a three-valued answer: the plan may not know a value yet.
type tri int

const (
	no tri = iota
	yes
	unknown
)

func and(a, b tri) tri {
	if a == no || b == no {
		return no
	}
	if a == unknown || b == unknown {
		return unknown
	}
	return yes
}

// evaluate applies one rule to one change. selected is false when the rule
// does not apply; the returned finding is nil when it applies and passes.
func evaluate(r Rule, c Change) (f *Finding, selected bool) {
	if !staticMatch(r.Match, c) {
		return nil, false
	}
	values, unknownTree := c.subject()
	var unknownPaths []string

	sel := yes
	for k, want := range r.Match.Tags {
		t := tagMatch(values, unknownTree, k, want)
		if t == unknown {
			unknownPaths = append(unknownPaths, "tags."+k)
		}
		sel = and(sel, t)
	}
	for _, cond := range r.Match.Attributes {
		t := cond.holds(values, unknownTree)
		if t == unknown {
			unknownPaths = append(unknownPaths, cond.Path)
		}
		sel = and(sel, t)
	}
	if sel == no {
		return nil, false
	}

	req := no // a rule without require fires on every change it selects
	var failed []string
	if len(r.Require) > 0 {
		req = yes
		for _, cond := range r.Require {
			t := cond.holds(values, unknownTree)
			switch t {
			case no:
				failed = append(failed, cond.String())
			case unknown:
				unknownPaths = append(unknownPaths, cond.Path)
			}
			req = and(req, t)
		}
	}
	// A change that satisfies require passes, even if the plan cannot yet tell
	// whether the rule selects it.
	if req == yes {
		return nil, true
	}

	out := &Finding{
		Rule:         r.ID,
		Severity:     r.Severity.Level(),
		Address:      c.Address,
		ResourceType: c.Type,
		Action:       c.ActionLabel(),
		Message:      r.Description,
		Failed:       failed,
		RuleFile:     r.Path,
		RuleLine:     r.Line,
	}
	// Only a rule that definitely applies and definitely fails keeps its
	// severity. Anything resting on an unknown value is a warning: never a
	// silent pass, never a red gate the plan cannot justify.
	if sel == unknown || req == unknown {
		sort.Strings(unknownPaths)
		out.Unknown = unknownPaths
		out.Severity = check.Warning
		out.Message = fmt.Sprintf("%s (undetermined: %s known only after apply)", r.Description, strings.Join(unknownPaths, ", "))
	}
	return out, true
}

func staticMatch(m Match, c Change) bool {
	hit := false
	for _, a := range m.Actions {
		if c.Has(a) {
			hit = true
			break
		}
	}
	if !hit {
		return false
	}
	if len(m.ResourceTypes) > 0 {
		hit = false
		for _, p := range m.ResourceTypes {
			if ok, _ := path.Match(p, c.Type); ok {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if len(m.Addresses) > 0 {
		hit = false
		for _, p := range m.Addresses {
			if config.MatchAddress(p, c.Address) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// tagMatch looks for a tag under every attribute the providers use for labels.
// want "*" matches any value.
func tagMatch(values map[string]any, unknownTree any, key, want string) tri {
	result := no
	for _, attr := range []string{"tags", "tags_all", "labels", "freeform_tags"} {
		vals, unk := resolve(values, child(unknownTree, attr), []string{key}, attr)
		if unk {
			result = unknown
			continue
		}
		for _, v := range vals {
			if s, ok := v.(string); ok && (want == "*" || strings.EqualFold(s, want)) {
				return yes
			}
		}
	}
	return result
}

// holds answers the condition for an object and its after_unknown tree.
func (c Condition) holds(values map[string]any, unknownTree any) tri {
	segs := strings.Split(c.Path, ".")
	vals, unk := resolve(values, child(unknownTree, segs[0]), segs[1:], segs[0])
	if unk {
		return unknown
	}
	switch c.Op {
	case "exists":
		return boolTri((len(vals) > 0) == c.Value.(bool))
	case "equals":
		return boolTri(len(vals) > 0 && all(vals, func(v any) bool { return equal(v, c.Value) }))
	case "not_equals":
		return boolTri(!anyOf(vals, func(v any) bool { return equal(v, c.Value) }))
	case "in":
		return boolTri(len(vals) > 0 && all(vals, func(v any) bool { return member(v, c.Value.([]any)) }))
	case "not_in":
		return boolTri(!anyOf(vals, func(v any) bool { return member(v, c.Value.([]any)) }))
	}
	return no
}

func boolTri(b bool) tri {
	if b {
		return yes
	}
	return no
}

func all(vals []any, f func(any) bool) bool {
	for _, v := range vals {
		if !f(v) {
			return false
		}
	}
	return true
}

func anyOf(vals []any, f func(any) bool) bool {
	for _, v := range vals {
		if f(v) {
			return true
		}
	}
	return false
}

func member(v any, list []any) bool {
	for _, x := range list {
		if equal(v, x) {
			return true
		}
	}
	return false
}

// resolve walks the first segment's value (looked up by the caller) down the
// remaining segments. It returns the non-null values at the end of the path and
// whether any step is marked unknown in after_unknown. "*" fans out over a list.
func resolve(values map[string]any, unknownTree any, rest []string, first string) ([]any, bool) {
	var v any
	if values != nil {
		v = values[first]
	}
	return walk(v, unknownTree, rest)
}

func walk(v, u any, segs []string) ([]any, bool) {
	if b, ok := u.(bool); ok && b {
		return nil, true
	}
	if len(segs) == 0 {
		if v == nil {
			return nil, false
		}
		return []any{v}, false
	}
	seg, rest := segs[0], segs[1:]
	if seg == "*" {
		var (
			out []any
			unk bool
		)
		list, _ := v.([]any)
		n := len(list)
		if ul, ok := u.([]any); ok && len(ul) > n {
			n = len(ul)
		}
		for i := 0; i < n; i++ {
			var e any
			if i < len(list) {
				e = list[i]
			}
			vals, u2 := walk(e, child(u, strconv.Itoa(i)), rest)
			out = append(out, vals...)
			unk = unk || u2
		}
		return out, unk
	}
	var next any
	switch t := v.(type) {
	case map[string]any:
		next = t[seg]
	case []any:
		if i, err := strconv.Atoi(seg); err == nil && i >= 0 && i < len(t) {
			next = t[i]
		}
	}
	return walk(next, child(u, seg), rest)
}

// child steps into an after_unknown tree, which mirrors the after object.
func child(u any, seg string) any {
	switch t := u.(type) {
	case map[string]any:
		return t[seg]
	case []any:
		if i, err := strconv.Atoi(seg); err == nil && i >= 0 && i < len(t) {
			return t[i]
		}
	}
	return nil
}

// normalize folds YAML and JSON number types onto float64 so 1 from a rule
// equals 1 from a plan.
func normalize(v any) any {
	switch t := v.(type) {
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case uint64:
		return float64(t)
	case float32:
		return float64(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalize(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = normalize(x)
		}
		return out
	}
	return v
}

func equal(a, b any) bool { return reflect.DeepEqual(normalize(a), normalize(b)) }

// applyExemptions downgrades a finding covered by a live exemption to info. An
// expired exemption leaves the finding at full severity and says so.
func applyExemptions(f Finding, exemptions []Exemption, now time.Time) Finding {
	for _, e := range exemptions {
		if e.Rule != f.Rule || !config.MatchAddress(e.Address, f.Address) {
			continue
		}
		f.ExemptionReason = e.Reason
		f.ExemptionExpires = e.ExpiresOn
		if e.Expired(now) {
			f.Message = fmt.Sprintf("%s (exemption expired on %s and no longer applies)", f.Message, e.ExpiresOn)
			return f
		}
		f.Exempted = true
		f.Severity = check.Info
		f.Message = fmt.Sprintf("exempted until %s: %s (was: %s)", e.ExpiresOn, e.Reason, f.Message)
		return f
	}
	return f
}
