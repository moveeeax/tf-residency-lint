// Package policy is a small rule engine over the resource_changes block of a
// `terraform show -json tfplan` document: deny a destroy of a resource that
// carries a protection tag, require encryption and block public exposure on new
// storage, without running a policy server.
//
// Rules are YAML matchers over resource type, address, change action, tags and
// attribute values. Unlike the residency inventory, this engine has to read
// attribute values to evaluate them, so it keeps the before and after objects
// in memory for the length of a run. They never reach a Finding: a finding
// names the attribute path and the condition it failed, not the value, because
// plan JSON carries passwords and key material in clear.
package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/moveeeax/tf-residency-lint/internal/plan"
)

// Action is one step of a planned change, as `terraform show -json` spells it,
// plus "replace", which this package adds to every change that both deletes
// and creates an object.
type Action string

const (
	NoOp    Action = "no-op"
	Create  Action = "create"
	Read    Action = "read"
	Update  Action = "update"
	Delete  Action = "delete"
	Forget  Action = "forget"
	Replace Action = "replace"
)

var knownActions = map[Action]bool{
	NoOp: true, Create: true, Read: true, Update: true, Delete: true, Forget: true, Replace: true,
}

// Change is one entry of resource_changes.
type Change struct {
	Address  string
	Type     string
	Mode     string
	Provider string
	// Actions are the raw steps from the plan, e.g. [delete create].
	Actions []Action

	before       map[string]any
	after        map[string]any
	afterUnknown any
}

// Has reports whether the change performs an action. Replace is true when the
// change both deletes and creates, whichever order Terraform does it in, so a
// rule listing "delete" catches replacements too, as the Terraform JSON format
// documentation intends.
func (c Change) Has(a Action) bool {
	if a == Replace {
		return c.has(Delete) && c.has(Create)
	}
	return c.has(a)
}

func (c Change) has(a Action) bool {
	for _, x := range c.Actions {
		if x == a {
			return true
		}
	}
	return false
}

// Destroys reports whether the change removes the existing object.
func (c Change) Destroys() bool { return c.has(Delete) }

// ActionLabel is the change as one word for reports: "replace" for
// delete-and-create, otherwise the actions joined with "+".
func (c Change) ActionLabel() string {
	if c.Has(Replace) {
		return string(Replace)
	}
	s := ""
	for i, a := range c.Actions {
		if i > 0 {
			s += "+"
		}
		s += string(a)
	}
	return s
}

// subject is the object a rule is evaluated against: the prior state when the
// change destroys the resource or only forgets it, the planned state
// otherwise. A destroy rule cares about the tags the resource has now; a
// creation rule cares about what is about to exist.
func (c Change) subject() (values map[string]any, unknown any) {
	if c.Destroys() || (c.has(Forget) && !c.has(Create)) {
		return c.before, nil
	}
	return c.after, c.afterUnknown
}

// Tags returns the labels of the subject object, read the same way the
// residency inventory reads them (tags, tags_all, labels, freeform_tags).
func (c Change) Tags() map[string]string {
	values, _ := c.subject()
	return plan.ExtractTags(values)
}

type changesDoc struct {
	FormatVersion    string          `json:"format_version"`
	TerraformVersion string          `json:"terraform_version"`
	PlannedValues    json.RawMessage `json:"planned_values"`
	Values           json.RawMessage `json:"values"`
	ResourceChanges  []rawChange     `json:"resource_changes"`
}

type rawChange struct {
	Address      string `json:"address"`
	Mode         string `json:"mode"`
	Type         string `json:"type"`
	ProviderName string `json:"provider_name"`
	Change       struct {
		Actions      []string        `json:"actions"`
		Before       json.RawMessage `json:"before"`
		After        json.RawMessage `json:"after"`
		AfterUnknown json.RawMessage `json:"after_unknown"`
	} `json:"change"`
}

// ErrNotPlan is returned for a state document or anything else that has no
// planned changes to evaluate. Passing a state file to a change policy would
// otherwise report "no violations" for a plan nobody looked at.
var ErrNotPlan = errors.New("policy check needs a plan document (terraform show -json tfplan)")

// ParseChanges reads the resource_changes of a `terraform show -json tfplan`
// document. A plan with no changes is valid and yields no Change.
func ParseChanges(data []byte) (string, []Change, error) {
	var doc changesDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", nil, fmt.Errorf("parse terraform json: %w", err)
	}
	if doc.FormatVersion == "" && doc.TerraformVersion == "" {
		return "", nil, plan.ErrNotTerraformJSON
	}
	if len(doc.PlannedValues) == 0 || string(doc.PlannedValues) == "null" {
		if len(doc.Values) > 0 {
			return "", nil, fmt.Errorf("%w: got a state document", ErrNotPlan)
		}
		return "", nil, fmt.Errorf("%w: no planned_values block", ErrNotPlan)
	}

	out := make([]Change, 0, len(doc.ResourceChanges))
	for _, rc := range doc.ResourceChanges {
		c := Change{
			Address:  rc.Address,
			Type:     rc.Type,
			Mode:     rc.Mode,
			Provider: rc.ProviderName,
		}
		if c.Mode == "" {
			c.Mode = "managed"
		}
		if len(rc.Change.Actions) == 0 {
			return "", nil, fmt.Errorf("resource_changes %s: no actions", rc.Address)
		}
		for _, a := range rc.Change.Actions {
			act := Action(a)
			if !knownActions[act] || act == Replace {
				// A future Terraform action this engine does not know must stop
				// the run; guessing whether it destroys something is not safe.
				return "", nil, fmt.Errorf("resource_changes %s: unknown action %q", rc.Address, a)
			}
			c.Actions = append(c.Actions, act)
		}
		var err error
		if c.before, err = object(rc.Change.Before); err != nil {
			return "", nil, fmt.Errorf("resource_changes %s: before: %w", rc.Address, err)
		}
		if c.after, err = object(rc.Change.After); err != nil {
			return "", nil, fmt.Errorf("resource_changes %s: after: %w", rc.Address, err)
		}
		if len(rc.Change.AfterUnknown) > 0 {
			if err := json.Unmarshal(rc.Change.AfterUnknown, &c.afterUnknown); err != nil {
				return "", nil, fmt.Errorf("resource_changes %s: after_unknown: %w", rc.Address, err)
			}
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Address < out[b].Address })
	return doc.TerraformVersion, out, nil
}

func object(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}
