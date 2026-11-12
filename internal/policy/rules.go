package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/moveeeax/tf-residency-lint/internal/check"
)

// Severity is what a rule author writes. It maps onto the engine severities so
// --fail-on means the same thing for `check` and for `policy check`.
type Severity string

const (
	Deny Severity = "deny"
	Warn Severity = "warn"
)

// Level is the engine severity a rule's findings carry.
func (s Severity) Level() check.Severity {
	if s == Deny {
		return check.Violation
	}
	return check.Warning
}

// File is one rules file.
type File struct {
	Version    int         `yaml:"version"`
	Rules      []Rule      `yaml:"rules"`
	Exemptions []Exemption `yaml:"exemptions"`
}

// Rule selects resource changes with Match and, when Require is set, demands
// that every selected change satisfies it. A rule without Require denies (or
// warns about) every change it selects.
type Rule struct {
	ID          string      `yaml:"id"`
	Description string      `yaml:"description"`
	Severity    Severity    `yaml:"severity"`
	Match       Match       `yaml:"match"`
	Require     []Condition `yaml:"require"`

	// Path and Line locate the rule for SARIF.
	Path string `yaml:"-"`
	Line int    `yaml:"-"`
}

// Match is AND across its populated fields and OR within a list: a change is
// selected when one of its actions is listed, its type matches one of the
// resource_types globs (if any), its address one of the addresses globs (if
// any), it carries every listed tag, and every attribute condition holds.
type Match struct {
	Actions       []Action          `yaml:"actions"`
	ResourceTypes []string          `yaml:"resource_types"`
	Addresses     []string          `yaml:"addresses"`
	Tags          map[string]string `yaml:"tags"`
	Attributes    []Condition       `yaml:"attributes"`
}

// Exemption lets one rule pass for the resources it names. Like a residency
// waiver it must say why and until when; an expired exemption stops working.
type Exemption struct {
	Rule      string `yaml:"rule"`
	Address   string `yaml:"address"`
	Reason    string `yaml:"reason"`
	ExpiresOn string `yaml:"expires_on"`

	expires time.Time
}

// Expired reports whether the exemption no longer suppresses anything.
func (e Exemption) Expired(now time.Time) bool { return now.After(e.expires) }

// Condition tests the value at an attribute path with exactly one operator.
//
// Paths are dot-separated: `storage_encrypted`, `encrypt_at_rest.0.enabled`,
// `encrypt_at_rest.*.enabled` (every element of a list). A path that leads
// nowhere resolves to no value; a value Terraform will only know after apply
// makes the condition undetermined.
type Condition struct {
	Path string
	Op   string
	// Value is the operand: a bool for exists, a scalar for equals and
	// not_equals, a list for in and not_in.
	Value any
}

var operators = map[string]bool{"exists": true, "equals": true, "not_equals": true, "in": true, "not_in": true}

// UnmarshalYAML reads `{path: x, <operator>: v}` and rejects anything else, so
// a typo in an operator is a load error instead of a condition that never runs.
func (c *Condition) UnmarshalYAML(n *yaml.Node) error {
	var raw map[string]any
	if err := n.Decode(&raw); err != nil {
		return err
	}
	for k, v := range raw {
		switch {
		case k == "path":
			s, ok := v.(string)
			if !ok || strings.TrimSpace(s) == "" {
				return fmt.Errorf("line %d: path must be a non-empty string", n.Line)
			}
			c.Path = s
		case operators[k]:
			if c.Op != "" {
				return fmt.Errorf("line %d: condition on %q sets both %s and %s; use one operator per condition", n.Line, raw["path"], c.Op, k)
			}
			c.Op, c.Value = k, v
		default:
			return fmt.Errorf("line %d: unknown condition key %q (want path and one of exists, equals, not_equals, in, not_in)", n.Line, k)
		}
	}
	if c.Path == "" {
		return fmt.Errorf("line %d: condition needs a path", n.Line)
	}
	switch c.Op {
	case "":
		return fmt.Errorf("line %d: condition on %q needs an operator (exists, equals, not_equals, in, not_in)", n.Line, c.Path)
	case "exists":
		if _, ok := c.Value.(bool); !ok {
			return fmt.Errorf("line %d: exists on %q must be true or false", n.Line, c.Path)
		}
	case "in", "not_in":
		if _, ok := c.Value.([]any); !ok {
			return fmt.Errorf("line %d: %s on %q must be a list", n.Line, c.Op, c.Path)
		}
	}
	c.Value = normalize(c.Value)
	return nil
}

// String renders the condition as the rule file states it. It shows the
// operand from the rule, never a value from the plan.
func (c Condition) String() string {
	return fmt.Sprintf("%s %s %s", c.Path, c.Op, formatValue(c.Value))
}

func formatValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return fmt.Sprintf("%q", t)
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = formatValue(x)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return fmt.Sprint(v)
}

// Set is every rule and exemption loaded for a run.
type Set struct {
	Rules      []Rule
	Exemptions []Exemption
}

var ruleID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Load reads rules from files and directories. A directory contributes every
// .yaml/.yml file under it. Rule IDs must be unique across everything loaded.
func Load(paths []string) (*Set, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no rules given; pass --rules with a file or directory")
	}
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("read rules: %w", err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(fp string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			ext := strings.ToLower(filepath.Ext(fp))
			if !d.IsDir() && (ext == ".yaml" || ext == ".yml") {
				files = append(files, fp)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read rules: %w", err)
		}
	}

	set := &Set{}
	where := map[string]string{}
	for _, fp := range files {
		f, err := LoadFile(fp)
		if err != nil {
			return nil, err
		}
		for _, r := range f.Rules {
			if prev, dup := where[r.ID]; dup {
				return nil, fmt.Errorf("rule %q defined twice: %s and %s", r.ID, prev, fp)
			}
			where[r.ID] = fp
			set.Rules = append(set.Rules, r)
		}
		set.Exemptions = append(set.Exemptions, f.Exemptions...)
	}
	if len(set.Rules) == 0 {
		return nil, fmt.Errorf("no rules found in %s", strings.Join(paths, ", "))
	}
	for i, e := range set.Exemptions {
		if _, ok := where[e.Rule]; !ok {
			return nil, fmt.Errorf("exemptions[%d] %q: rule %q is not defined in any loaded rules file", i, e.Address, e.Rule)
		}
	}
	sort.SliceStable(set.Rules, func(a, b int) bool { return set.Rules[a].ID < set.Rules[b].ID })
	return set, nil
}

// LoadFile reads and validates one rules file.
func LoadFile(pathToFile string) (*File, error) {
	data, err := os.ReadFile(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("read rules: %w", err)
	}
	f, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pathToFile, err)
	}
	for i := range f.Rules {
		f.Rules[i].Path = pathToFile
	}
	return f, nil
}

// Parse validates rules content already in memory.
func Parse(data []byte) (*File, error) {
	var f File
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo'd key must not silently drop a matcher
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if err := f.validate(); err != nil {
		return nil, err
	}
	f.recordLines(data)
	return &f, nil
}

func (f *File) validate() error {
	if f.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", f.Version)
	}
	if len(f.Rules) == 0 && len(f.Exemptions) == 0 {
		return fmt.Errorf("file defines no rules and no exemptions")
	}
	seen := map[string]bool{}
	for i := range f.Rules {
		r := &f.Rules[i]
		if !ruleID.MatchString(r.ID) {
			return fmt.Errorf("rules[%d]: id %q must be lowercase letters, digits, '.', '_' or '-'", i, r.ID)
		}
		if seen[r.ID] {
			return fmt.Errorf("rules[%d]: duplicate id %q", i, r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Description) == "" {
			return fmt.Errorf("rule %q: description is required; it is the message a failing change shows", r.ID)
		}
		switch r.Severity {
		case Deny, Warn:
		case "":
			return fmt.Errorf("rule %q: severity is required (deny or warn)", r.ID)
		default:
			return fmt.Errorf("rule %q: severity must be deny or warn, got %q", r.ID, r.Severity)
		}
		if len(r.Match.Actions) == 0 {
			return fmt.Errorf("rule %q: match.actions is required (create, update, delete, replace, read, forget, no-op)", r.ID)
		}
		for _, a := range r.Match.Actions {
			if !knownActions[a] {
				return fmt.Errorf("rule %q: unknown action %q (want create, update, delete, replace, read, forget, no-op)", r.ID, a)
			}
		}
		for _, t := range r.Match.ResourceTypes {
			if _, err := path.Match(t, ""); err != nil || t == "" {
				return fmt.Errorf("rule %q: bad resource type pattern %q", r.ID, t)
			}
		}
		for _, a := range r.Match.Addresses {
			if _, err := path.Match(strings.ReplaceAll(a, ".", "/"), ""); err != nil || a == "" {
				return fmt.Errorf("rule %q: bad address pattern %q", r.ID, a)
			}
		}
		for k := range r.Match.Tags {
			if strings.TrimSpace(k) == "" {
				return fmt.Errorf("rule %q: empty tag key in match.tags", r.ID)
			}
		}
	}
	for i := range f.Exemptions {
		e := &f.Exemptions[i]
		if strings.TrimSpace(e.Rule) == "" {
			return fmt.Errorf("exemptions[%d]: rule is required", i)
		}
		if strings.TrimSpace(e.Address) == "" {
			return fmt.Errorf("exemptions[%d] %q: address is required", i, e.Rule)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("exemptions[%d] %q: reason is required; an unexplained exemption is a silent failure", i, e.Address)
		}
		if e.ExpiresOn == "" {
			return fmt.Errorf("exemptions[%d] %q: expires_on is required; exemptions do not last forever", i, e.Address)
		}
		t, err := time.Parse("2006-01-02", e.ExpiresOn)
		if err != nil {
			return fmt.Errorf("exemptions[%d] %q: expires_on must be YYYY-MM-DD: %w", i, e.Address, err)
		}
		e.expires = t
	}
	return nil
}

// recordLines notes where each rule starts so SARIF can point at it. Best
// effort, as in residency.yaml: the document already decoded.
func (f *File) recordLines(data []byte) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil || len(root.Content) == 0 {
		return
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value != "rules" {
			continue
		}
		for j, n := range doc.Content[i+1].Content {
			if j < len(f.Rules) {
				f.Rules[j].Line = n.Line
			}
		}
	}
}
