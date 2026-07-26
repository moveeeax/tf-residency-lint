// Package config loads and validates residency.yaml — the file a customer
// keeps in their own repository declaring which parts of their Terraform estate
// carry which class of data.
//
// The tool never guesses a data class from a resource name. Classification is a
// business fact only the customer holds, so it is declared explicitly and lives
// under review in their repo.
package config

import (
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DataClass is one of the four classes v1 covers.
type DataClass string

const (
	Personal   DataClass = "personal"
	Health     DataClass = "health"
	Financial  DataClass = "financial"
	Government DataClass = "government"
	// None marks a resource as explicitly out of scope.
	None DataClass = "none"
)

// aliases accepts the wording customers actually use in their own docs without
// letting the ruleset key space drift.
var aliases = map[string]DataClass{
	"personal":      Personal,
	"pii":           Personal,
	"health":        Health,
	"phi":           Health,
	"medical":       Health,
	"financial":     Financial,
	"payment":       Financial,
	"payments":      Financial,
	"pci":           Financial,
	"government":    Government,
	"state":         Government,
	"public-sector": Government,
	"none":          None,
}

// ParseDataClass folds an alias onto its canonical class.
func ParseDataClass(s string) (DataClass, bool) {
	c, ok := aliases[strings.ToLower(strings.TrimSpace(s))]
	return c, ok
}

// KnownClasses returns the canonical in-scope classes, sorted.
func KnownClasses() []DataClass {
	return []DataClass{Financial, Government, Health, Personal}
}

// Config is the parsed residency.yaml.
type Config struct {
	Version       int           `yaml:"version"`
	Jurisdictions []string      `yaml:"jurisdictions"`
	DefaultClass  string        `yaml:"default_class"`
	Declarations  []Declaration `yaml:"declarations"`
	Exclusions    []string      `yaml:"exclusions"`
	Waivers       []Waiver      `yaml:"waivers"`
}

// Declaration binds a set of resources to a data class.
type Declaration struct {
	Name      string `yaml:"name"`
	DataClass string `yaml:"data_class"`
	Match     Match  `yaml:"match"`

	class DataClass
}

// Class is the parsed, canonical data class of the declaration.
func (d Declaration) Class() DataClass { return d.class }

// Match is the criteria set. A resource matches the declaration if it satisfies
// any populated criterion (OR), which is what people expect when they list a
// module path and a tag side by side.
type Match struct {
	Addresses     []string          `yaml:"addresses"`
	ResourceTypes []string          `yaml:"resource_types"`
	Tags          map[string]string `yaml:"tags"`
}

func (m Match) empty() bool {
	return len(m.Addresses) == 0 && len(m.ResourceTypes) == 0 && len(m.Tags) == 0
}

// Waiver records an accepted exposure. It is not a suppression: a waiver must
// name a reason and an expiry, and an expired waiver stops suppressing.
type Waiver struct {
	Address      string `yaml:"address"`
	Jurisdiction string `yaml:"jurisdiction"`
	Reason       string `yaml:"reason"`
	ExpiresOn    string `yaml:"expires_on"`

	expires time.Time
}

// Expires is the parsed expiry date.
func (w Waiver) Expires() time.Time { return w.expires }

// Expired reports whether the waiver no longer suppresses anything.
func (w Waiver) Expired(now time.Time) bool { return now.After(w.expires) }

// Covers reports whether the waiver applies to an address in a jurisdiction.
func (w Waiver) Covers(address, jurisdiction string) bool {
	if w.Jurisdiction != "" && w.Jurisdiction != "*" && !strings.EqualFold(w.Jurisdiction, jurisdiction) {
		return false
	}
	return globMatch(w.Address, address)
}

// Load reads and validates a residency.yaml file.
func Load(pathToFile string) (*Config, error) {
	data, err := os.ReadFile(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("read residency config: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pathToFile, err)
	}
	return cfg, nil
}

// Parse validates residency.yaml content already in memory.
func Parse(data []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // a typo'd key must not silently drop a declaration
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse residency config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", c.Version)
	}
	if len(c.Jurisdictions) == 0 {
		return fmt.Errorf("at least one jurisdiction must be declared")
	}
	seen := map[string]bool{}
	for i, j := range c.Jurisdictions {
		j = strings.ToUpper(strings.TrimSpace(j))
		if j == "" {
			return fmt.Errorf("jurisdictions[%d] is empty", i)
		}
		if seen[j] {
			return fmt.Errorf("jurisdiction %q listed twice", j)
		}
		seen[j] = true
		c.Jurisdictions[i] = j
	}

	if c.DefaultClass == "" {
		c.DefaultClass = string(None)
	}
	if _, ok := ParseDataClass(c.DefaultClass); !ok {
		return fmt.Errorf("default_class %q is not a known data class (%s)", c.DefaultClass, classList())
	}

	if len(c.Declarations) == 0 {
		return fmt.Errorf("at least one declaration is required; without one nothing is in scope")
	}
	names := map[string]bool{}
	for i := range c.Declarations {
		d := &c.Declarations[i]
		if strings.TrimSpace(d.Name) == "" {
			return fmt.Errorf("declarations[%d]: name is required", i)
		}
		if names[d.Name] {
			return fmt.Errorf("declarations[%d]: duplicate name %q", i, d.Name)
		}
		names[d.Name] = true
		cls, ok := ParseDataClass(d.DataClass)
		if !ok {
			return fmt.Errorf("declarations[%d] %q: data_class %q is not known (%s)", i, d.Name, d.DataClass, classList())
		}
		d.class = cls
		if d.Match.empty() {
			return fmt.Errorf("declarations[%d] %q: match must set at least one of addresses, resource_types, tags", i, d.Name)
		}
		for _, pattern := range d.Match.Addresses {
			if _, err := path.Match(pattern, ""); err != nil {
				return fmt.Errorf("declarations[%d] %q: bad address pattern %q: %w", i, d.Name, pattern, err)
			}
		}
	}

	for i, pattern := range c.Exclusions {
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("exclusions[%d]: bad pattern %q: %w", i, pattern, err)
		}
	}

	for i := range c.Waivers {
		w := &c.Waivers[i]
		if strings.TrimSpace(w.Address) == "" {
			return fmt.Errorf("waivers[%d]: address is required", i)
		}
		if strings.TrimSpace(w.Reason) == "" {
			return fmt.Errorf("waivers[%d] %q: reason is required; an unexplained waiver is a silent failure", i, w.Address)
		}
		if w.ExpiresOn == "" {
			return fmt.Errorf("waivers[%d] %q: expires_on is required; waivers do not last forever", i, w.Address)
		}
		t, err := time.Parse("2006-01-02", w.ExpiresOn)
		if err != nil {
			return fmt.Errorf("waivers[%d] %q: expires_on must be YYYY-MM-DD: %w", i, w.Address, err)
		}
		w.expires = t
		if w.Jurisdiction != "" {
			w.Jurisdiction = strings.ToUpper(w.Jurisdiction)
		}
	}
	return nil
}

func classList() string {
	keys := make([]string, 0, len(aliases))
	for k := range aliases {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// Excluded reports whether an address is declared out of scope entirely.
func (c *Config) Excluded(address string) bool {
	for _, pattern := range c.Exclusions {
		if globMatch(pattern, address) {
			return true
		}
	}
	return false
}

// Classify returns the data class declared for a resource and the name of the
// declaration that matched. The first matching declaration wins, so ordering in
// the file is meaningful and reviewable.
func (c *Config) Classify(address, resourceType string, tags map[string]string) (DataClass, string) {
	for _, d := range c.Declarations {
		if d.matches(address, resourceType, tags) {
			return d.class, d.Name
		}
	}
	cls, _ := ParseDataClass(c.DefaultClass)
	return cls, "default_class"
}

func (d Declaration) matches(address, resourceType string, tags map[string]string) bool {
	for _, pattern := range d.Match.Addresses {
		if globMatch(pattern, address) {
			return true
		}
	}
	for _, t := range d.Match.ResourceTypes {
		if t == resourceType {
			return true
		}
	}
	for k, want := range d.Match.Tags {
		if got, ok := tags[k]; ok && strings.EqualFold(got, want) {
			return true
		}
	}
	return false
}

// indexSuffix strips count/for_each indices so `module.db.aws_s3_bucket.this[0]`
// matches a pattern written against the un-indexed address.
var indexSuffix = regexp.MustCompile(`\[[^\]]*\]`)

// globMatch matches a Terraform address against a pattern. path.Match treats
// "/" as a separator but Terraform addresses use ".", so a trailing "*" would
// otherwise stop at the first dot; "module.db.*" must cover
// "module.db.aws_rds_cluster.this". Indices are stripped before comparing.
func globMatch(pattern, address string) bool {
	if pattern == "" {
		return false
	}
	pattern = strings.ReplaceAll(pattern, ".", "/")
	target := strings.ReplaceAll(indexSuffix.ReplaceAllString(address, ""), ".", "/")
	if ok, err := path.Match(pattern, target); err == nil && ok {
		return true
	}
	// A pattern ending in "*" is read as a prefix over the whole subtree.
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(target, prefix)
	}
	return pattern == target
}
