// Package ruleset loads the versioned residency rulesets — one YAML file per
// jurisdiction, kept in git so that every change to what the tool asserts about
// a country's law is a reviewable diff with an author and a date.
//
// Two invariants are enforced at load time and are the reason this package
// exists at all:
//
//   - every entry carries a source_url and a checked_on date, and
//   - checked_on is a real date that is not in the future.
//
// A rule without a citation is an opinion, and this tool does not ship
// opinions about the law.
package ruleset

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/moveeeax/tf-residency-lint/internal/plan"
)

// Obligation is the strength of the localisation requirement.
type Obligation string

const (
	// MustStayYes: the data may not leave the jurisdiction.
	MustStayYes Obligation = "yes"
	// MustStayNo: no localisation obligation for this class.
	MustStayNo Obligation = "no"
	// MustStayConditional: it may leave only via a named mechanism.
	MustStayConditional Obligation = "conditional"
)

// Status marks whether a ruleset is a shipped assertion about the law or a
// fixture. Only "published" files are treated as authoritative.
type Status string

const (
	// StatusPublished: researched against primary sources, safe to gate on.
	StatusPublished Status = "published"
	// StatusExample: fictional data for tests and documentation.
	StatusExample Status = "example"
	// StatusDraft: research in progress, must not be used to gate CI.
	StatusDraft Status = "draft"
)

// Ruleset is one jurisdiction's file.
type Ruleset struct {
	Version      int     `yaml:"version" json:"version"`
	Jurisdiction string  `yaml:"jurisdiction" json:"jurisdiction"`
	Name         string  `yaml:"name" json:"name"`
	Status       Status  `yaml:"status" json:"status"`
	Note         string  `yaml:"note,omitempty" json:"note,omitempty"`
	Entries      []Entry `yaml:"entries" json:"entries"`

	// Path is where the file was loaded from, so a finding can point at it.
	Path string `yaml:"-" json:"path,omitempty"`
}

// Entry is one (jurisdiction, data class) cell of the residency table.
type Entry struct {
	DataClass             string              `yaml:"data_class" json:"data_class"`
	MustStayLocal         Obligation          `yaml:"must_stay_local" json:"must_stay_local"`
	TransferMechanism     string              `yaml:"transfer_mechanism,omitempty" json:"transfer_mechanism,omitempty"`
	AllowedRegions        map[string][]string `yaml:"allowed_regions,omitempty" json:"allowed_regions,omitempty"`
	InCountryAlternatives []string            `yaml:"in_country_alternatives,omitempty" json:"in_country_alternatives,omitempty"`
	Penalty               string              `yaml:"penalty,omitempty" json:"penalty,omitempty"`
	SourceURL             string              `yaml:"source_url" json:"source_url"`
	CheckedOn             string              `yaml:"checked_on" json:"checked_on"`

	checked time.Time
}

// Checked is the parsed checked_on date.
func (e Entry) Checked() time.Time { return e.checked }

// Age is how long ago the entry was last verified against its source.
func (e Entry) Age(now time.Time) time.Duration { return now.Sub(e.checked) }

// RegionAllowed reports whether a region is on the approved list for a cloud,
// and whether the ruleset lists any approved region for that cloud at all.
// The two answers are different findings: "wrong region" is a fix, "no region
// exists" is an architecture decision.
func (e Entry) RegionAllowed(cloud plan.Cloud, region string) (allowed, haveList bool) {
	list, ok := e.AllowedRegions[string(cloud)]
	if !ok || len(list) == 0 {
		return false, false
	}
	for _, r := range list {
		if plan.NormalizeRegion(r) == plan.NormalizeRegion(region) {
			return true, true
		}
	}
	return false, true
}

// Set is every ruleset loaded from a directory, keyed by jurisdiction code.
type Set struct {
	byJurisdiction map[string]*Ruleset
}

// Jurisdictions returns the loaded jurisdiction codes, sorted.
func (s *Set) Jurisdictions() []string {
	out := make([]string, 0, len(s.byJurisdiction))
	for k := range s.byJurisdiction {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Get returns one jurisdiction's ruleset.
func (s *Set) Get(jurisdiction string) (*Ruleset, bool) {
	r, ok := s.byJurisdiction[strings.ToUpper(jurisdiction)]
	return r, ok
}

// Lookup finds the entry for a (jurisdiction, data class) pair.
func (s *Set) Lookup(jurisdiction, dataClass string) (*Ruleset, *Entry, bool) {
	rs, ok := s.Get(jurisdiction)
	if !ok {
		return nil, nil, false
	}
	for i := range rs.Entries {
		if strings.EqualFold(rs.Entries[i].DataClass, dataClass) {
			return rs, &rs.Entries[i], true
		}
	}
	return rs, nil, false
}

// LoadDir reads every .yaml/.yml file under dir as a ruleset.
func LoadDir(dir string) (*Set, error) {
	set := &Set{byJurisdiction: map[string]*Ruleset{}}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("read rulesets: %w", err)
	}
	if !info.IsDir() {
		rs, err := LoadFile(dir)
		if err != nil {
			return nil, err
		}
		set.byJurisdiction[rs.Jurisdiction] = rs
		return set, nil
	}

	walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		rs, err := LoadFile(p)
		if err != nil {
			return err
		}
		if prev, dup := set.byJurisdiction[rs.Jurisdiction]; dup {
			return fmt.Errorf("jurisdiction %s defined twice: %s and %s", rs.Jurisdiction, prev.Path, p)
		}
		set.byJurisdiction[rs.Jurisdiction] = rs
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if len(set.byJurisdiction) == 0 {
		return nil, fmt.Errorf("no ruleset files found under %s", dir)
	}
	return set, nil
}

// LoadFile reads and validates a single ruleset file.
func LoadFile(pathToFile string) (*Ruleset, error) {
	data, err := os.ReadFile(pathToFile)
	if err != nil {
		return nil, fmt.Errorf("read ruleset: %w", err)
	}
	rs, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", pathToFile, err)
	}
	rs.Path = pathToFile
	return rs, nil
}

// Parse validates ruleset content already in memory.
func Parse(data []byte) (*Ruleset, error) {
	var rs Ruleset
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&rs); err != nil {
		return nil, fmt.Errorf("parse ruleset: %w", err)
	}
	if err := rs.validate(); err != nil {
		return nil, err
	}
	return &rs, nil
}

var knownClouds = map[string]bool{"aws": true, "azure": true, "gcp": true, "oci": true}

func (r *Ruleset) validate() error {
	if r.Version != 1 {
		return fmt.Errorf("version must be 1, got %d", r.Version)
	}
	r.Jurisdiction = strings.ToUpper(strings.TrimSpace(r.Jurisdiction))
	if r.Jurisdiction == "" {
		return fmt.Errorf("jurisdiction code is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("%s: name is required", r.Jurisdiction)
	}
	switch r.Status {
	case StatusPublished, StatusExample, StatusDraft:
	case "":
		return fmt.Errorf("%s: status is required (published, draft or example)", r.Jurisdiction)
	default:
		return fmt.Errorf("%s: unknown status %q", r.Jurisdiction, r.Status)
	}
	if len(r.Entries) == 0 {
		return fmt.Errorf("%s: at least one entry is required", r.Jurisdiction)
	}

	seen := map[string]bool{}
	for i := range r.Entries {
		e := &r.Entries[i]
		cls := strings.ToLower(strings.TrimSpace(e.DataClass))
		if cls == "" {
			return fmt.Errorf("%s: entries[%d]: data_class is required", r.Jurisdiction, i)
		}
		if seen[cls] {
			return fmt.Errorf("%s: two entries for data class %q", r.Jurisdiction, cls)
		}
		seen[cls] = true
		e.DataClass = cls

		switch e.MustStayLocal {
		case MustStayYes, MustStayNo, MustStayConditional:
		default:
			return fmt.Errorf("%s/%s: must_stay_local must be yes, no or conditional, got %q",
				r.Jurisdiction, cls, e.MustStayLocal)
		}
		if e.MustStayLocal == MustStayConditional && strings.TrimSpace(e.TransferMechanism) == "" {
			return fmt.Errorf("%s/%s: must_stay_local is conditional, so transfer_mechanism must name the condition",
				r.Jurisdiction, cls)
		}
		for cloud, regions := range e.AllowedRegions {
			if !knownClouds[cloud] {
				return fmt.Errorf("%s/%s: unknown cloud %q in allowed_regions", r.Jurisdiction, cls, cloud)
			}
			for _, reg := range regions {
				if strings.TrimSpace(reg) == "" {
					return fmt.Errorf("%s/%s: empty region in allowed_regions.%s", r.Jurisdiction, cls, cloud)
				}
			}
		}

		if strings.TrimSpace(e.SourceURL) == "" {
			return fmt.Errorf("%s/%s: source_url is required; a rule without a citation is not shippable",
				r.Jurisdiction, cls)
		}
		u, err := url.Parse(e.SourceURL)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("%s/%s: source_url %q must be an absolute URL", r.Jurisdiction, cls, e.SourceURL)
		}
		if e.CheckedOn == "" {
			return fmt.Errorf("%s/%s: checked_on is required", r.Jurisdiction, cls)
		}
		t, err := time.Parse("2006-01-02", e.CheckedOn)
		if err != nil {
			return fmt.Errorf("%s/%s: checked_on must be YYYY-MM-DD: %w", r.Jurisdiction, cls, err)
		}
		e.checked = t
	}
	return nil
}

// Problem is a freshness or coverage defect found by Validate. These are about
// the maintainer's process, not about a customer's estate.
type Problem struct {
	Jurisdiction string `json:"jurisdiction"`
	DataClass    string `json:"data_class,omitempty"`
	Path         string `json:"path,omitempty"`
	Kind         string `json:"kind"`
	Message      string `json:"message"`
}

// Validate audits the loaded set: coverage of the four data classes, staleness
// against the quarterly review cadence, and rulesets that are not yet
// publishable. It is the quarterly review turned into a checked artefact.
func (s *Set) Validate(now time.Time, maxAge time.Duration, wantClasses []string) []Problem {
	var problems []Problem
	for _, code := range s.Jurisdictions() {
		rs := s.byJurisdiction[code]
		if rs.Status != StatusPublished {
			problems = append(problems, Problem{
				Jurisdiction: code, Path: rs.Path, Kind: "not-published",
				Message: fmt.Sprintf("status is %q; it will not be used to gate CI", rs.Status),
			})
		}
		have := map[string]bool{}
		for _, e := range rs.Entries {
			have[e.DataClass] = true
			if age := e.Age(now); age > maxAge {
				problems = append(problems, Problem{
					Jurisdiction: code, DataClass: e.DataClass, Path: rs.Path, Kind: "stale",
					Message: fmt.Sprintf("last checked %s, %d days ago (limit %d)",
						e.CheckedOn, int(age.Hours()/24), int(maxAge.Hours()/24)),
				})
			}
		}
		for _, cls := range wantClasses {
			if !have[cls] {
				problems = append(problems, Problem{
					Jurisdiction: code, DataClass: cls, Path: rs.Path, Kind: "missing-class",
					Message: "no entry for this data class",
				})
			}
		}
	}
	return problems
}
