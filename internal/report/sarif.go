package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/config"
)

// Meta is what the SARIF and JUnit renderers need beyond the result itself.
type Meta struct {
	// Plan and Config are the paths as given on the command line.
	Plan   string
	Config string
	// Version is the tool version stamped at build time.
	Version string
	// FailOn is the gate threshold; JUnit fails a testcase at or above it.
	FailOn check.Severity
	// Declarations resolves a declaration name to its residency.yaml line.
	Declarations *config.Config
}

const (
	informationURI = "https://github.com/moveeeax/tf-residency-lint"
	findingsHelp   = informationURI + "#4-findings"
)

// ruleHelp describes every rule a finding can carry. The README findings
// table is the long form.
var ruleHelp = map[string]string{
	check.RuleResidencyViolation: "The data class must stay in the jurisdiction and this resource is elsewhere.",
	check.RuleNoApprovedRegion:   "The ruleset lists no approved region for this cloud at all.",
	check.RuleConditional:        "Transfer is permitted only via a named mechanism the tool cannot verify.",
	check.RuleUnknownRegion:      "The resource carries in-scope data and no region could be determined.",
	check.RuleUnclassified:       "The resource stores data at rest and no declaration covers it.",
	check.RuleMissingRule:        "The jurisdiction's ruleset has no entry for this data class.",
	check.RuleStaleRule:          "The rule behind a finding has not been re-checked within the review cadence.",
	check.RuleExpiredWaiver:      "A waiver for this finding has expired and no longer suppresses it.",
	check.RuleWaived:             "A live waiver downgraded this finding to informational.",
}

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool      `json:"tool"`
	Results    []sarifResult  `json:"results"`
	Properties map[string]any `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifLogical struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind"`
}

// sarifLevel maps a finding severity onto a SARIF result level.
func sarifLevel(s check.Severity) string {
	switch s {
	case check.Violation:
		return "error"
	case check.Warning:
		return "warning"
	}
	return "note"
}

// SARIF writes the result as a SARIF 2.1.0 log for code scanning.
//
// A plan has no source lines, so every result is located at the residency.yaml
// declaration that classified the resource (line 1 when no declaration
// applies), with the resource address as a logical location. The citation goes
// in the message and in the result properties, because it differs per
// jurisdiction and data class while the rule does not.
func SARIF(w io.Writer, res check.Result, meta Meta) error {
	uri := filepath.ToSlash(filepath.Clean(meta.Config))

	ids := map[string]bool{}
	for _, f := range res.Findings {
		ids[f.Rule] = true
	}
	ruleIDs := make([]string, 0, len(ids))
	for id := range ids {
		ruleIDs = append(ruleIDs, id)
	}
	sort.Strings(ruleIDs)
	index := map[string]int{}
	rules := make([]sarifRule, 0, len(ruleIDs))
	for i, id := range ruleIDs {
		index[id] = i
		desc := ruleHelp[id]
		if desc == "" {
			desc = id
		}
		rules = append(rules, sarifRule{
			ID:               id,
			Name:             id,
			ShortDescription: sarifMessage{Text: desc},
			HelpURI:          findingsHelp,
		})
	}

	results := make([]sarifResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		line := 0
		if meta.Declarations != nil && f.DeclaredBy != "" {
			line = meta.Declarations.DeclarationLine(f.DeclaredBy)
		}
		if line < 1 {
			line = 1
		}
		loc := sarifLocation{PhysicalLocation: sarifPhysical{
			ArtifactLocation: sarifArtifact{URI: uri},
			Region:           sarifRegion{StartLine: line},
		}}
		if f.Address != "" {
			loc.LogicalLocations = []sarifLogical{{FullyQualifiedName: f.Address, Kind: "resource"}}
		}
		results = append(results, sarifResult{
			RuleID:    f.Rule,
			RuleIndex: index[f.Rule],
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: sarifText(f)},
			Locations: []sarifLocation{loc},
			// Every result shares one file and often one line, so the default
			// line-hash fingerprint would merge distinct findings into one alert.
			PartialFingerprints: map[string]string{"primaryLocationLineHash": fingerprint(f)},
			Properties:          findingProperties(f),
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tf-residency-lint",
				Version:        meta.Version,
				InformationURI: informationURI,
				Rules:          rules,
			}},
			Results: results,
			Properties: map[string]any{
				"disclaimer":    Disclaimer,
				"plan":          meta.Plan,
				"jurisdictions": res.Jurisdictions,
			},
		}},
	})
}

// sarifText is the one-paragraph message a code scanning alert shows.
func sarifText(f check.Finding) string {
	var parts []string
	if f.Jurisdiction != "" {
		parts = append(parts, f.Jurisdiction+":")
	}
	if f.Address != "" {
		parts = append(parts, f.Address+":")
	}
	parts = append(parts, f.Message+".")
	if f.TransferMechanism != "" {
		parts = append(parts, "Mechanism: "+f.TransferMechanism)
	}
	if f.SourceURL != "" {
		parts = append(parts, "Source: "+f.SourceURL+" (checked "+f.CheckedOn+").")
	}
	return strings.Join(parts, " ")
}

func findingProperties(f check.Finding) map[string]any {
	props := map[string]any{"severity": string(f.Severity)}
	add := func(k, v string) {
		if v != "" {
			props[k] = v
		}
	}
	add("jurisdiction", f.Jurisdiction)
	add("data_class", f.DataClass)
	add("declared_by", f.DeclaredBy)
	add("cloud", f.Cloud)
	add("region", f.Region)
	add("region_source", f.RegionSource)
	add("source_url", f.SourceURL)
	add("checked_on", f.CheckedOn)
	add("waived_from", f.WaivedFrom)
	add("waiver_reason", f.WaiverReason)
	return props
}

// fingerprint identifies a finding across runs independent of its wording.
func fingerprint(f check.Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{f.Rule, f.Jurisdiction, f.DataClass, f.Address}, "\x00")))
	return hex.EncodeToString(sum[:16])
}
