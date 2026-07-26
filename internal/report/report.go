// Package report renders a check result for humans and for machines.
//
// Both renderers emit the disclaimer. It is not decoration: this tool reports
// what a cited document said on a given date, and a reader who takes that for
// legal advice has been misled by the deliverable, not by their lawyer.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/plan"
	"github.com/moveeeax/tf-residency-lint/internal/ruleset"
)

// Disclaimer is attached to every deliverable this tool produces.
const Disclaimer = "tf-residency-lint reports what the cited sources said on the dates shown. " +
	"It is not legal advice, no lawyer has reviewed these rulesets, and it is not a compliance sign-off. " +
	"Verify every cited source with counsel before acting on a finding."

// Pretty writes a human-readable report.
func Pretty(w io.Writer, res check.Result, planPath string) {
	counts := res.Counts()
	fmt.Fprintf(w, "tf-residency-lint  %s\n", res.GeneratedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(w, "  plan          %s\n", planPath)
	fmt.Fprintf(w, "  jurisdictions %s\n", strings.Join(res.Jurisdictions, ", "))
	fmt.Fprintf(w, "  resources     %d scanned, %d carrying declared data\n\n", res.Scanned, res.InScope)

	if len(res.Findings) == 0 {
		fmt.Fprintf(w, "No findings.\n\n")
		fmt.Fprintf(w, "%s\n", wrap(Disclaimer, 78))
		return
	}

	byJurisdiction := map[string][]check.Finding{}
	var order []string
	for _, f := range res.Findings {
		key := f.Jurisdiction
		if key == "" {
			key = "(estate-wide)"
		}
		if _, seen := byJurisdiction[key]; !seen {
			order = append(order, key)
		}
		byJurisdiction[key] = append(byJurisdiction[key], f)
	}
	sort.Strings(order)

	for _, j := range order {
		fmt.Fprintf(w, "%s\n%s\n", j, strings.Repeat("-", len(j)))
		for _, f := range byJurisdiction[j] {
			fmt.Fprintf(w, "  [%s] %s\n", f.Severity, f.Rule)
			if f.Address != "" {
				fmt.Fprintf(w, "      resource   %s (%s)\n", f.Address, f.ResourceType)
			}
			if f.Region != "" {
				fmt.Fprintf(w, "      region     %s / %s (from %s)\n", f.Cloud, f.Region, f.RegionSource)
			}
			if f.DataClass != "" {
				fmt.Fprintf(w, "      data class %s", f.DataClass)
				if f.DeclaredBy != "" {
					fmt.Fprintf(w, " (declared by %q)", f.DeclaredBy)
				}
				fmt.Fprintln(w)
			}
			fmt.Fprintf(w, "      %s\n", wrapIndent(f.Message, 72, "      "))
			if f.TransferMechanism != "" {
				fmt.Fprintf(w, "      mechanism  %s\n", wrapIndent(f.TransferMechanism, 60, "                 "))
			}
			if len(f.Alternatives) > 0 {
				fmt.Fprintf(w, "      in-country %s\n", strings.Join(f.Alternatives, "; "))
			}
			if f.Penalty != "" {
				fmt.Fprintf(w, "      penalty    %s\n", f.Penalty)
			}
			if f.WaiverReason != "" {
				fmt.Fprintf(w, "      waiver     %s\n", f.WaiverReason)
			}
			if f.SourceURL != "" {
				fmt.Fprintf(w, "      source     %s (checked %s)\n", f.SourceURL, f.CheckedOn)
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintf(w, "%d violation(s), %d warning(s), %d informational\n\n",
		counts[check.Violation], counts[check.Warning], counts[check.Info])
	fmt.Fprintf(w, "%s\n", wrap(Disclaimer, 78))
}

// jsonReport is the machine-readable shape. It is a separate struct so that the
// disclaimer travels with the data even when a pipeline throws away stdout.
type jsonReport struct {
	Tool       string       `json:"tool"`
	Plan       string       `json:"plan"`
	Result     check.Result `json:"result"`
	Disclaimer string       `json:"disclaimer"`
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, res check.Result, planPath string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if res.Findings == nil {
		res.Findings = []check.Finding{}
	}
	return enc.Encode(jsonReport{
		Tool:       "tf-residency-lint",
		Plan:       planPath,
		Result:     res,
		Disclaimer: Disclaimer,
	})
}

// Inventory writes the resource map: what exists, where it is, and how the
// region was determined. This half of the product is free forever.
func Inventory(w io.Writer, inv plan.Inventory, statefulOnly bool) {
	rows := inv.Resources
	if statefulOnly {
		rows = inv.Stateful()
	}
	fmt.Fprintf(w, "%-58s %-8s %-18s %s\n", "ADDRESS", "CLOUD", "REGION", "SOURCE")
	for _, r := range rows {
		region := r.Region
		if region == "" {
			region = "-"
		}
		fmt.Fprintf(w, "%-58s %-8s %-18s %s\n", r.Address, r.Cloud, region, r.RegionSource)
	}
	fmt.Fprintf(w, "\n%d resource(s)", len(rows))
	if statefulOnly {
		fmt.Fprintf(w, " storing data at rest, of %d total", len(inv.Resources))
	}
	fmt.Fprintf(w, " from %s (terraform %s)\n", inv.Format, inv.Terraform)
}

// InventoryJSON writes the resource map as JSON.
func InventoryJSON(w io.Writer, inv plan.Inventory, statefulOnly bool) error {
	if statefulOnly {
		inv.Resources = inv.Stateful()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(inv)
}

// Problems writes the ruleset audit.
func Problems(w io.Writer, problems []ruleset.Problem, jurisdictions []string) {
	fmt.Fprintf(w, "Rulesets loaded: %s\n\n", strings.Join(jurisdictions, ", "))
	if len(problems) == 0 {
		fmt.Fprintln(w, "No ruleset problems.")
		return
	}
	for _, p := range problems {
		where := p.Jurisdiction
		if p.DataClass != "" {
			where += "/" + p.DataClass
		}
		fmt.Fprintf(w, "  [%s] %-24s %s\n", p.Kind, where, p.Message)
		if p.Path != "" {
			fmt.Fprintf(w, "      %s\n", p.Path)
		}
	}
	fmt.Fprintf(w, "\n%d problem(s)\n", len(problems))
}

// ProblemsJSON writes the ruleset audit as JSON.
func ProblemsJSON(w io.Writer, problems []ruleset.Problem, jurisdictions []string) error {
	if problems == nil {
		problems = []ruleset.Problem{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Jurisdictions []string          `json:"jurisdictions"`
		Problems      []ruleset.Problem `json:"problems"`
		Disclaimer    string            `json:"disclaimer"`
	}{jurisdictions, problems, Disclaimer})
}

func wrap(s string, width int) string { return wrapIndent(s, width, "") }

func wrapIndent(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	line := words[0]
	for _, word := range words[1:] {
		if len(line)+1+len(word) > width {
			b.WriteString(line + "\n" + indent)
			line = word
			continue
		}
		line += " " + word
	}
	b.WriteString(line)
	return b.String()
}
