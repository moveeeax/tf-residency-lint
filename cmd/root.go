// Package cmd wires the tf-residency-lint CLI.
package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/moveeeax/tf-residency-lint/internal/check"
	"github.com/moveeeax/tf-residency-lint/internal/config"
	"github.com/moveeeax/tf-residency-lint/internal/plan"
	"github.com/moveeeax/tf-residency-lint/internal/report"
	"github.com/moveeeax/tf-residency-lint/internal/ruleset"
)

// Exit codes: 0 = clean, 1 = findings at or above --fail-on, 2 = usage or
// internal error. CI gates on 1; 2 must never be mistaken for a pass.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 2
)

// Version is stamped at build time: -ldflags "-X .../cmd.Version=v0.1.0".
var Version = "dev"

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) (int, error) {
	code := exitOK

	root := &cobra.Command{
		Use:   "tf-residency-lint",
		Short: "Gate Terraform changes on data-residency rules",
		Long: "tf-residency-lint reads `terraform show -json`, maps every resource to the\n" +
			"region it will live in, applies the data classes declared in residency.yaml,\n" +
			"and checks them against versioned per-jurisdiction rulesets.\n\n" +
			report.Disclaimer,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	root.AddCommand(checkCmd(&code), inventoryCmd(), rulesetsCmd(&code))

	if err := root.Execute(); err != nil {
		return exitError, err
	}
	return code, nil
}

func checkCmd(code *int) *cobra.Command {
	var (
		planPath     string
		configPath   string
		rulesetsPath string
		asJSON       bool
		format       string
		failOn       string
		maxAgeDays   int
		unclassified bool
		unpublished  bool
	)

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check a plan against the residency rulesets",
		Example: "  terraform show -json tfplan > plan.json\n" +
			"  tf-residency-lint check --plan plan.json --config residency.yaml --rulesets ./rulesets\n" +
			"  tf-residency-lint check --plan plan.json --format sarif > residency.sarif",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			severity, ok := check.ParseSeverity(failOn)
			if !ok {
				return fmt.Errorf("--fail-on must be violation, warning or info, got %q", failOn)
			}
			// --json predates --format and stays as an alias for --format json.
			if asJSON {
				if c.Flags().Changed("format") && format != "json" {
					return fmt.Errorf("--json conflicts with --format %s", format)
				}
				format = "json"
			}
			if !validFormat(format) {
				return fmt.Errorf("--format must be one of %s, got %q", strings.Join(checkFormats, ", "), format)
			}
			inv, err := loadPlan(planPath)
			if err != nil {
				return err
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				return err
			}
			set, err := ruleset.LoadDir(rulesetsPath)
			if err != nil {
				return err
			}

			res, err := check.Run(inv, cfg, set, check.Options{
				Now:                time.Now().UTC(),
				MaxRuleAge:         time.Duration(maxAgeDays) * 24 * time.Hour,
				ReportUnclassified: unclassified,
				AllowUnpublished:   unpublished,
			})
			if err != nil {
				return err
			}

			for _, f := range res.Findings {
				if f.Severity.AtLeast(severity) {
					*code = exitFindings
					break
				}
			}

			meta := report.Meta{
				Plan:         planPath,
				Config:       configPath,
				Version:      Version,
				FailOn:       severity,
				Declarations: cfg,
			}
			switch format {
			case "json":
				return report.JSON(c.OutOrStdout(), res, planPath)
			case "sarif":
				return report.SARIF(c.OutOrStdout(), res, meta)
			case "junit":
				return report.JUnit(c.OutOrStdout(), res, meta)
			}
			report.Pretty(c.OutOrStdout(), res, planPath)
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVar(&planPath, "plan", "", "path to `terraform show -json` output, or - for stdin (required)")
	f.StringVar(&configPath, "config", "residency.yaml", "path to the residency declaration file")
	f.StringVar(&rulesetsPath, "rulesets", "rulesets", "directory of versioned jurisdiction rulesets")
	f.BoolVar(&asJSON, "json", false, "emit machine-readable JSON (alias for --format json)")
	f.StringVar(&format, "format", "text", "output format: "+strings.Join(checkFormats, ", "))
	f.StringVar(&failOn, "fail-on", string(check.Violation), "minimum severity that exits non-zero: violation, warning, info")
	f.IntVar(&maxAgeDays, "max-rule-age-days", 90, "flag findings that rest on rules unverified for longer than this")
	f.BoolVar(&unclassified, "report-unclassified", false, "warn about stateful resources no declaration covers")
	f.BoolVar(&unpublished, "allow-unpublished", false, "let draft and example rulesets produce findings")
	_ = cmd.MarkFlagRequired("plan")
	return cmd
}

// checkFormats are the report formats `check` can write.
var checkFormats = []string{"text", "json", "sarif", "junit"}

func validFormat(f string) bool {
	for _, known := range checkFormats {
		if f == known {
			return true
		}
	}
	return false
}

func inventoryCmd() *cobra.Command {
	var (
		planPath     string
		asJSON       bool
		statefulOnly bool
	)

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List every resource and the region it lands in",
		Long: "inventory is the map: what the plan creates, which cloud and region each\n" +
			"resource lands in, and how that region was determined. It applies no rules\n" +
			"and needs no ruleset, so it works before any residency research exists.",
		Example: "  tf-residency-lint inventory --plan plan.json --stateful-only",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			inv, err := loadPlan(planPath)
			if err != nil {
				return err
			}
			if asJSON {
				return report.InventoryJSON(c.OutOrStdout(), inv, statefulOnly)
			}
			report.Inventory(c.OutOrStdout(), inv, statefulOnly)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&planPath, "plan", "", "path to `terraform show -json` output, or - for stdin (required)")
	f.BoolVar(&asJSON, "json", false, "emit machine-readable JSON")
	f.BoolVar(&statefulOnly, "stateful-only", false, "only resources that store data at rest")
	_ = cmd.MarkFlagRequired("plan")
	return cmd
}

func rulesetsCmd(code *int) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rulesets",
		Short: "Inspect and audit the jurisdiction rulesets",
		Args:  cobra.NoArgs,
		RunE:  func(c *cobra.Command, _ []string) error { return c.Help() },
	}

	var (
		rulesetsPath string
		asJSON       bool
		maxAgeDays   int
	)
	validate := &cobra.Command{
		Use:   "validate",
		Short: "Audit ruleset coverage and freshness",
		Long: "validate is the quarterly review as a checked artefact: it reports rulesets\n" +
			"that are not published, data classes with no entry, and entries whose\n" +
			"checked_on date is older than the review cadence.",
		Example: "  tf-residency-lint rulesets validate --rulesets ./rulesets --max-age-days 90",
		Args:    cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			set, err := ruleset.LoadDir(rulesetsPath)
			if err != nil {
				return err
			}
			classes := make([]string, 0, 4)
			for _, cl := range config.KnownClasses() {
				classes = append(classes, string(cl))
			}
			problems := set.Validate(time.Now().UTC(), time.Duration(maxAgeDays)*24*time.Hour, classes)
			if len(problems) > 0 {
				*code = exitFindings
			}
			if asJSON {
				return report.ProblemsJSON(c.OutOrStdout(), problems, set.Jurisdictions())
			}
			report.Problems(c.OutOrStdout(), problems, set.Jurisdictions())
			return nil
		},
	}
	vf := validate.Flags()
	vf.StringVar(&rulesetsPath, "rulesets", "rulesets", "directory of versioned jurisdiction rulesets")
	vf.BoolVar(&asJSON, "json", false, "emit machine-readable JSON")
	vf.IntVar(&maxAgeDays, "max-age-days", 90, "maximum age of a checked_on date before it is stale")

	cmd.AddCommand(validate)
	return cmd
}

func loadPlan(path string) (plan.Inventory, error) {
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return plan.Inventory{}, fmt.Errorf("read plan: %w", err)
	}
	inv, err := plan.Parse(data)
	if err != nil {
		return plan.Inventory{}, fmt.Errorf("%s: %w", path, err)
	}
	return inv, nil
}
