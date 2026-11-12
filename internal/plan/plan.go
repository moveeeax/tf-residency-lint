// Package plan turns `terraform show -json` output into a flat resource
// inventory annotated with the cloud and region each resource lives in.
//
// It accepts both shapes that command emits: a plan document (`terraform show
// -json tfplan`, which carries `planned_values`) and a state document
// (`terraform show -json`, which carries `values`).
//
// The parser keeps only the address, type, provider, region and tags of a
// resource. Attribute values are read and dropped inside Parse so that no
// password, key material or `sensitive_values` blob can survive into a report
// that gets pasted into a ticket.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Cloud is the hyperscaler a resource belongs to, derived from its type prefix.
type Cloud string

const (
	AWS     Cloud = "aws"
	Azure   Cloud = "azure"
	GCP     Cloud = "gcp"
	OCI     Cloud = "oci"
	Unknown Cloud = "unknown"
)

// RegionSource records how a region was determined, so a finding can explain
// itself rather than asserting a region the reader cannot locate in their code.
type RegionSource string

const (
	FromAttribute        RegionSource = "resource attribute"
	FromLocation         RegionSource = "resource location"
	FromAvailabilityZone RegionSource = "availability zone"
	FromProviderConfig   RegionSource = "provider configuration"
	FromNone             RegionSource = "undetermined"
)

// Resource is one managed or data resource in the estate.
type Resource struct {
	Address      string            `json:"address"`
	Type         string            `json:"type"`
	Name         string            `json:"name"`
	Mode         string            `json:"mode"`
	Cloud        Cloud             `json:"cloud"`
	Region       string            `json:"region"`
	RegionSource RegionSource      `json:"region_source"`
	Tags         map[string]string `json:"tags,omitempty"`
	Stateful     bool              `json:"stateful"`
}

// Inventory is the parsed estate.
type Inventory struct {
	// Format is "plan" or "state", i.e. which half of the document we read.
	Format    string     `json:"format"`
	Terraform string     `json:"terraform_version,omitempty"`
	Resources []Resource `json:"resources"`
}

// Stateful returns only the resources that hold data at rest.
func (i Inventory) Stateful() []Resource {
	out := make([]Resource, 0, len(i.Resources))
	for _, r := range i.Resources {
		if r.Stateful {
			out = append(out, r)
		}
	}
	return out
}

type document struct {
	FormatVersion    string      `json:"format_version"`
	TerraformVersion string      `json:"terraform_version"`
	PlannedValues    *valuesDoc  `json:"planned_values"`
	Values           *valuesDoc  `json:"values"`
	Configuration    *configDoc  `json:"configuration"`
	ResourceChanges  []rawChange `json:"resource_changes"`
}

type valuesDoc struct {
	RootModule moduleDoc `json:"root_module"`
}

type moduleDoc struct {
	Address      string        `json:"address"`
	Resources    []rawResource `json:"resources"`
	ChildModules []moduleDoc   `json:"child_modules"`
}

type rawResource struct {
	Address      string         `json:"address"`
	Mode         string         `json:"mode"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	ProviderName string         `json:"provider_name"`
	Values       map[string]any `json:"values"`
}

type rawChange struct {
	Address string `json:"address"`
}

type configDoc struct {
	ProviderConfig map[string]providerConfig `json:"provider_config"`
	RootModule     configModule              `json:"root_module"`
}

type providerConfig struct {
	Name        string                     `json:"name"`
	Alias       string                     `json:"alias"`
	Expressions map[string]json.RawMessage `json:"expressions"`
}

type configModule struct {
	Resources   []configResource      `json:"resources"`
	ModuleCalls map[string]moduleCall `json:"module_calls"`
}

type moduleCall struct {
	Module configModule `json:"module"`
}

type configResource struct {
	Address           string `json:"address"`
	Mode              string `json:"mode"`
	Type              string `json:"type"`
	ProviderConfigKey string `json:"provider_config_key"`
}

// ErrNotTerraformJSON is returned for documents that are syntactically JSON but
// are not `terraform show -json` output. Reporting "no resources in scope" for
// the wrong file would be a silent false green in CI.
var ErrNotTerraformJSON = errors.New("not a terraform show -json document")

// Parse reads a `terraform show -json` document into an Inventory.
func Parse(data []byte) (Inventory, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return Inventory{}, fmt.Errorf("parse terraform json: %w", err)
	}
	if doc.FormatVersion == "" && doc.TerraformVersion == "" {
		return Inventory{}, ErrNotTerraformJSON
	}

	inv := Inventory{Terraform: doc.TerraformVersion}
	var root *moduleDoc
	switch {
	case doc.PlannedValues != nil:
		inv.Format = "plan"
		root = &doc.PlannedValues.RootModule
	case doc.Values != nil:
		inv.Format = "state"
		root = &doc.Values.RootModule
	default:
		return Inventory{}, fmt.Errorf("%w: no planned_values or values block", ErrNotTerraformJSON)
	}

	providerRegions := providerRegionMap(doc.Configuration)
	resourceProvider := resourceProviderMap(doc.Configuration)

	collect(root, &inv, providerRegions, resourceProvider)
	sort.Slice(inv.Resources, func(a, b int) bool {
		return inv.Resources[a].Address < inv.Resources[b].Address
	})
	return inv, nil
}

func collect(m *moduleDoc, inv *Inventory, providerRegions, resourceProvider map[string]string) {
	for _, raw := range m.Resources {
		inv.Resources = append(inv.Resources, convert(raw, providerRegions, resourceProvider))
	}
	for i := range m.ChildModules {
		collect(&m.ChildModules[i], inv, providerRegions, resourceProvider)
	}
}

func convert(raw rawResource, providerRegions, resourceProvider map[string]string) Resource {
	r := Resource{
		Address:      raw.Address,
		Type:         raw.Type,
		Name:         raw.Name,
		Mode:         raw.Mode,
		Cloud:        cloudOf(raw.Type, raw.ProviderName),
		RegionSource: FromNone,
		Stateful:     raw.Mode != "data" && IsStateful(raw.Type),
		Tags:         extractTags(raw.Values),
	}
	if r.Mode == "" {
		r.Mode = "managed"
	}

	region, src := regionFromValues(r.Cloud, raw.Values)
	if region == "" {
		if key, ok := resourceProvider[normalizeAddress(raw.Address)]; ok {
			if reg, ok := lookupProviderRegion(providerRegions, key); ok {
				region, src = reg, FromProviderConfig
			}
		}
		// A single unaliased provider block is by far the common case; fall back
		// to it rather than reporting every resource as region-unknown.
		if region == "" {
			if reg, ok := lookupProviderRegion(providerRegions, string(r.Cloud)); ok {
				region, src = reg, FromProviderConfig
			}
		}
	}
	r.Region = normalizeRegion(region)
	if r.Region != "" {
		r.RegionSource = src
	}
	// raw.Values goes out of scope here: nothing but region and tags survives.
	return r
}

func cloudOf(resourceType, providerName string) Cloud {
	switch {
	case strings.HasPrefix(resourceType, "aws_"):
		return AWS
	case strings.HasPrefix(resourceType, "azurerm_"), strings.HasPrefix(resourceType, "azuread_"):
		return Azure
	case strings.HasPrefix(resourceType, "google_"):
		return GCP
	case strings.HasPrefix(resourceType, "oci_"):
		return OCI
	}
	switch {
	case strings.Contains(providerName, "/aws"):
		return AWS
	case strings.Contains(providerName, "/azurerm"):
		return Azure
	case strings.Contains(providerName, "/google"):
		return GCP
	case strings.Contains(providerName, "/oci"):
		return OCI
	}
	return Unknown
}

var azSuffix = regexp.MustCompile(`^([a-z]{2}(?:-[a-z]+)+-\d)[a-z]$`)

func regionFromValues(cloud Cloud, values map[string]any) (string, RegionSource) {
	if values == nil {
		return "", FromNone
	}
	if s, ok := stringValue(values, "region"); ok {
		return s, FromAttribute
	}
	if s, ok := stringValue(values, "location"); ok {
		return s, FromLocation
	}
	if cloud == AWS {
		if s, ok := stringValue(values, "availability_zone"); ok {
			if m := azSuffix.FindStringSubmatch(s); m != nil {
				return m[1], FromAvailabilityZone
			}
		}
		if raw, ok := values["availability_zones"]; ok {
			if list, ok := raw.([]any); ok && len(list) > 0 {
				if s, ok := list[0].(string); ok {
					if m := azSuffix.FindStringSubmatch(s); m != nil {
						return m[1], FromAvailabilityZone
					}
				}
			}
		}
	}
	return "", FromNone
}

func stringValue(values map[string]any, key string) (string, bool) {
	raw, ok := values[key]
	if !ok {
		return "", false
	}
	s, ok := raw.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	return s, true
}

// tagKeys are the attributes each provider uses for user-supplied labels. Only
// freeform tags are read; OCI defined_tags are namespaced governance metadata
// and are not something a customer maps a data class onto.
var tagKeys = []string{"tags", "tags_all", "labels", "freeform_tags"}

func extractTags(values map[string]any) map[string]string {
	if values == nil {
		return nil
	}
	out := map[string]string{}
	for _, key := range tagKeys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeRegion folds the spellings the providers accept into one form, so
// "West Europe", "westeurope" and "WestEurope" all compare equal to a ruleset
// entry.
func normalizeRegion(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	return strings.ReplaceAll(s, " ", "")
}

// NormalizeRegion is exported for the ruleset loader, which must fold the
// regions it reads from YAML in exactly the same way.
func NormalizeRegion(s string) string { return normalizeRegion(s) }

var indexSuffix = regexp.MustCompile(`\[[^\]]*\]`)

// normalizeAddress strips count/for_each indices so that a planned address such
// as `module.app.aws_instance.worker[0]` matches the configuration address
// `module.app.aws_instance.worker`.
func normalizeAddress(addr string) string {
	return indexSuffix.ReplaceAllString(addr, "")
}

// NormalizeAddress is exported so matching rules elsewhere use one definition.
func NormalizeAddress(addr string) string { return normalizeAddress(addr) }

func providerRegionMap(cfg *configDoc) map[string]string {
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	for key, pc := range cfg.ProviderConfig {
		for _, attr := range []string{"region", "location"} {
			raw, ok := pc.Expressions[attr]
			if !ok {
				continue
			}
			var expr struct {
				ConstantValue any `json:"constant_value"`
			}
			if err := json.Unmarshal(raw, &expr); err != nil {
				continue
			}
			if s, ok := expr.ConstantValue.(string); ok && s != "" {
				out[key] = s
				break
			}
		}
	}
	return out
}

// lookupProviderRegion resolves a provider_config_key against the provider
// config map. Keys inside modules are qualified ("module.app:aws"), so fall
// back to the segment after the last colon and then to the bare provider name.
func lookupProviderRegion(regions map[string]string, key string) (string, bool) {
	if key == "" {
		return "", false
	}
	if v, ok := regions[key]; ok {
		return v, true
	}
	if i := strings.LastIndex(key, ":"); i >= 0 {
		if v, ok := regions[key[i+1:]]; ok {
			return v, true
		}
	}
	if v, ok := regions[key]; ok {
		return v, true
	}
	return "", false
}

func resourceProviderMap(cfg *configDoc) map[string]string {
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	walkConfigModule("", cfg.RootModule, out)
	return out
}

func walkConfigModule(prefix string, m configModule, out map[string]string) {
	for _, r := range m.Resources {
		addr := r.Address
		if addr == "" {
			continue
		}
		out[normalizeAddress(prefix+addr)] = r.ProviderConfigKey
	}
	for name, call := range m.ModuleCalls {
		walkConfigModule(prefix+"module."+name+".", call.Module, out)
	}
}

// ExtractTags reads the user-supplied labels from a resource's attribute
// values, so the policy engine reads tags exactly as the inventory does.
func ExtractTags(values map[string]any) map[string]string { return extractTags(values) }
