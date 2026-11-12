# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Minimum Go version is now 1.26; CI tests Go 1.26 and 1.27.
- YAML parsing moved from the archived `gopkg.in/yaml.v3` to its maintained
  fork `go.yaml.in/yaml/v3` v3.0.6.
- `github.com/spf13/cobra` upgraded to v1.10.2.
- CI uses `actions/checkout` v7 and `actions/setup-go` v7; Dependabot keeps
  actions and Go modules current.

### Added

- MIT license.
- `check --format text|json|sarif|junit`. SARIF 2.1.0 for GitHub code scanning
  (one rule per finding rule, results located at the matching `residency.yaml`
  declaration with the resource address as a logical location, disclaimer in
  `run.properties`); JUnit XML with one testcase per (jurisdiction, resource)
  for GitLab and Jenkins. `--json` stays as an alias for `--format json`.
- `policy check`: YAML rules over the plan's `resource_changes`, matching on
  resource type, address, change action, tags and attribute values, with
  `deny` and `warn` severities and exemptions that need a reason and an
  expiry. Values only known after apply produce undetermined warnings.
  Text, JSON, SARIF and JUnit output. Starter rules in `policies/`: deny
  destroy or replace of resources tagged `protected = "true"`, require
  encryption at rest on new EBS, RDS, Redshift, ElastiCache and OpenSearch
  storage, block public S3 access blocks, public databases and public Azure
  blobs, warn on GCS buckets without enforced public access prevention.
  Carried over from the archived `tf-plan-policy` idea.

## [0.1.0] - 2026-07-26

### Added

- `inventory`: map `terraform show -json` output to resources and regions.
- `check`: residency gate against declared data classes in `residency.yaml`
  and versioned per-jurisdiction rulesets with mandatory citations.
- `rulesets validate`: audit rulesets for citations, publication status and
  review freshness.
- Text and JSON reports.

[Unreleased]: https://github.com/moveeeax/tf-residency-lint/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moveeeax/tf-residency-lint/releases/tag/v0.1.0
