# tf-residency-lint

A CI gate for data residency. It reads `terraform show -json`, works out which
region every resource will actually land in, applies the data classes you
declare in `residency.yaml`, and checks them against versioned per-jurisdiction
rulesets.

Every rule carries the URL of the primary source it came from and the date
someone last read it. Every finding carries that citation through to the output.
A rule without a citation fails to load — there is no flag to bypass it.

**This is not legal advice.** No lawyer has reviewed the rulesets in this repo,
and the output is not a compliance sign-off. It tells you what a cited document
said on a stated date. Verify it with counsel before acting on it.

---

## What it does

| Command | Purpose |
| --- | --- |
| `inventory` | The map: every resource, its cloud, its region, and how that region was determined. Needs no ruleset. |
| `check` | The gate: applies rulesets to classified resources and exits non-zero on a violation. |
| `rulesets validate` | The freshness audit: which rules are stale, which classes are uncovered, which files are not publishable. |
| `policy check` | Change policy: YAML rules over the plan's resource changes, e.g. deny destroying a protected resource, require encryption on new storage. Needs no ruleset and no `residency.yaml`. |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or
internal error. A malformed plan, a missing ruleset or an uncited rule is always
`2` — this tool does not have a quiet failure mode.

## Status

The engine is complete and tested. **The jurisdiction rulesets are not.**

v1 targets eight jurisdictions — Saudi Arabia, UAE, India, Indonesia, Vietnam,
Kazakhstan, Turkey and Brazil — across four data classes. None of them are
published yet, because each one requires reading the primary source and
recording the URL and the date it was read. A fabricated citation would be worse
than an empty file. See [`rulesets/README.md`](rulesets/README.md) for the
schema, the coverage table and the research process.

What ships today under `rulesets/` are two **fictional** jurisdictions. They
document the schema and make the example below runnable. They are marked
`status: example`, which means the engine refuses to gate on them unless you
pass `--allow-unpublished`.

## Install

Requires Go 1.26 or newer.

```console
go install github.com/moveeeax/tf-residency-lint@latest
```

Or from a clone:

```console
git clone https://github.com/moveeeax/tf-residency-lint
cd tf-residency-lint
make build
```

## Usage

Everything below runs against the fixtures in this repository, so you can paste
it as-is after cloning.

### 1. The map — what have I got and where is it?

```console
$ ./tf-residency-lint inventory --plan testdata/plan.json --stateful-only
ADDRESS                                                    CLOUD    REGION             SOURCE
aws_efs_file_system.scratch                                aws      eu-west-1          provider configuration
aws_s3_bucket.customer_docs                                aws      eu-west-1          resource attribute
module.analytics.google_storage_bucket.events              gcp      eu                 resource location
module.clinical.azurerm_storage_account.records            azure    westeurope         resource location
module.core_db.aws_rds_cluster.primary                     aws      ex-central-1       availability zone
module.legacy.oci_objectstorage_bucket.archive             oci      -                  undetermined
module.observability.aws_s3_bucket.logs                    aws      us-east-1          resource attribute
module.payments.aws_dynamodb_table.ledger[0]               aws      us-east-1          resource attribute
module.payments.aws_sqs_queue.settlement                   aws      eu-west-1          provider configuration

9 resource(s) storing data at rest, of 11 total from plan (terraform 1.9.5)
```

The `SOURCE` column is the point. A region read off a resource attribute is a
fact; a region inherited from a provider block is an assumption worth checking;
`undetermined` is the tool refusing to guess.

### 2. Declare what carries what

`residency.yaml` lives in your repo. Nothing is in scope until you say so.

```yaml
version: 1
jurisdictions: [EX, WM]
default_class: none

declarations:
  - name: customer documents
    data_class: personal
    match:
      addresses: ["aws_s3_bucket.customer_docs"]

  - name: payments and settlement
    data_class: financial
    match:
      tags:
        data-class: financial

  - name: clinical records
    data_class: health
    match:
      addresses: ["module.clinical.*"]

exclusions:
  # Operational telemetry: no customer records, scrubbed at ingest.
  - "module.observability.*"
```

The full fixture is [`testdata/residency.yaml`](testdata/residency.yaml); an
annotated starter template is [`examples/residency.yaml`](examples/residency.yaml).

### 3. The gate

```console
$ terraform show -json tfplan > plan.json    # in your own repo
$ ./tf-residency-lint check \
    --plan testdata/plan.json \
    --config testdata/residency.yaml \
    --rulesets ./rulesets \
    --allow-unpublished
```

Abridged output — the full run reports 5 violations and 7 warnings across the
two fictional jurisdictions:

```
tf-residency-lint  2026-07-26 02:02:25 UTC
  plan          testdata/plan.json
  jurisdictions EX, WM
  resources     11 scanned, 7 carrying declared data

EX
--
  [violation] residency-violation
      resource   aws_s3_bucket.customer_docs (aws_s3_bucket)
      region     aws / eu-west-1 (from resource attribute)
      data class personal (declared by "customer documents")
      personal data must stay in EX but this resource is in eu-west-1
      penalty    Fictional. Up to 2% of annual turnover.
      source     https://example.invalid/examplestan/personal-data-act-2024#art-19 (checked 2026-07-20)

  [violation] no-approved-region
      resource   module.clinical.azurerm_storage_account.records (azurerm_storage_account)
      region     azure / westeurope (from resource location)
      data class health (declared by "clinical records")
      EX lists no approved azure region for health data; westeurope is not
      covered by the ruleset
      in-country Examplestan National Health Cloud (state-operated); Colocation in Example City with a licensed operator
      penalty    Fictional. Licence suspension.
      source     https://example.invalid/examplestan/health-records-rules-2025#s-7 (checked 2026-07-20)

  [warning] conditional-transfer
      resource   module.payments.aws_dynamodb_table.ledger[0] (aws_dynamodb_table)
      region     aws / us-east-1 (from resource attribute)
      data class financial (declared by "payments and settlement")
      financial data in us-east-1 is outside the EX approved list; transfer is
      permitted only via the named mechanism
      mechanism  Prior written no-objection from the Examplestan Financial
                 Authority, plus a copy of the processing agreement filed
                 within 30 days.
      penalty    Fictional. Fine per affected record.
      source     https://example.invalid/examplestan/financial-circular-11#para-4 (checked 2026-07-20)

...

5 violation(s), 7 warning(s), 0 informational

tf-residency-lint reports what the cited sources said on the dates shown. It
is not legal advice, no lawyer has reviewed these rulesets, and it is not a
compliance sign-off. Verify every cited source with counsel before acting on a
finding.

$ echo $?
1
```

Drop `--allow-unpublished` and the same command exits `0` — fictional rulesets
never gate. `--format` picks the report; the exit code does not depend on it.

| `--format` | For | Notes |
| --- | --- | --- |
| `text` (default) | people | The report above. |
| `json` | pipelines | The full result with the disclaimer in the document. `--json` is an alias. |
| `sarif` | GitHub code scanning | SARIF 2.1.0, see below. |
| `junit` | GitLab, Jenkins and other test-report views | JUnit XML, see below. |

**SARIF.** One rule per finding rule (`residency-violation`, `no-approved-region`,
…). `violation` maps to `error`, `warning` to `warning`, `info` (waived) to
`note`. A plan has no source lines, so each result points at the line in
`residency.yaml` where the declaration that classified the resource starts (line
1 when none did, e.g. `stale-rule`), and carries the resource address as a
logical location. The citation (`source_url`, `checked_on`) differs per
jurisdiction and data class, so it is in each result's message and properties;
the rule's `helpUri` points at the findings table below. The disclaimer is in
`runs[0].properties.disclaimer`. Pass `--config` as a path relative to the
repository root so code scanning can open the file.

**JUnit.** One testsuite per jurisdiction (plus `(estate-wide)` for unclassified
resources) and one testcase per (jurisdiction, resource) pair the rules were
applied to, passes included. A testcase fails when it has a finding at or above
`--fail-on`, so the test view agrees with the exit code; findings below the
threshold go to `system-out`. Ruleset-level findings (`stale-rule`) appear as
`ruleset <J>/<class>`. Every suite carries the disclaimer as a property.

### 4. Findings

| Rule | Severity | Means |
| --- | --- | --- |
| `residency-violation` | violation | The class must stay local and this resource is elsewhere. |
| `no-approved-region` | violation / warning | The ruleset lists no approved region for that cloud at all. That is an architecture decision, not a config fix. |
| `conditional-transfer` | warning | Transfer is permitted only via a named mechanism. Whether you have it is a fact the tool cannot see. |
| `unknown-region` | warning | The resource carries in-scope data and no region could be determined. Never silently passed. |
| `unclassified-stateful-resource` | warning | Stores data at rest, and no declaration covers it. Opt in with `--report-unclassified`. |
| `missing-rule` | warning | The jurisdiction has no entry for that data class — nobody has researched it. |
| `stale-rule` | warning | The rule behind a finding has not been re-checked within the review cadence. |
| `waived` / `expired-waiver` | info / warning | A waiver suppressed a finding, or stopped doing so. |

### 5. Freshness is a checked artefact

Rules go out of date. The quarterly review is enforced, not remembered:

```console
$ ./tf-residency-lint rulesets validate --rulesets ./rulesets --max-age-days 90
Rulesets loaded: EX, WM

  [not-published] EX                       status is "example"; it will not be used to gate CI
      rulesets/example/examplestan.yaml
  [not-published] WM                       status is "example"; it will not be used to gate CI
      rulesets/example/westmark.yaml
  [missing-class] WM/government            no entry for this data class
      rulesets/example/westmark.yaml
  [missing-class] WM/health                no entry for this data class
      rulesets/example/westmark.yaml

4 problem(s)
```

`stale` problems appear the same way once a `checked_on` date passes the
cadence.

## Plan policy

`policy check` is a second, independent gate over the same plan file. It
reads the `resource_changes` of `terraform show -json tfplan` and applies YAML
rules: matchers over resource type, address, change action, tags and
attribute values. No policy server, no new language, no cloud credentials.

```console
$ ./tf-residency-lint policy check \
    --plan testdata/policy/plan.json \
    --rules ./policies \
    --rules testdata/policy/exemptions.yaml
```

Abridged output (the full run reports 8 denied, 2 warnings, 1 exempted):

```
  [violation] protected-destroy
      resource   module.db.aws_db_instance.main (aws_db_instance)
      action     replace
      resource tagged protected=true would be destroyed
      rule       policies/protect.yaml:7

  [violation] s3-public-access-block
      resource   aws_s3_bucket_public_access_block.site (aws_s3_bucket_public_access_block)
      action     create
      S3 public access block does not block all four kinds of public access
      failed     block_public_policy equals true
      failed     restrict_public_buckets equals true
      rule       policies/public-access.yaml:5

  [warning] ebs-volume-encrypted
      resource   aws_ebs_volume.cache (aws_ebs_volume)
      action     create
      new EBS volume is not encrypted at rest (undetermined: encrypted known
      only after apply)
      rule       policies/encryption.yaml:13
```

`--rules` takes a file or a directory and can be repeated; extra positional
arguments are rule files too, so `--rules policy/*.yaml` works after shell
expansion. `--format` (`text`, `json`, `sarif`, `junit`) and the exit codes
work as for `check`. `--fail-on` also accepts `deny` and `warn`.

### Starter rules

[`policies/`](policies) ships rules you can copy into your repo and edit:

| File | Rules |
| --- | --- |
| `protect.yaml` | `protected-destroy`: deny delete or replace of a resource tagged `protected = "true"`. |
| `encryption.yaml` | Deny new EBS volumes, RDS instances and clusters, Redshift clusters, ElastiCache replication groups and OpenSearch domains without encryption at rest. |
| `public-access.yaml` | Deny an S3 public access block that leaves any of its four settings off, a publicly accessible RDS or Redshift database, an Azure storage account with `allow_nested_items_to_be_public`; warn on a GCS bucket without `public_access_prevention = "enforced"`. |

The encryption rules cover only types where encryption at rest is opt-in. S3,
DynamoDB, EFS, Azure Storage and Google Cloud Storage encrypt at rest without
a setting, so rules for them would never fire.

### Rule schema

```yaml
version: 1
rules:
  - id: rds-storage-encrypted        # lowercase, unique across all loaded files
    description: new RDS instance is not encrypted at rest   # the finding message
    severity: deny                   # deny | warn
    match:                           # AND across fields, OR within a list
      actions: [create]              # required: create, update, delete, replace, read, forget, no-op
      resource_types: ["aws_db_*"]   # globs
      addresses: ["module.db.*"]     # same globs as residency.yaml
      tags: {tier: prod}             # every tag must match; "*" matches any value
      attributes:                    # conditions that must all hold to select
        - path: engine
          in: [postgres, mysql]
    require:                         # optional: conditions every selected change must meet
      - path: storage_encrypted
        equals: true

exemptions:
  - rule: rds-storage-encrypted
    address: module.db.aws_db_instance.legacy
    reason: Migrated to an encrypted cluster in TICKET-123; old instance retires next sprint.
    expires_on: "2026-12-31"
```

A rule without `require` fires on every change it selects (the destroy rule
works this way). A rule with `require` fires when a selected change fails a
condition. Conditions take a `path` and exactly one operator: `exists`
(true/false), `equals`, `not_equals`, `in`, `not_in`. Paths are dot-separated;
nested blocks are lists in plan JSON, so write `encrypt_at_rest.0.enabled`, or
`encrypt_at_rest.*.enabled` for every element. A path that leads nowhere has no
value: `equals` and `in` fail on it, `not_equals` and `not_in` pass.

Which object a rule sees depends on the change. A delete or replace is
evaluated against the prior state, so the protection tag counts even when the
same plan removes it; everything else is evaluated against the planned state.
Tags are read from `tags`, `tags_all`, `labels` and `freeform_tags`. `delete`
in `actions` also matches replacements, and `create` matches them too,
because a replacement creates a new object.

**Unknown is not clean here either.** When a value is only known after apply
(an unset computed attribute, an interpolated tag), the finding is reported as
a warning marked undetermined, never as a pass and never as a deny the plan
cannot back up.

**Exemptions need a reason and an expiry.** A live exemption downgrades the
finding to `info`; an expired one stops suppressing and the finding says so.
An exemption that names a rule no loaded file defines is a load error.

**Values stay out of the report.** Policy rules have to read attribute values,
but a finding names the attribute path and the condition from the rule file,
never the value from the plan.

SARIF results point at the line of the rules file where the failing rule
starts, with the resource address as a logical location; every loaded rule is
listed in the driver. JUnit has one testsuite per rule and one testcase per
resource change the rule selected, passes included.

## In CI

```yaml
- name: Residency gate
  run: |
    terraform show -json tfplan > plan.json
    tf-residency-lint check \
      --plan plan.json \
      --config residency.yaml \
      --rulesets ./rulesets \
      --report-unclassified
```

With the change policy alongside:

```yaml
- name: Plan policy
  run: tf-residency-lint policy check --plan plan.json --rules ./policies
```

As code scanning alerts on GitHub:

```yaml
- name: Residency gate
  run: |
    tf-residency-lint check --plan plan.json --config residency.yaml \
      --rulesets ./rulesets --format sarif > residency.sarif
- uses: github/codeql-action/upload-sarif@v4
  if: always()
  with:
    sarif_file: residency.sarif
    category: tf-residency-lint
```

As test results on GitLab:

```yaml
residency:
  script:
    - tf-residency-lint check --plan plan.json --config residency.yaml --rulesets ./rulesets --format junit > residency.xml
  artifacts:
    when: always
    reports:
      junit: residency.xml
```

## Design decisions

**Classification is declared, never inferred.** Which bucket holds patient
records is a business fact only the customer has. Guessing it from a resource
name would produce findings nobody can act on and misses nobody can detect.

**Attribute values never leave the parser.** `terraform show -json` contains
passwords and key material. The parser reads attributes to find a region and a
tag set and drops everything else, because residency reports get pasted into
tickets. There is a test that greps the parsed inventory for the fixture's
secrets.

**Unknown is not clean.** A region that cannot be determined, a jurisdiction
with no ruleset, a plan file that is not a plan — each is a finding or an error.
The one outcome this tool must never produce is a quiet green.

**The map is free.** `inventory` needs no rulesets, no config and no account. It
is deliberately the most useful thing here that costs nothing.

## Development

```console
make test    # go test -race ./...
make lint    # gofmt -l . && go vet ./...
make build
```

Fixtures live in `testdata/` (`testdata/policy/` for the plan policy). Every
jurisdiction in the fixtures and in `rulesets/` is fictional, and every URL in
them is under `example.invalid`.

## License

[MIT](LICENSE)
