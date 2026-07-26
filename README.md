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
never gate. `--json` emits the same result machine-readably, with the disclaimer
carried in the document.

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

Fixtures live in `testdata/`. Every jurisdiction in the fixtures and in
`rulesets/` is fictional, and every URL in them is under `example.invalid`.
