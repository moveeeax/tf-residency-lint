# Rulesets

One YAML file per jurisdiction. These files are the product's only assertion
about what the law requires, so they live in git: every change to a rule is a
diff with an author, a date and a reviewer.

## Status of the v1 jurisdictions

v1 covers eight jurisdictions and four data classes. **None of the eight are
published yet.** Each one requires reading the primary source — the act, the
implementing regulation or the regulator's circular — and recording the URL and
the date it was read. That research is not something the tool can generate, and
a fabricated citation would be worse than an empty file.

| Jurisdiction | Code | Status |
| --- | --- | --- |
| Saudi Arabia | SA | not started |
| United Arab Emirates | AE | not started |
| India | IN | not started |
| Indonesia | ID | not started |
| Vietnam | VN | not started |
| Kazakhstan | KZ | not started |
| Turkey | TR | not started |
| Brazil | BR | not started |

Russia and China are deliberately out of scope for v1.

`example/` holds two fictional jurisdictions. They exist to document the schema
and to make the README command runnable. `status: example` keeps them out of any
real gate unless `--allow-unpublished` is passed.

## Schema

```yaml
version: 1                 # schema version, must be 1
jurisdiction: SA           # ISO 3166-1 alpha-2 code, unique across the directory
name: Kingdom of Saudi Arabia
status: published          # published | draft | example
note: optional maintainer note

entries:                   # one per data class; at most one entry per class
  - data_class: personal   # personal | health | financial | government
    must_stay_local: "yes" # yes | no | conditional

    # Required when must_stay_local is "conditional": name the mechanism.
    transfer_mechanism: "..."

    # Regions where this class may lawfully sit, per cloud. Omit a cloud
    # entirely when it has no approved region — that produces a
    # `no-approved-region` finding, which is a different conversation from
    # "wrong region".
    allowed_regions:
      aws:   ["..."]
      azure: ["..."]
      gcp:   ["..."]
      oci:   ["..."]

    # Where no hyperscaler region exists in-country.
    in_country_alternatives:
      - "..."

    penalty: "..."                       # optional, free text

    source_url: "https://..."            # REQUIRED, absolute, primary source
    checked_on: "2026-07-20"             # REQUIRED, YYYY-MM-DD, not in future
```

`source_url` and `checked_on` are enforced by the loader. A file missing either
on any entry fails to load — there is no flag to bypass it.

Region strings are compared case-insensitively with spaces removed, so
`West Europe`, `westeurope` and `WestEurope` are the same region.

## Adding or refreshing a jurisdiction

1. Read the primary source. Not a law-firm summary, not a vendor blog.
2. Fill one entry per data class. If a class genuinely has no localisation
   rule, write `must_stay_local: "no"` with the source that says so — never
   leave the entry out. A missing entry means "not researched", and the engine
   reports it as such.
3. Set `checked_on` to the date you read the source, not the date of the file.
4. Keep `status: draft` until someone other than the author has read the diff.
5. Run the audit:

   ```console
   tf-residency-lint rulesets validate --rulesets ./rulesets --max-age-days 90
   ```

## Quarterly review

The review cadence is 90 days, which is what `--max-age-days` defaults to. The
review is a checked artefact, not a calendar reminder: `rulesets validate` exits
non-zero when any published entry is older than the cadence, so the review being
overdue is something CI can say out loud.

Re-reading a source and finding nothing changed still counts — bump `checked_on`
and commit that alone. A one-line diff that says "still true on this date" is
the entire point of the format.
