# ext.0.1.nuclei Shadow API Discovery via nuclei

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0); guarantee 0.1 partially covered by
> external tools (see roadmap) · **Source of truth:**
> [`src/external_tests/ext_test_0_1_shadow_api_nuclei.py`](../../../../src/external_tests/ext_test_0_1_shadow_api_nuclei.py),
> [`src/connectors/nuclei.py`](../../../../src/connectors/nuclei.py) · **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `ext.0.1.nuclei` |
| Name | Shadow API Discovery via nuclei (template-based exposure detection) |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| CWE | CWE-200 |
| Depends on | none |
| Tool | nuclei 3.8.0 with nuclei-templates 10.4.3 (pinned by `install_tools.sh`) |
| Configuration | [`external_tools.nuclei`](../../../reference/configuration.md#external_tools) |
| Companion test | [`0.1`](../../domain-0/0-1-shadow-api-discovery.md) |

## What it checks

Known exposure patterns on the target (admin panels, debug endpoints, exposed API documentation, common
misconfigurations), detected with community-maintained nuclei templates. It complements test 0.1: 0.1 compares
live paths with the project's own specification; this test looks for patterns that are known to be dangerous,
whatever the specification says.

## How it works

Runs the nuclei binary against `target.base_url`:

```
nuclei -u <base_url> -t <template_dir> -tags <tags> -timeout <per_request_timeout> -rl <rate_limit_rps> \
       -duc -ni -no-color -je <temporary file> [extra_flags]
```

`-duc` disables update checks, `-ni` disables interactsh out-of-band callbacks (no traffic to third parties),
`-no-color` and `-je` give clean JSON output. Each nuclei result is classified by `info.severity`:

| Severity | Result |
|---|---|
| `critical`, `high`, `medium` | One Finding each: `[nuclei:<template-id>] <name>` |
| `low`, `info` | One InfoNote each: `[<severity>] <name>` |
| Any other value | Treated as InfoNote, with a warning in the log |

The binary is looked up in `./tools/nuclei/nuclei` (relative to the working directory), then in `PATH`.

## Outcomes

| Status | When |
|---|---|
| PASS | No result, or only `low`/`info` results (reported as InfoNotes). |
| FAIL | At least one `medium`, `high` or `critical` result. |
| SKIP | nuclei enabled but not found. |
| ERROR | nuclei failed or exceeded `timeout_seconds`. |
| (absent) | `external_tools.nuclei.enabled` is `false` or the master switch is off: the test is not scheduled. |

References on every item: OWASP API9:2023, CWE-200, plus the CWE ids declared by the template.
The raw nuclei output is stored in `evidence.json` (pinned artefact), in `outputs/tools/`, and in
`tool_artifact` of the JSON report.

## Configuration

`external_tools.nuclei.*`: `enabled`, `timeout_seconds` (required, 60-600), `template_dir`, `tags`
(default `api, exposure, misconfig, panel`), `per_request_timeout`, `rate_limit_rps` (default 30, kept low so the
scan does not interfere with test 4.1), `extra_flags`, `expected_version`, `dev_mode`.

## Why it exists

Same guarantee as [0.1](../../domain-0/0-1-shadow-api-discovery.md) (OWASP API9:2023). Tooling decision
([`decisions.it.md` §0.1](../../../knowledge/tools/decisions.it.md)): nuclei is the Cat A tool that turns
"undocumented endpoint exists" into "known-dangerous exposure". The other planned Cat A tools for 0.1 (ffuf,
katana) are not implemented, which is why the roadmap marks the guarantee as partially covered (Q-09).

## Limitations

- Results depend on the pinned template set and on the selected tags.
- The module docstring describes the native test 0.1 as using `OPTIONS` and a versioning check; the native test
  does neither (see [0.1](../../domain-0/0-1-shadow-api-discovery.md#coverage-against-the-methodology)).

## See also

- [`0.1 Shadow API discovery`](../../domain-0/0-1-shadow-api-discovery.md)
- [`../../reference/compatibility.md`](../../../reference/compatibility.md#external-tools)
- [`../../guides/extending/add-an-external-test.md`](../../../guides/extending/add-an-external-test.md)
