# APIGuard Assurance - Documentation Map

> **Status: restructuring in progress.** This map lists only pages that exist today.
> Sections marked *planned* are part of the target structure and will be filled in order.
> Pages with the `.it.md` suffix are Italian sources awaiting translation or reorganisation.
> Folders marked *repository only* are not included in the source package: read them on the repository.

## By role

| I want to… | Go to |
|---|---|
| Install and try the tool | [`getting-started/installation.md`](getting-started/installation.md), [`getting-started/first-assessment.md`](getting-started/first-assessment.md) |
| Configure and run it on a target | [`guides/usage/configure-a-target.md`](guides/usage/configure-a-target.md), [`guides/usage/select-tests.md`](guides/usage/select-tests.md), [`guides/usage/read-the-report.md`](guides/usage/read-the-report.md) |
| Integrate it in a pipeline or another system | [`reference/exit-codes.md`](reference/exit-codes.md), [`reference/report-schema.md`](reference/report-schema.md) - *planned:* `guides/integration/` |
| Add a native test | [`guides/extending/add-a-native-test.md`](guides/extending/add-a-native-test.md) |
| Add an external test or connector | [`guides/extending/add-an-external-test.md`](guides/extending/add-an-external-test.md) |
| Support another API gateway | [`guides/extending/add-a-gateway-adapter.md`](guides/extending/add-a-gateway-adapter.md) |
| Know the coding rules before contributing | [`guides/extending/coding-rules.md`](guides/extending/coding-rules.md) |

## By need

| I need… | Go to |
|---|---|
| What a test checks, what it needs, what it does to the target | [`tests/`](tests/README.md) |
| Exact meaning of a config field | [`reference/configuration.md`](reference/configuration.md) |
| Commands and options | [`reference/cli.md`](reference/cli.md) |
| Exit codes | [`reference/exit-codes.md`](reference/exit-codes.md) |
| Output files | [`reference/report-schema.md`](reference/report-schema.md), [`reference/evidence-format.md`](reference/evidence-format.md) |
| Supported versions, platforms, stability | [`reference/compatibility.md`](reference/compatibility.md) |
| How the tool works internally | [`architecture/overview.md`](architecture/overview.md), [`data-model.md`](architecture/data-model.md) |
| How tests are organised, selected and judged | [`architecture/assessment-model.md`](architecture/assessment-model.md) |
| Secrets, outputs, traffic and TLS | [`architecture/security-model.md`](architecture/security-model.md) |
| Why a test or a design choice exists (research) | [`knowledge/`](knowledge/README.md) (repository only) |
| Project state, roadmap, past audits | [`project/roadmap.md`](project/roadmap.md), [`project/audits/`](project/audits/) (repository only) |

## Target structure

```
getting-started/   installation, first assessment
guides/            usage/ · integration/ · extending/
tests/             one page per test
reference/         configuration, cli, report schema, evidence format, exit codes, compatibility
architecture/      overview, data model, assessment model, security model
knowledge/         thesis research: background, methodology, tools, design properties (repository only)
project/           roadmap, audits, maintainer notes (repository only)
```
