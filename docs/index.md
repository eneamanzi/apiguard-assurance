# APIGuard Assurance - Documentation Map

> The folders are numbered in reading order. `06-knowledge/` and `project/` are not included in the source package:
> read them on the repository.

## By role

| I want to… | Go to |
|---|---|
| Install and try the tool | [`01-installation`](01-getting-started/01-installation.md), [`02-first-assessment`](01-getting-started/02-first-assessment.md) |
| Configure and run it on a target | [`01-configure-a-target`](02-guides/01-usage/01-configure-a-target.md), [`02-select-tests`](02-guides/01-usage/02-select-tests.md), [`03-read-the-report`](02-guides/01-usage/03-read-the-report.md) |
| Integrate it in a pipeline or another system | [`01-integrate-apiguard`](02-guides/02-integration/01-integrate-apiguard.md), then [`03-exit-codes`](03-reference/03-exit-codes.md), [`04-report-schema`](03-reference/04-report-schema.md) |
| Know the coding rules before contributing | [`01-coding-rules`](02-guides/03-extending/01-coding-rules.md) |
| Add a native test | [`02-add-a-native-test`](02-guides/03-extending/02-add-a-native-test.md) |
| Add an external test or connector | [`03-add-an-external-test`](02-guides/03-extending/03-add-an-external-test.md) |
| Support another API gateway | [`04-add-a-gateway-adapter`](02-guides/03-extending/04-add-a-gateway-adapter.md) |

## By need

| I need… | Go to |
|---|---|
| What a test checks, what it needs, what it does to the target | [`05-tests/`](05-tests/README.md) |
| Exact meaning of a config field | [`01-configuration`](03-reference/01-configuration.md); every key with its default: [`config.example.yaml`](../config.example.yaml) |
| Commands and options | [`02-cli`](03-reference/02-cli.md) |
| Exit codes | [`03-exit-codes`](03-reference/03-exit-codes.md) |
| Output files | [`04-report-schema`](03-reference/04-report-schema.md), [`05-evidence-format`](03-reference/05-evidence-format.md) |
| Supported versions, platforms, stability | [`06-compatibility`](03-reference/06-compatibility.md) |
| How the tool works internally | [`01-overview`](04-architecture/01-overview.md), [`02-data-model`](04-architecture/02-data-model.md) |
| How tests are organised, selected and judged | [`03-assessment-model`](04-architecture/03-assessment-model.md) |
| Secrets, outputs, traffic and TLS | [`04-security-model`](04-architecture/04-security-model.md) |
| Why the tool is built this way (configuration by connection, TLS, credentials, prepared resources, gateway concepts) | [`05-design-decisions`](04-architecture/05-design-decisions.md) |
| Why a test or a design choice exists (research) | [`06-knowledge/`](06-knowledge/README.md) (repository only) |
| Project state, plan, roadmap, the v0.1.0 audit | [`plan`](project/plan.md), [`roadmap`](project/roadmap.md), [`audit-v0.1.0`](project/audit-v0.1.0.md) (repository only) |

## Structure

```
01-getting-started/   installation, first assessment
02-guides/            01-usage · 02-integration · 03-extending
03-reference/         configuration, cli, exit codes, report schema, evidence format, compatibility
04-architecture/      overview, data model, assessment model, security model, design decisions
05-tests/             one page per test, by domain
06-knowledge/         thesis research, in thesis order (repository only)
project/              plan, roadmap, test review, maintainer commands, v0.1.0 audit (repository only)
```
