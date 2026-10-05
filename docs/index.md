# APIGuard Assurance — Documentation Map

> **Status: restructuring in progress.** This map lists only pages that exist today.
> Sections marked *planned* are part of the target structure and will be filled in order.
> Pages with the `.it.md` suffix are Italian sources awaiting translation or reorganisation.

## By role

| I want to… | Go to |
|---|---|
| Install and try the tool | [`README.en.md`](../README.en.md) §2–4 — *planned:* `getting-started/` |
| Configure and run it on a target | [`README.en.md`](../README.en.md) §3–5 — *planned:* `guides/usage/` |
| Integrate it in a pipeline or another system | [`README.en.md`](../README.en.md) §4, §8 — *planned:* `guides/integration/` |
| Add a native test | [`guides/extending/add-a-native-test.md`](guides/extending/add-a-native-test.md) |
| Add an external test or connector | [`guides/extending/add-an-external-test.md`](guides/extending/add-an-external-test.md) |

## By need

| I need… | Go to |
|---|---|
| What a test checks | *planned:* `tests/` — today: [`knowledge/methodology/methodology.it.md`](knowledge/methodology/methodology.it.md) |
| Exact meaning of a config field, CLI option, exit code, output file | *planned:* `reference/` — today: [`README.en.md`](../README.en.md) |
| How the tool works internally | [`architecture/overview.md`](architecture/overview.md) |
| Why a test or a design choice exists (research) | [`knowledge/`](knowledge/README.md) |
| Project state, roadmap, past audits | [`project/roadmap.md`](project/roadmap.md), [`project/audits/`](project/audits/) |

## Target structure

```
getting-started/   installation, first assessment
guides/            usage/ · integration/ · extending/
tests/             one page per test
reference/         configuration, cli, report schema, evidence format, exit codes, compatibility
architecture/      overview, data model, assessment model, security model
knowledge/         thesis research: background, methodology, tools, design properties
project/           roadmap, audits, maintainer notes
```
