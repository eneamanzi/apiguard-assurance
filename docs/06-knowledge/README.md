# Knowledge Base - Research Behind APIGuard Assurance

This folder holds the research the tool is built on, in the order of the Master's thesis chapters it comes from
(the file numbers give the reading order): context, methodology, tools, test scenario, design properties. It
explains *why* tests and design choices exist; for *what the tool does today*, see
[`../04-architecture/`](../04-architecture/01-overview.md) and the guides.

Every page is in English. The Italian originals stay in the git history; see [Italian originals](#italian-originals).

| File | Thesis chapter | Content |
|---|---|---|
| [`01-state-of-the-art.md`](01-state-of-the-art.md) | 2 - State of the art | API exposure patterns (gateway, Kubernetes ingress, service mesh, serverless), protocol mechanisms (REST, GraphQL, gRPC, SOAP, WebSocket, SSE), architecture-protocol impedance mismatch; the facts corrected against current sources |
| [`02-state-of-the-art-extended.md`](02-state-of-the-art-extended.md) | 2 - State of the art (extended) | The full research notes behind the chapter, translated as written (Kubernetes internals, protocol details, the architecture-protocol physiology and pathology, bibliographies); its facts are corrected in `01` |
| [`03-methodology.md`](03-methodology.md) | 3 - Methodology | Guarantees and how each is described, the knowledge and privilege gradient (what a check may use), prerequisites and effects on the target, priorities by importance |
| [`04-guarantees.md`](04-guarantees.md) | 3 - Methodology (catalogue) | The 29 security guarantees in 8 domains (references, failure scenarios, prerequisites, test logic), translated from the thesis and not yet aligned with the tool (see the note at the top of the page) |
| [`05-tool-decisions.md`](05-tool-decisions.md) | tool review | The decisions in short: criteria, categories, tools chosen per guarantee, what is implemented today, reasons, shared connectors |
| [`06-tool-catalog.md`](06-tool-catalog.md) | tool review | The complete review: every tool found, per guarantee, in category A, B or C, with its role and the reason for each choice; appendices (cross-cutting, non-REST, abandoned, future, confidence matrix) |
| [`07-target-selection.md`](07-target-selection.md) | 5 - Test scenario | Requirements for the target application, candidates evaluated, and the three labs of today |
| [`08-design-properties.md`](08-design-properties.md) | design properties | The tool's architectural properties (39 from the thesis in 7 domains, updated to the code, plus those added since), each with consequences, evidence and possible developments |

The thesis implementation chapter (chapter 4) is covered by [`../04-architecture/`](../04-architecture/01-overview.md) and
`08-design-properties.md`.

## Italian originals

The Italian sources removed after their adaptation, in their last version, are in commit `694f89a` (the last commit
that holds them); the thesis versions are also in the release tag `v0.1.0` (commit `0840ef5`), under `docs/priv/`.
The English pages leave out some content on purpose, notably the detailed attack technique lists of the tool review
and the construction details of attack inputs in the guarantees; those are only in the originals.

| English page | Original, last version | Command |
|---|---|---|
| `01-state-of-the-art.md` | `docs/knowledge/background/state-of-the-art-compact.it.md` | `git show 694f89a:docs/knowledge/background/state-of-the-art-compact.it.md` |
| `02-state-of-the-art-extended.md` | `docs/knowledge/background/archive/state-of-the-art-extensive.it.md` | `git show 694f89a:docs/knowledge/background/archive/state-of-the-art-extensive.it.md` |
| `03-methodology.md` and `04-guarantees.md` | `docs/knowledge/methodology/methodology.it.md` | `git show 694f89a:docs/knowledge/methodology/methodology.it.md` |
| `05-tool-decisions.md` | `docs/knowledge/tools/decisions.it.md` | `git show 694f89a:docs/knowledge/tools/decisions.it.md` |
| `06-tool-catalog.md` | `docs/knowledge/tools/catalog.it.md` | `git show 694f89a:docs/knowledge/tools/catalog.it.md` |
| `07-target-selection.md` | `docs/knowledge/target-selection.it.md` | `git show 694f89a:docs/knowledge/target-selection.it.md` |
| `08-design-properties.md` | `docs/knowledge/design-properties.it.md` | `git show 694f89a:docs/knowledge/design-properties.it.md` |
| `../project/audit-v0.1.0.md` | `docs/project/audits/2026-05-18-v0.1.0-release.it.md` | `git show 694f89a:docs/project/audits/2026-05-18-v0.1.0-release.it.md` |
| (covered by `../04-architecture/`) | `docs/knowledge/archive/implementation-chapter.it.md` | `git show 694f89a:docs/knowledge/archive/implementation-chapter.it.md` |
| (covered by `../02-guides/03-extending/01-coding-rules.md`) | `docs/project/claude-rules.it.md` | `git show 694f89a:docs/project/claude-rules.it.md` |

In the tag `v0.1.0` the same documents are `docs/priv/knowledge/2-Background_compact.md`,
`2-Background_extensive.md`, `3-Metodologia.md`, `4-Implementazione.md`, `5-Scenario-test.md`,
`docs/priv/apiguard_property.md`, `docs/priv/TOOLS_decisions.md`, `docs/priv/TOOLS_catalog.md` and
`docs/priv/RULES_claude.md` (for example `git show v0.1.0:docs/priv/TOOLS_catalog.md`).
