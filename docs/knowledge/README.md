# Knowledge Base - Research Behind APIGuard Assurance

This folder holds the research the tool is built on, ordered as the Master's thesis chapters it comes from:
context → methodology → implementation → test scenario. It explains *why* tests and design choices exist;
for *what the tool does today*, see [`../architecture/`](../architecture/overview.md) and the guides.

Every page is in English. The Italian originals stay in the git history; see [Italian originals](#italian-originals).

| Thesis chapter | File | Content |
|---|---|---|
| 2 - State of the art | [`background/state-of-the-art.md`](background/state-of-the-art.md) | API exposure patterns (gateway, Kubernetes ingress, service mesh, serverless), protocol mechanisms (REST, GraphQL, gRPC, SOAP, WebSocket, SSE), architecture-protocol impedance mismatch |
| 2 - State of the art (extended) | [`background/archive/state-of-the-art-extensive.md`](background/archive/state-of-the-art-extensive.md) | Full research notes behind the chapter, translated as written (Kubernetes internals, protocol details, the architecture-protocol physiology and pathology, bibliographies); its facts are corrected in the chapter |
| 3 - Methodology | [`methodology/framework.md`](methodology/framework.md) | Guarantees and how each is described, the knowledge and privilege gradient (what a check may use), prerequisites and effects on the target, priorities by importance |
| 3 - Methodology (catalogue) | [`methodology/guarantees.md`](methodology/guarantees.md) | The 29 security guarantees in 8 domains (references, failure scenarios, prerequisites, test logic), translated from the thesis and not yet aligned with the tool (see the note at the top of the page); its opening framework is superseded by `framework.md` |
| 4 - Implementation | [`../architecture/overview.md`](../architecture/overview.md) | The thesis implementation chapter is covered by `architecture/` and [`design-properties.md`](design-properties.md) (what it said and is still true is there; the constraints and the sequential execution rationale were added to the overview); the original is recoverable (see below) |
| 5 - Test scenario | [`target-selection.md`](target-selection.md) | Requirements for the target application, candidates evaluated, and the three labs of today |
| - | [`design-properties.md`](design-properties.md) | Catalogue of the tool's architectural properties (39 from the thesis in 7 domains, updated to the code, plus those added since), each with consequences, evidence and possible developments |
| - | [`tools/catalog.md`](tools/catalog.md) | The complete tool review: every tool found, per guarantee, in category A, B or C, with its role and the reason for each choice; appendices (cross-cutting, non-REST, abandoned, future, confidence matrix) |
| - | [`methodology/guarantees.md`](methodology/guarantees.md) | `docs/knowledge/methodology/methodology.it.md` | `git show 694f89a:docs/knowledge/methodology/methodology.it.md` |
| [`tools/decisions.md`](tools/decisions.md) | The decisions in short: criteria, categories, tools chosen per guarantee, what is implemented today, reasons, shared connectors |

## Italian originals

The Italian sources removed after their adaptation, in their last version, are in commit `694f89a` (the last commit
that holds them); the thesis versions are also in the release tag `v0.1.0` (commit `0840ef5`), under `docs/priv/`.
The English pages leave out some content on purpose, notably the detailed attack technique lists of the tool review;
those are only in the originals.

| English page | Original, last version | Command |
|---|---|---|
| [`background/state-of-the-art.md`](background/state-of-the-art.md) | `docs/knowledge/background/state-of-the-art-compact.it.md` | `git show 694f89a:docs/knowledge/background/state-of-the-art-compact.it.md` |
| [`background/archive/state-of-the-art-extensive.md`](background/archive/state-of-the-art-extensive.md) | `docs/knowledge/background/archive/state-of-the-art-extensive.it.md` | `git show 694f89a:docs/knowledge/background/archive/state-of-the-art-extensive.it.md` |
| [`design-properties.md`](design-properties.md) | `docs/knowledge/design-properties.it.md` | `git show 694f89a:docs/knowledge/design-properties.it.md` |
| [`tools/decisions.md`](tools/decisions.md) | `docs/knowledge/tools/decisions.it.md` | `git show 694f89a:docs/knowledge/tools/decisions.it.md` |
| [`tools/catalog.md`](tools/catalog.md) | `docs/knowledge/tools/catalog.it.md` | `git show 694f89a:docs/knowledge/tools/catalog.it.md` |
| [`target-selection.md`](target-selection.md) | `docs/knowledge/target-selection.it.md` | `git show 694f89a:docs/knowledge/target-selection.it.md` |
| [`../project/audits/2026-05-18-v0.1.0-release.md`](../project/audits/2026-05-18-v0.1.0-release.md) | `docs/project/audits/2026-05-18-v0.1.0-release.it.md` | `git show 694f89a:docs/project/audits/2026-05-18-v0.1.0-release.it.md` |
| (removed, covered by [`architecture/overview.md`](../architecture/overview.md) and [`design-properties.md`](design-properties.md)) | `docs/knowledge/archive/implementation-chapter.it.md` | `git show 694f89a:docs/knowledge/archive/implementation-chapter.it.md` |
| (removed, covered by [`coding-rules.md`](../guides/extending/coding-rules.md)) | `docs/project/claude-rules.it.md` | `git show 694f89a:docs/project/claude-rules.it.md` |

In the tag `v0.1.0` the same documents are `docs/priv/knowledge/2-Background_compact.md`,
`2-Background_extensive.md`, `docs/priv/apiguard_property.md`, `docs/priv/TOOLS_decisions.md` and
`docs/priv/TOOLS_catalog.md` (for example `git show v0.1.0:docs/priv/TOOLS_catalog.md`); the tool review files are
identical in both places.
