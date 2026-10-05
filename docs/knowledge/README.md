# Knowledge Base — Research Behind APIGuard Assurance

This folder holds the research the tool is built on, ordered as the Master's thesis chapters it comes from:
context → methodology → implementation → test scenario. It explains *why* tests and design choices exist;
for *what the tool does today*, see [`../architecture/`](../architecture/overview.md) and the guides.

Files with the `.it.md` suffix are the original Italian sources. Planned: selective translation —
methodology, tool decisions and design properties in full; background as an English summary
(the extensive version stays as an Italian archive).

| Thesis chapter | File | Content |
|---|---|---|
| 2 — State of the art | [`background/state-of-the-art-compact.it.md`](background/state-of-the-art-compact.it.md) | API exposure patterns (gateway, Kubernetes ingress, service mesh, serverless), protocol mechanisms (REST, GraphQL, gRPC, SOAP, WebSocket, SSE), architecture–protocol impedance mismatch |
| 2 — State of the art (extended) | [`background/archive/state-of-the-art-extensive.it.md`](background/archive/state-of-the-art-extensive.it.md) | Full research notes behind the compact chapter |
| 3 — Methodology | [`methodology/methodology.it.md`](methodology/methodology.it.md) | Black/Grey/White Box gradient, priority matrix, 29 security guarantees in 8 domains (references, failure scenarios, prerequisites, test logic) |
| 4 — Implementation | [`archive/implementation-chapter.it.md`](archive/implementation-chapter.it.md) | Thesis version of the architecture; superseded by [`../architecture/overview.md`](../architecture/overview.md) |
| 5 — Test scenario | [`target-selection.it.md`](target-selection.it.md) | Requirements for the target application and candidates evaluated |
| — | [`design-properties.it.md`](design-properties.it.md) | Catalogue of 39 architectural properties (D1–D7) with code locus and evidence |
| — | [`tools/catalog.it.md`](tools/catalog.it.md) | External security tools evaluated per guarantee |
| — | [`tools/decisions.it.md`](tools/decisions.it.md) | Tool chosen per test (Cat A/B/C) and rationale |
