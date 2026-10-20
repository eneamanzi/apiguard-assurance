# State of the Art: Architectures and Protocols for Exposing APIs

> **Audience:** readers of the research, contributors · **Status:** thesis chapter 2, adapted to English and
> corrected against current sources (the corrections are listed in [Corrections](#corrections-to-the-thesis-version))
> · **Verified:** 2026-10-20

The research background of the tool: how APIs are exposed in cloud environments, which structural weaknesses each
protocol carries, and where architecture and protocol interact badly. It explains why the tool tests what it tests;
what the tool does today is in [`architecture/`](../../architecture/overview.md).

## Approach

Designing a tool for automated API security assessment raises a first question that is not technical: what does
"testing an API" mean when the same API can be exposed through a traditional API gateway, a Kubernetes ingress
controller, a service mesh or a serverless platform, and spoken in REST, GraphQL, gRPC, SOAP, WebSocket or
Server-Sent Events?

A descriptive catalogue ("Kong works like this, AWS API Gateway has these features") would be complete but would not
say where and how to test independently of the product. This chapter abstracts instead: for each architecture, the
**universal problem** it solves, the **abstract technical mechanism** that solves it, and only then the
**substantial differences** between implementations, where they change the attack surface or the testing strategy.
The same applies to protocols: not their syntax, but how data is serialised, transported and interpreted, and which
weaknesses follow from that design.

Three parts: architectural patterns, protocol mechanisms, and the interactions between the two.

## 1. Architectural patterns for exposing APIs

### 1.1 API gateway: the centralised mediator

**The problem.** In a microservice architecture each service exposes its own interface: fifty services can mean
fifty endpoints, each with its own authentication, rate limiting and versioning. For an external client this is
unmanageable; for security, each endpoint is an attack vector that needs its own protection.

The API gateway introduces a **single point of entry**: a specialised reverse proxy that intercepts all external
traffic, applies cross-cutting policies (authentication, rate limiting, logging) and routes requests to the right
backend. No external client reaches a service without passing through it.

**The mechanism.** Whatever the product, a request goes through the same layers:

```
[External client]
  1. HTTPS request
[TLS termination]
  2. TLS decrypted
[Authentication]
  3. credential validated (JWT, API key, OAuth)
[Authorization]
  4. permission for the requested resource checked
[Rate limiting]
  5. counting algorithm (window counters, token bucket)
[Routing]
  6. URL path mapped to a backend service
[Backend communication]
  7. request proxied, often plain HTTP on the internal network
[Backend service]
```

Implementations differ on **where** and **how** each layer is implemented; the pattern stays the same.

**Substantial differences.** Three dimensions matter for testing and security.

*A. Data plane architecture.*

- **Kong** (self-hosted) is built on Nginx extended with OpenResty (Lua). Each request goes through the plugins
  configured for it, in sequence, ordered by priority in each request phase. A slow plugin (for example one that
  queries a database to validate a credential) adds its time to every request it handles. For testing: slow or
  misconfigured plugins are an easy denial of service, since an attacker can send requests that trigger the most
  expensive plugins.
- **AWS API Gateway** (managed) has an opaque data plane: no access to the servers, configuration only through the
  API or console, deployment, scaling and patching handled by AWS. For testing: infrastructure-level weaknesses
  (kernel exploits, container escape) cannot be tested; testing is limited to the configured policies and the
  behaviour exposed through the API. This reduces the testable surface and introduces trust in the provider.
- **Azure API Management** (managed and self-hosted) offers a managed gateway and a self-hosted gateway deployed as
  a container, which takes its configuration from the cloud management plane. For testing: in a hybrid deployment
  the channel between gateway and management plane is an additional attack surface; whoever compromises it (man in
  the middle, credential theft) can change the gateway configuration without access to the management plane.

*B. Rate limiting algorithm.*

- **Kong**: the Rate Limiting plugin counts requests in **fixed windows** (per second, minute, hour...); the Rate
  Limiting Advanced plugin uses **sliding windows** by default (the previous window's count weighs on the current
  one) or fixed windows.
- **AWS API Gateway** uses a **token bucket**: the throttling rate is the rate at which tokens are added, the burst
  is the bucket's capacity, each request takes one token, and an empty bucket gives `429 Too Many Requests`. AWS
  describes the limits as best-effort targets, not guaranteed ceilings.

For testing, the algorithm decides the probe: a token bucket accepts a burst up to its capacity and then the refill
rate, so a burst test measures the capacity and a sustained stream measures the rate; a fixed window resets at the
window boundary, so up to twice the limit can pass around a boundary; a sliding window smooths that edge. Testing
rate limiting means knowing which algorithm is in place and probing accordingly.

*C. TLS termination and backend communication.* Every gateway terminates TLS at the gateway; they differ on what
happens after:

- **Kong**: the connection to the backend can be plain HTTP, HTTPS, or mutual TLS; a service's protocol is `http`
  unless configured.
- **AWS API Gateway**: a REST API can present a client certificate to an HTTP backend (a certificate generated by the
  gateway, or, since September 2026, an AWS Certificate Manager certificate for mutual TLS).
- **Azure API Management**: the `authentication-certificate` policy authenticates to the backend with a client
  certificate, on the managed, consumption and self-hosted gateways.

For testing: if backend communication is plain text, an attacker on the internal network (lateral movement from a
compromised container) can read API traffic. Testing must cover not only the perimeter (client to gateway) but also
the inside (gateway to backend).

**Layered authentication.** A gateway typically authenticates in layers: an **API key** identifies the calling
client (not the user) and drives quotas and analytics; a **JWT** identifies the user (signature, expiry, claims such
as user ID and roles); an optional **custom authorizer** (a Lambda authorizer in AWS, a policy in Azure) decides
fine-grained permissions, possibly querying a database. The gateway then forwards the request with the identity it
established, for example in a header such as `X-User-Id`, and the backend trusts it. Rate limits are keyed on the API
key (per client), the IP address (anonymous users) or the user ID taken from the token. For testing: the trust the
backend places in the gateway holds only if the backend cannot be reached directly and a client cannot supply that
header itself; OWASP asks that propagated identity be validated by each receiving service and that direct access
bypassing the gateway's checks be prevented
([Microservices Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html)).

**Risks of the gateway itself.** Centralising security creates risks of its own:

- **Single point of failure and of attack**: if the gateway is compromised or denied, every API behind it is lost,
  so an attack on it has a multiplied effect.
- **Misconfiguration**: modern gateways are complex (Kong with dozens of plugins, Azure policies in XML); a wrong
  rate limiting, authentication or CORS setting exposes a weakness that no single service shows.
- **Trust boundary after TLS termination**: behind the gateway, traffic to the backends is often plain HTTP or TLS
  with self-signed certificates. In cloud-native environments the internal network is virtually flat (pods on any
  node, isolation only through network policies), so "the internal network is safe" is a weak assumption.
- **Configuration drift between instances**: with several gateway instances (for availability) their configurations
  can diverge. In Kong's DB-less mode each node loads its declarative configuration on its own (at startup or through
  `/config`) and nodes share nothing, so a failed deployment can leave a node with an old configuration that still
  exposes endpoints meant to be gone (shadow endpoints)
  ([Kong DB-less mode](https://developer.konghq.com/gateway/db-less-mode/)).

**Implications for testing.** A testing tool should:

1. Recognise the implementation: HTTP headers (`Server: kong/3.x`, `X-Amzn-RequestId` for AWS), error messages,
   specific behaviour.
2. Test the universal pattern, whatever the vendor: authentication bypass, authorization flaws, rate limiting
   bypass, injection through routing parameters.
3. Test the substantial differences: for Kong, which plugins are active and how they are configured, code
   injection in custom Lua plugins; for AWS, IAM policies, Lambda authorizer logic, log analysis for anomalies; for
   Azure, the security of the self-hosted gateway's channel and of its XML policies.

### 1.2 Kubernetes Ingress and Gateway API

**The problem.** Kubernetes orchestrates containers but has no native way to expose HTTP services outside the
cluster: a `ClusterIP` Service is reachable only inside it, a `LoadBalancer` Service creates a provider-specific load
balancer (costly and not portable). A Kubernetes-native abstraction for HTTP routing is needed.

Ingress (the original model) and Gateway API (its successor) define declarative resources that state routing rules,
and delegate their implementation to specialised controllers.

**The mechanism.** Configuration (Kubernetes resources) is separated from implementation (controllers):

```
[Developer]        writes an Ingress or HTTPRoute resource
[API server]       stores it in etcd
[Controller]       watches the API, translates the resource into proxy configuration
[Reverse proxy]    Nginx, Envoy, Traefik... applies it (reload or hot reload)
[HTTP traffic]     routed by hostname and path
[Service → Pod]
```

Implementations differ on which proxy they use and how they translate resources into its configuration.

**Ingress and Gateway API.**

- **Ingress** defines basic HTTP routing: by hostname (`api.example.com` to service A), by path (`/api/v1/users` to
  the users service), and TLS termination with the certificates per hostname. Its structural problem: advanced
  features (rate limiting, authentication, header rewriting) need **controller-specific annotations**, which are not
  portable:

  ```yaml
  metadata:
    annotations:
      nginx.ingress.kubernetes.io/limit-rps: "100"
  ```

  Moving from one controller to another means rewriting every annotation.
- **Gateway API** solves this with a role-oriented design and typed resources: **GatewayClass** (the controller
  type, managed by the infrastructure provider), **Gateway** (an instance with its listeners: port, protocol, TLS,
  managed by the cluster operator), **HTTPRoute / GRPCRoute / TCPRoute** (routing per protocol, managed by the
  application developer). The specification is standard: an HTTPRoute with header matching behaves the same on every
  conformant implementation.

**Differences between controllers.**

- **Nginx-based controllers** translate the resources into `nginx.conf`; a change needs an Nginx reload (without
  downtime, but not instantaneous). For testing: there is a window between the change of a resource and its
  application. The community **Ingress NGINX** controller was retired in March 2026: no more releases, bug fixes or
  security patches; Kubernetes recommends migrating to Gateway API.
- **Envoy-based controllers** (Istio Gateway, Contour, Envoy Gateway) push configuration to Envoy through the xDS
  protocol over a gRPC stream, applied without reload. For testing: no reload window, but xDS is itself an attack
  surface: whoever compromises the control plane can push a malicious configuration.
- **Cilium** implements Gateway API in the network layer (CNI) with eBPF programs in the kernel for routing and
  policy enforcement. For testing: very high performance (fewer user-space context switches), but the attack surface
  includes the kernel's eBPF subsystem, and testing needs its security model (verifier, capability checks).

**Implications for testing.** A tool should:

1. Distinguish Ingress from Gateway API: the resource kind (`Ingress` or `HTTPRoute`) says which specification is
   implemented.
2. Identify the controller: through the ingress class or the GatewayClass. Controllers behave differently.
3. Test portability: an HTTPRoute should behave the same on different controllers; cross-controller tests check
   conformance to the specification.
4. Test configuration drift: in clusters with several controllers (for example one for HTTP and one for gRPC),
   check that policies are consistent between them.

### 1.3 Service mesh: the invisible infrastructure

**The problem.** API gateways and ingress handle **north-south** traffic (external to internal). In microservice
architectures the dominant volume is **east-west** traffic (service to service). How to enforce mutual TLS between
all services without changing their code? How to apply retries, timeouts and circuit breakers consistently? How to
observe that traffic?

A service mesh introduces a **distributed data plane** (proxies that intercept service-to-service traffic) and a
**centralised control plane** (which configures the proxies and aggregates telemetry).

**The mechanism.** Proxy injection plus control plane configuration:

```
[Service A pod]
  [application]     calls service B
                    traffic redirected to the proxy (iptables)
  [sidecar proxy]   Envoy or linkerd2-proxy: intercepts outbound traffic,
                    encrypts with mTLS (certificate from the control plane),
                    discovers and load-balances the endpoints of B
[network]           encrypted traffic
[Service B pod]
  [sidecar proxy]   decrypts, enforces authorization policy, collects metrics
  [application]     receives the request in plain text
```

The control plane (**istiod** for Istio, the Linkerd control plane) acts as certificate authority (X.509
certificates for workload identity), does service discovery (service name to endpoints), and distributes
configuration to the proxies.

**Differences between implementations.**

- **Istio** uses Envoy (C++), highly configurable, for HTTP/1.1, HTTP/2, gRPC, TCP and WebSocket. Its control plane,
  istiod (a single binary since 2020), translates high-level resources (VirtualService, DestinationRule) into Envoy
  configuration through xDS. In **sidecar mode** every pod runs the application and an Envoy; Istio's own
  measurements put a proxy at about 0.5 vCPU per 1000 requests per second, with memory depending on how much
  configuration it holds (about 50 MB in a large namespace). **Ambient mode** (generally available since Istio 1.24,
  November 2024) removes the sidecar: a per-node Layer 4 proxy, **ztunnel** (Rust), handles mTLS, authentication, L4
  authorization and telemetry, and optional **waypoint** proxies add Layer 7 features. For testing: with sidecars,
  each pod may carry a different configuration and is tested on its own; in ambient mode, ztunnel per node and
  waypoints per namespace or service are tested, with a more centralised configuration.
- **Linkerd** uses its own lightweight Rust proxy, linkerd2-proxy, and a Go control plane made of several services
  (destination, identity, proxy injector). It proxies all TCP traffic, including TLS, WebSocket and HTTP tunnelling,
  with HTTP/1.1, HTTP/2 and gRPC load balancing; traffic splitting is done with HTTPRoute and GRPCRoute, and since
  2.15 (February 2024) it can mesh non-Kubernetes workloads such as VMs. Linkerd favours simplicity and footprint: in an
  independent comparison (LiveWyer, 2024, Istio's Bookinfo on EKS) Linkerd was 5-10% slower than no mesh and Istio
  25-35%; in benchmarks published by Linkerd's maintainers (2021, at 2000 requests per second) its data plane used
  about one ninth of Istio's memory and one eighth of its CPU. For testing: fewer features means a smaller surface to test.

**Configuration propagation.** Both meshes push configuration to their proxies over gRPC streams: istiod validates
a resource, translates it into Envoy configuration (listeners, clusters, routes) and pushes it to the affected
proxies; Linkerd's destination service keeps a stream open with each proxy, sends the full state first and then
only the changes. Propagation takes seconds, not zero: in very large clusters a push storm can overload the control
plane, and if the control plane is down the proxies keep their last known configuration. For testing: checking that
a policy is correctly written is not enough; it must be checked that every proxy actually applies it.

**Implications for testing.** A tool should:

1. Detect the mesh: pod labels and annotations (`sidecar.istio.io/inject: "true"`), sidecar containers
   (`istio-proxy`, `linkerd-proxy`).
2. Test mTLS enforcement: a mesh is not automatically encrypted; check that mTLS is enforced (Istio `STRICT` rather
   than `PERMISSIVE`).
3. Test authorization policies: a mesh allows fine-grained policies (service A may call service B only on
   `/api/v1`); test their enforcement, not only their configuration.
4. Test configuration consistency: across clusters and while changes propagate, check that a policy is applied by
   every proxy.

### 1.4 Serverless: the computational abstraction

**The problem.** Always-on servers waste resources (a service used ten minutes a day consumes CPU all day), scaling
is complex and slow, and patching, monitoring and high availability need operational effort.

Serverless replaces servers with **event-driven functions** that run on demand, scale automatically (from zero to
thousands of instances) and are paid by execution time.

**The mechanism.** Event triggering plus ephemeral execution:

```
[Event source]   HTTP request, file upload, database change
[Platform]       function not running: cold start
                   (execution environment provisioned: micro-VM or container,
                    code downloaded, runtime initialised)
                 function warm: existing environment reused
[Execution]      handler receives the event; business logic
[Response]       return value or HTTP response
[Platform]       keeps the environment warm for a while, then reclaims it
```

Implementations differ on the isolation model, the cold start duration and the integration with their ecosystem.

**Differences between implementations.**

- **AWS Lambda** isolates executions in **Firecracker** micro-VMs, whose memory overhead AWS states as under 5 MiB
  per micro-VM. Cold starts are shorter for interpreted runtimes (Python, Node.js) than for JIT runtimes (Java,
  .NET); provisioned concurrency keeps environments pre-initialised at a cost. Lambda integrates natively with AWS
  services and runs with an IAM role. **VPC access**: since 2019 a function reaches private resources through a
  shared Hyperplane network interface created when the function is created or its VPC settings change, so cold
  starts no longer create a network interface (the one-time setup can take up to 90 seconds, and functions idle for
  weeks can lose it). Since December 2025 Lambda also offers **durable functions**: multi-step executions that
  checkpoint progress and can suspend for up to a year.
- **Azure Functions** run in containers with a preconfigured runtime; cold starts on the consumption plan are
  longer than on plans that keep instances warm. They integrate with Azure services and offer **Durable Functions**:
  orchestrations with persistent state (function chaining, fan-out/fan-in, waiting for human approval). For testing:
  durable orchestrations introduce state into a stateless model; test state consistency and replay (an orchestrator
  re-executes functions with the same input).
- **Knative** runs functions as standard Kubernetes pods, with no isolation beyond namespaces and network policies.
  Cold starts are longer (image pull, scheduling, init containers), mitigated with `minScale` above zero. Each deploy
  creates an immutable **revision**, and traffic can be split between revisions (blue-green, canary). For testing:
  one service can have several URLs (one per revision, plus the latest); discovery must find every active revision.

**Invocation types.**

- **Synchronous** (request-response): an HTTP API invokes the function and waits for its response (Lambda runs up to
  15 minutes; an API gateway in front usually has a shorter timeout). For testing: an ordinary HTTP API (fuzzing,
  injection, authorization bypass).
- **Asynchronous** (fire and forget): an event is queued and processed later; a failed Lambda invocation is retried
  (up to two retries, configurable), then sent to a dead-letter queue or failure destination. For testing: there is
  no immediate response, so side effects must be checked (file processed, record updated), and so must the retry
  logic.

**Implications for testing.** A tool should:

1. Identify the platform: response metadata (`X-Amzn-RequestId` for AWS, `x-ms-request-id` for Azure), timing
   patterns (cold start latency spikes).
2. Test cold start effects: bursts after an idle period, checking for exploitable timeouts or errors.
3. Test identity: the function's role should have least privilege (no `AdministratorAccess`) and no way to escalate.
4. Test event injection: in asynchronous invocations, a malformed event can cause crashes or retry storms.
5. Test secrets management: secrets (database passwords, API keys) must not be hard-coded or logged.

## 2. Protocol mechanisms and attack surfaces

Cataloguing syntax ("REST uses GET and POST, GraphQL uses queries and mutations, gRPC uses protobuf") does not reveal
what decides security. What matters is the mechanism: how data is serialised, how the transport handles state, how
client and server agree on a format. From the mechanism follow **structural weaknesses**: not implementation bugs,
but properties of the protocol's design.

### 2.1 REST: stateless, resource-oriented

**The mechanism.** REST is not a protocol (no RFC defines a "REST protocol") but an architectural style:

1. **Resource identification**: every entity (user, product, order) is a resource identified by a URL.
2. **Uniform interface**: resources are handled with the standard HTTP methods (GET read, POST create, PUT replace,
   PATCH modify, DELETE remove).
3. **Statelessness**: each request carries everything needed; the server keeps no session state between requests.
4. **Representation**: a resource has several representations (JSON, XML, HTML), negotiated through `Accept` and
   `Content-Type`.

```
[Client]   GET /users/123
           Accept: application/json, Authorization: Bearer <token>
[Server]   parse (method, resource, format)
           authenticate (validate the token)
           authorize (may this token read user 123?)
           retrieve (query user 123)
           serialise (user object to JSON)
[Client]   200 OK, Content-Type: application/json
           {"id": 123, "name": "Alice"}
```

**Structural weaknesses.**

- **Over-fetching** (intrinsic). REST returns the whole representation of a resource: a client that needs only
  `name` still receives `{id, name, email, dateOfBirth, address, ...}`. It is not a bug: REST has no native field
  selection; it follows from the representation principle. Security consequence: sensitive fields (`passwordHash`,
  `internalId`) in the response even when not needed, that is excessive data exposure. Testing: check which fields
  are returned against least privilege (the client should receive only what its use case needs).
- **BOLA, broken object level authorization** (from resource identification). Resources are identified by IDs in
  the URL (`/users/123`, `/orders/456`), often sequential or predictable. The mechanism has no built-in
  authorization: the developer must check that the requester may access that specific object. If the check is
  missing or flawed, an attacker iterates IDs and reads other users' resources. Testing: authenticate as user A,
  request user B's resource, check that access is denied. This needs **several users**, which generic HTTP scanners
  do not handle.
- **Mass assignment** (from flexible serialisation). REST imposes no schema: a POST or PUT may carry any JSON field.
  If the backend binds the body directly to a database object without an allow-list, an attacker adds undocumented
  fields:

  ```
  POST /users
  {"username": "attacker", "email": "evil@test.com", "isAdmin": true}
  ```

  If `isAdmin` maps to a column, the attacker creates an administrator account. Testing: send extra fields
  (`isAdmin`, `role`, `privileges`) and check whether the backend applies them.

- **HTTP verb tampering**. A server is expected to apply the logic of each method (GET read-only, DELETE
  destructive) and to refuse the methods an endpoint does not implement. A misconfigured one accepts them: a DELETE
  on an endpoint documented only for GET and PATCH removes the resource. Some frameworks treat PUT and POST alike or
  accept a GET with a body, so a firewall that lets GET pass as read-only lets a write through. Testing: every method
  on every endpoint, checking the status (`405 Method Not Allowed` expected) and the side effects
  ([OWASP WSTG, Test HTTP Methods](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods)).
- **Caching of sensitive responses**. HTTP caching (`Cache-Control`, `ETag`, `Expires`) lets proxies, CDNs and
  browsers reuse responses. A response with user data marked `Cache-Control: public, max-age=3600` can be stored by a
  shared proxy and served to other users. It is worse with cookie authentication and URLs without a user identifier
  (`/api/profile`): the proxy cannot tell users apart. Testing: response headers of sensitive endpoints should carry
  `Cache-Control: private` or `no-store`
  ([RFC 9111](https://www.rfc-editor.org/rfc/rfc9111)).

**Testing challenges of REST.**

- **Endpoint proliferation and shadow APIs**: twenty entities with versions (`/v1/`, `/v2/`) easily give over a
  hundred endpoints; shadow APIs are undocumented but live (old versions, debug endpoints such as
  `/api/debug/users`, forgotten admin endpoints such as `/api/admin/backup`). Wordlist scanners find only common
  names; discovery combines the OpenAPI document, crawling of HTML and JavaScript for API calls, variations of known
  patterns (if `/users` exists, try `/products`, `/orders`) and HATEOAS links
  ([OWASP API9:2023 Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)).
- **Content negotiation**: the same endpoint may answer JSON, XML or HTML depending on `Accept`, each through a
  different parser with its own weaknesses (XXE in an XML parser, XSS in HTML rendering), so full coverage tests each
  endpoint with each supported format: 100 endpoints and 3 formats are 300 tests
  ([OWASP XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)).
- **HTTP/2 multiplexing**: many requests travel in parallel on one connection
  ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)). Nothing changes for REST, but a limit per connection does
  not limit requests, and monitoring that counts connections misses the load. Testing needs HTTP/2 clients
  (`curl --http2`, `h2load`) and checks that rate limiting counts requests, not connections.

**REST variants.** Pure REST (Fielding's dissertation) is rare; most "REST APIs" are REST-like.

- **HATEOAS** (hypermedia as the engine of application state): responses carry links to related resources
  (`"_links": {"orders": "/users/123/orders"}`). A crawler can follow them to discover endpoints, but HATEOAS is
  rarely implemented, which makes discovery harder.
- **REST with a schema (OpenAPI)**: the API describes its endpoints, parameters and responses in an OpenAPI document.
  For testing the schema is a gold mine: test cases generated automatically, fuzzing driven by type constraints,
  undocumented endpoints (shadow APIs) found by difference. But the schema is optional, often outdated, and not
  enforced at runtime.

### 2.2 GraphQL: a query language over a graph

**The mechanism.** Instead of many endpoints, a **single endpoint** (`/graphql`) accepts queries in a
domain-specific language. The server defines a strongly typed **schema** (types, fields, relations); the **client**
says exactly which fields it wants and receives only those (no over-fetching); a query **traverses the graph** of
types along its relations.

```
[Client]   POST /graphql
           {"query": "{ user(id: 123) { name posts { title } } }"}
[Server]   lex and parse: query to abstract syntax tree
           validate against the schema (does "user" exist? "name" on User?)
           execute: one resolver per field
             user(id: 123) → users query
             posts        → posts where userId = 123
           compose the JSON result
[Client]   {"data": {"user": {"name": "Alice", "posts": [...]}}}
```

**Structural weaknesses.**

- **Query complexity explosion** (from graph traversal). Queries can nest arbitrarily
  (`users { posts { comments { author { posts { ... } } } } }`), and each level multiplies resolver calls: 10 users
  × 100 posts × 50 comments = 50,000 calls. Consequence: denial of service through expensive queries. Testing:
  increasing nesting while measuring response time; check for depth limits or cost analysis.
- **Schema leakage through introspection** (from schema-first design). An introspection query
  (`{ __schema { types { name fields { name } } } }`) returns every type, field and relation: a full map for an
  attacker. Disabling introspection in production is the usual advice, but the schema can be rebuilt from **field
  suggestions** in errors (`{ user { invalidField } }` → "Did you mean 'username', 'email'?"), iterated by tools
  such as Clairvoyance. Introspection disabled does not mean the schema is secret. Testing: try introspection; if
  disabled, brute-force suggestions; compare the schema obtained with the documentation (shadow fields).
- **Rate limiting bypass through batching** (from the single endpoint). Aliases put many operations in one request
  (`{ u1: user(id: 1) {...} u2: user(id: 2) {...} ... u1000: user(id: 1000) {...} }`): the gateway sees one POST, the
  backend runs a thousand resolvers. An HTTP limit of 100 requests per second becomes 100,000 operations per second.
  Testing: send batched queries; check that limits apply per GraphQL operation, not per HTTP request.

**Monolith and federation.** A **monolithic** GraphQL server holds the whole schema and every resolver: simple, but
hard to share among teams. With **Apollo Federation**, each service exposes a subgraph and a gateway composes them
into a supergraph: it plans the query, sends sub-queries to the subgraphs in parallel and merges the results. For
testing: test the subgraphs individually, not only the supergraph, and check that entity resolution across subgraphs
does not leak fields one subgraph should not see.

### 2.3 gRPC: binary RPC over HTTP/2

**The mechanism.** A remote procedure call: the client invokes methods on the server as if they were local. Unlike
REST and GraphQL, it is **action-oriented**, not resource-oriented. Two pillars: **Protocol Buffers** (binary
serialisation; the schema in a `.proto` file compiled into code; payloads not human-readable and much smaller than
JSON) and **HTTP/2** (multiplexing over one connection, header compression with HPACK, bidirectional streaming).

```
[Client]   stub.GetUser(request): request serialised to protobuf bytes
[HTTP/2]   HEADERS frame: :method POST, :path /UserService/GetUser
           DATA frame: protobuf payload
[Server]   deserialise, execute, serialise the response
[Client]   DATA frame, deserialised to the response object
```

**Structural weaknesses.**

- **Payload opacity** (from binary serialisation). A WAF or IDS cannot inspect a protobuf payload without
  deserialising it, which needs the `.proto` schema. It sees bytes (`08 7B 12 05 ...`), not an injection inside them.
  Testing: malicious payloads must be correctly encoded (the `.proto` is needed); generic HTTP scanners are useless.
- **Parser vulnerabilities** (from binary parsing). Malformed payloads exercise the parser, for example in the
  protobuf libraries: CVE-2021-22570 (a null pointer dereference when a symbol contains a null character, a crash)
  and CVE-2022-1941 (a crafted MessageSet causing out-of-memory, a denial of service). Testing: fuzzing needs a
  format-aware mutation fuzzer; random bit flips only produce deserialisation errors.
- **Stream exhaustion** (from HTTP/2 streaming). With bidirectional streaming both sides keep sending without
  closing the stream. HTTP/2 flow control should prevent abuse, but its configuration is often permissive: an
  attacker opens streams and sends messages slowly and indefinitely, exhausting server resources. Testing: open N
  streams, send at a low constant rate, measure the server's memory and threads.

**Reflection.** With **server reflection** the server exposes its schema (like GraphQL introspection), and a client
such as `grpcurl` lists services and methods (`grpcurl -plaintext localhost:9090 list`): discovery is trivial.
**Without reflection** (the usual production setting) the schema must be obtained out of band (repository, reverse
engineering of a client); without it, testing is blind.

### 2.4 SOAP: XML RPC with the WS-* stack

**The mechanism.** A legacy protocol (1990s-2000s) still common in enterprise, banking and government: RPC like
gRPC, but in XML. Every message is wrapped in a SOAP envelope (`soap:Header` for metadata such as authentication and
routing, `soap:Body` for the call and its parameters), and the contract is a **WSDL** document (operations, input and
output types, endpoint URL).

**Structural weaknesses.**

- **XML external entity (XXE) injection** (from XML parsing). A DTD can define entities that refer to local files
  or remote URLs:

  ```xml
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <soap:Body><UserId>&xxe;</UserId></soap:Body>
  ```

  A parser that expands `&xxe;` reads the file; if an error echoes `UserId`, the attacker gets its content.
  Consequences: file disclosure, server-side request forgery. Testing: send XXE payloads; the parser should refuse
  external DTDs.
- **XML bomb, "billion laughs"** (from recursive entities). Nested entities (`lol2` = ten `lol`, ..., `lol9`)
  expand to about 10^9 copies: the parser allocates gigabytes and crashes. Testing: send a bomb, check that the
  server rejects it rather than failing.
- **XML signature wrapping** (from WS-Security). A signature references elements by ID, not by position, so an
  attacker can restructure the XML and keep the signature valid. Testing: complex; it needs the XML Signature
  specification and crafted payloads.

**SOAP 1.1 and 1.2.** SOAP 1.1 uses the `SOAPAction` header to name the operation and `Content-Type: text/xml`;
SOAP 1.2 uses `Content-Type: application/soap+xml`, with the action as an optional media type parameter. For
testing: fingerprinting checks the version (envelope namespace, content type).

### 2.5 WebSocket: persistent full duplex

**The mechanism.** A **persistent bidirectional connection**: client and server send messages independently, with
no per-message connection overhead. **Handshake**: an HTTP GET with `Upgrade: websocket`, answered with
`101 Switching Protocols`. **After the handshake**: the TCP connection stays open and carries WebSocket frames
(opcode, length, masking key, payload). **Masking**: client-to-server frames must be masked (XOR with a random key),
which prevents cache poisoning of intermediaries.

**Structural weaknesses.**

- **Cross-site WebSocket hijacking** (no CORS preflight). The handshake is HTTP but has no CORS preflight: the browser
  sends the upgrade directly, with the victim's cookies. A page on `evil.com` can open
  `new WebSocket('wss://victim.com/chat')` and forward every message; if the server does not validate the `Origin`
  header, the connection is accepted. Testing: open a connection from a controlled origin and check whether it is
  accepted.
- **Rate limiting bypass** (persistent connection). One handshake is one request for an HTTP rate limiter; after it
  the client sends any number of frames: 100 handshakes × 1000 frames = 100,000 messages per second past a limit of
  100 requests per second. Testing: send frames at a high rate on one connection and check for enforcement.

**Subprotocols.** `Sec-WebSocket-Protocol` negotiates a subprotocol that defines the payload format (JSON, protobuf,
custom binary). Without knowing it the payload is opaque, and fuzzing needs the format reverse-engineered.

### 2.6 Server-Sent Events: one-way streaming

**The mechanism.** Server-to-client streaming over a long-lived HTTP response: the client sends a GET with
`Accept: text/event-stream`, the server answers `200 OK` with `Content-Type: text/event-stream`, keeps the connection
open and sends text events (`event:`, `data:`, `id:` lines). The browser's `EventSource` API reconnects automatically.

**Structural weaknesses.**

- **Token expiry mid-stream** (long-lived connection). A stream can last hours and a JWT may expire after one. If the
  server validates the token only at the start, the stream continues with an expired token (a security issue); if
  it closes the stream at expiry, the client reconnects with the expired token (a usability issue). Testing: open a
  stream with a short-lived token, wait for expiry, observe.
- **Silent idle timeout** (load balancer idle timeout). Load balancers assume short connections and close idle ones
  (for example after 60 seconds); a quiet stream is cut. The workaround is a heartbeat comment (`: heartbeat`) more
  often than the timeout. Testing: open a stream, send nothing, wait past the timeout, check whether it survives.

## 3. Interactions and implications for testing

### 3.1 Impedance mismatch

When architectures and protocols work together, their **design assumptions must be compatible**. The problem arises
when one layer violates the assumptions of another. The typical case: an API gateway assumes stateless HTTP
request-response, WebSocket needs a persistent stateful connection. Blind spots follow:

- the gateway's rate limiter counts the handshake and ignores the frames after it;
- the gateway's WAF inspects HTTP payloads and is blind to WebSocket frames;
- the gateway's log loses most of a large frame: AWS API Gateway truncates log events at 1024 bytes, while a
  WebSocket frame can be up to 32 KB (a message up to 128 KB).

These are not configuration bugs: they are **emergent properties** of incompatible designs.

### 3.2 Recurring mismatch patterns

1. **State mismatch**: the architecture assumes stateless, the protocol needs state (WebSocket through an API
   gateway, SSE through a load balancer, gRPC bidirectional streaming through a mesh sidecar). Infrastructure built
   for request-response fails with persistent connections: rate limiting, timeouts and resource allocation are
   wrong.
2. **Protocol translation loss**: transcoding loses metadata or meaning (gRPC-Web to gRPC through Envoy, HTTP/2
   downgraded to HTTP/1.1 by a misconfigured gateway). Logs differ (the gateway sees HTTP, the backend processes
   gRPC) and policies diverge (the WAF validates HTTP, the backend deserialises protobuf with other rules).
3. **Payload opacity**: the infrastructure cannot inspect binary or encrypted payloads (protobuf through a WAF,
   WebSocket frames after the upgrade). Injection payloads pass the security layer unseen; defence in depth is
   broken.
4. **Semantic routing failure**: the infrastructure routes on HTTP metadata, the protocol on payload semantics
   (GraphQL's single endpoint with batching, SOAP's single endpoint with the operation in the body). URL-based
   routing, rate limiting and authorization are ineffective: the gateway does not understand the application.
5. **Resource accounting mismatch**: the infrastructure counts HTTP requests, the protocol runs N operations per
   request (GraphQL batching, one HTTP/2 stream with unlimited gRPC messages, one WebSocket handshake with thousands
   of frames). Rate limiting, billing and capacity planning based on HTTP metrics are wrong.

### 3.3 Where to test what

| Protocol | With an API gateway | With Kubernetes ingress | With a service mesh | With serverless |
|---|---|---|---|---|
| REST | standard (authentication, authorization, rate limiting) | annotation-specific configuration | mTLS enforcement | IAM role privilege escalation |
| GraphQL | batching rate limit bypass | single endpoint routing | field-level authorization in mesh policy | cold start and query complexity |
| gRPC | binary payload WAF bypass | backend protocol annotation | memory exhaustion through streaming | reflection discovery in functions |
| SOAP | XXE through the gateway | XML bomb denial of service | WS-Security validation | legacy integration |
| WebSocket | rate limit after the handshake, WAF bypass, log truncation | health probe mismatch | stateful sidecar issues | connection tracking state |
| SSE | token expiry mid-stream | load balancer idle timeout | heartbeat overhead | EventSource reconnection |

### 3.4 Implications for a testing tool

A security assessment tool for cloud-native APIs should:

1. Recognise the deployed architecture: HTTP headers, metadata, behaviour.
2. Recognise the protocol: content type, endpoint patterns, payload structure.
3. Identify the architecture-protocol combination: not "GraphQL" or "API gateway" alone, but "GraphQL through an
   API gateway".
4. Select tests for the combination, guided by the matrix above (GraphQL through a gateway needs batching tests,
   gRPC through a mesh needs memory monitoring).
5. Use protocol-specific tools: generic HTTP scanners are inadequate; specialised tools (`grpcurl`, `graphql-cop`,
   `wscat`) are orchestrated by detected protocol.
6. Verify actual enforcement, not only the declared configuration: introspection disabled is not a secret schema,
   rate limiting configured is not protection; test runtime behaviour.
7. Validate every layer: the gateway (authentication, basic rate limiting), the mesh (mTLS, network policy) and the
   application (field-level authorization, input validation); look for the gaps where each layer assumes another one
   handles a control.

Generic HTTP scanners (Nikto, Dirb, an OWASP ZAP baseline scan) do not cover WebSocket frames after the handshake,
protobuf without its `.proto`, GraphQL query complexity, long SSE connections with token expiry, or protocol
downgrades (HTTP/2 to HTTP/1.1); these need specialised tools (`grpcurl` and `ghz` for gRPC, `graphql-cop` and
`clairvoyance` for GraphQL, `wscat` for WebSocket, a custom EventSource client for SSE, packet capture for protocol
inspection). The full research notes behind this chapter, with the combination-by-combination analysis, are in
[`archive/state-of-the-art-extensive.md`](archive/state-of-the-art-extensive.md).

## Conclusions

The chapter abstracted four architectural patterns (API gateway, Kubernetes ingress and Gateway API, service mesh,
serverless), each with its universal problem, common mechanism and the implementation differences that matter for
testing; six protocol mechanisms (REST, GraphQL, gRPC, SOAP, WebSocket, SSE) with the structural weaknesses that
follow from their design; and five recurring impedance mismatch patterns between the two, with a matrix of where to
test what. Abstracting instead of cataloguing, stressing substantial differences instead of feature lists, and
orienting everything to testing gives the basis for the methodology
([`methodology/framework.md`](../methodology/framework.md)) and for the tool's design.

## Corrections to the thesis version

Facts of the thesis chapter corrected on 2026-10-20 against the sources below; the thesis text is in the git history
(tag `v0.1.0`, `docs/priv/knowledge/2-Background_compact.md`).

| Thesis said | Correct | Source |
|---|---|---|
| Kong rate limiting uses a token bucket, AWS API Gateway a leaky bucket | Kong: fixed windows (Rate Limiting), sliding or fixed windows (Rate Limiting Advanced); AWS: token bucket | [Kong window types](https://developer.konghq.com/gateway/rate-limiting/window-types/), [Kong rate limiting](https://developer.konghq.com/gateway/rate-limiting), [AWS throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html) |
| Kong's plugin pipeline is synchronous and blocking | plugins run in sequence by priority in each phase; a slow plugin adds its time to the request ("blocking" dropped) | [Kong plugin ordering](https://docs.konghq.com/gateway/3.0.x/kong-enterprise/plugin-ordering) |
| AWS API Gateway has no mTLS towards private backends; Azure's managed gateway has none | AWS: client certificates for HTTP backends, ACM certificates for backend mTLS since September 2026; Azure: client certificate authentication on managed and self-hosted gateways | [AWS backend mTLS](https://aws.amazon.com/about-aws/whats-new/2026/09/amazon-api-gateway-mutual-tls-backend/), [Azure authentication-certificate](https://learn.microsoft.com/en-ie/azure/api-management/authentication-certificate-policy) |
| Nginx Ingress Controller as a current option, reload of about 100 ms | Ingress NGINX retired in March 2026 (no more security patches); the reload figure had no source | [Ingress NGINX retirement](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/), [statement of 2026-01-29](https://www.kubernetes.io/blog/2026/01/29/ingress-nginx-statement/) |
| Istio sidecar about 128 MB and 0.5 vCPU | about 0.5 vCPU per 1000 requests per second; memory depends on configuration (about 50 MB in a large namespace) | [Istio performance and scalability](https://istio.io/docs/ops/performance-and-scalability) |
| Ambient mode GA 2024 | GA in Istio 1.24, November 2024 (confirmed) | [Istio ambient GA](https://istio.io/blog/2024/ambient-reaches-ga/) |
| Linkerd: no TCP or WebSocket, no traffic splitting, no VM workloads | all TCP traffic including WebSocket; traffic splitting with HTTPRoute; non-Kubernetes workloads since 2.15 | [Linkerd features](https://linkerd.io/2.17/features/), [Linkerd traffic shifting](https://linkerd.io/2/tasks/traffic-shifting) |
| Linkerd overhead 10-15% against Istio 25-35% (source cited: LiveWyer) | the cited source says Linkerd 5-10%, Istio 25-35% slower than no mesh; the maintainers' 2021 benchmark added | [LiveWyer, Service Meshes Decoded](https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/), [Benchmarking Linkerd and Istio](https://linkerd.io/2021/05/27/linkerd-vs-istio-benchmarks/) |
| Linkerd configuration is pulled by polling, eventually consistent | pushed over a gRPC stream (full state, then changes); proxies keep the last configuration if the control plane is down | [How linkerd-destination works](https://linkerd.io/2026/02/26/deep-dive-how-linkerd-destination-works-in-the-linkerd-service-mesh/) |
| Firecracker micro-VM with 125 MB of overhead | under 5 MiB of memory overhead per micro-VM | [AWS Open Source Blog, Firecracker](https://aws.amazon.com/blogs/opensource/firecracker-open-source-secure-fast-microvm-serverless/) |
| Lambda in a VPC adds about 100-200 ms to a cold start | since 2019 the network interface is created with the function, not at cold start | [Improved VPC networking for Lambda](https://aws.amazon.com/blogs/compute/announcing-improved-vpc-networking-for-aws-lambda-functions/) |
| Durable Functions unique to Azure | AWS Lambda has durable functions since December 2025 | [Lambda durable functions](https://aws.amazon.com/about-aws/whats-new/2025/12/lambda-durable-multi-step-applications-ai-workflows/) |
| Cold start figures (100-500 ms, 1-2 s, 5-10 s; source cited for Lambda: Lumigo) | the cited source gives no figures, and no other source was found; kept as relative statements only | [Lumigo, AWS Lambda architecture](https://lumigo.io/learn/aws-lambda-architecture/) |
| CVE-2021-22570 heap overflow, CVE-2022-1941 stack overflow | null pointer dereference (crash); MessageSet parsing causing out-of-memory (denial of service) | [Debian DLA-3393-1](https://www.debian.org/lts/security/2023/dla-3393) |
| Ingress annotation `nginx.ingress.kubernetes.io/rate-limit` (and a Traefik equivalent) | the Ingress NGINX annotation is `limit-rps`; Traefik configures rate limits with middlewares, not an annotation (example dropped) | [Ingress NGINX annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/) |
| SOAP 1.2 deprecates `SOAPAction`, the operation is in the body | the action becomes an optional `action` parameter of `application/soap+xml` | [RFC 3902](https://www.rfc-editor.org/rfc/rfc3902) |
| AWS API Gateway truncates log events at 1024 bytes, WebSocket frames up to 32 KB | confirmed (messages up to 128 KB, split into frames of at most 32 KB) | [API Gateway important notes](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html) |
