# 2 \- Stato dell’arte

- [**INTRODUZIONE AL CAPITOLO**](#introduzione-al-capitolo)
- [**1.1 PREMESSA: DALL'IMPLEMENTAZIONE AL PATTERN**](#11-premessa-dallimplementazione-al-pattern)
- [**1.2 PATTERN 1: API GATEWAY - IL MEDIATORE CENTRALIZZATO**](#12-pattern-1-api-gateway---il-mediatore-centralizzato)
  - [**1.2.1 Il Problema Architetturale Universale**](#121-il-problema-architetturale-universale)
  - [**1.2.2 Il Meccanismo Tecnico Astratto**](#122-il-meccanismo-tecnico-astratto)
  - [**1.2.3 Differenze Sostanziali tra Implementazioni**](#123-differenze-sostanziali-tra-implementazioni)
    - [**A. Architettura del Data Plane**](#a-architettura-del-data-plane)
    - [**B. Meccanismo di Rate Limiting**](#b-meccanismo-di-rate-limiting)
    - [**C. TLS Termination e Backend Communication**](#c-tls-termination-e-backend-communication)
  - [**1.2.4 Implicazioni per il Testing**](#124-implicazioni-per-il-testing)
- [**1.3 PATTERN 2: KUBERNETES INGRESS E GATEWAY API**](#13-pattern-2-kubernetes-ingress-e-gateway-api)
  - [**1.3.1 Il Problema Architetturale Universale**](#131-il-problema-architetturale-universale)
  - [**1.3.2 Il Meccanismo Tecnico Astratto**](#132-il-meccanismo-tecnico-astratto)
  - [**1.3.3 Differenza Sostanziale: Ingress vs Gateway API**](#133-differenza-sostanziale-ingress-vs-gateway-api)
    - [**Ingress (Legacy Model)**](#ingress-legacy-model)
    - [**Gateway API (Modern Model)**](#gateway-api-modern-model)
  - [**1.3.4 Differenze Sostanziali tra Controller Implementation**](#134-differenze-sostanziali-tra-controller-implementation)
    - [**Nginx Ingress Controller**](#nginx-ingress-controller)
    - [**Envoy-based Controller (Istio Gateway, Contour)**](#envoy-based-controller-istio-gateway-contour)
    - [**Cilium Gateway (eBPF-based)**](#cilium-gateway-ebpf-based)
  - [**1.3.5 Implicazioni per il Testing**](#135-implicazioni-per-il-testing)
- [**1.4 PATTERN 3: SERVICE MESH - L'INFRASTRUTTURA INVISIBILE**](#14-pattern-3-service-mesh---linfrastruttura-invisibile)
  - [**1.4.1 Il Problema Architetturale Universale**](#141-il-problema-architetturale-universale)
  - [**1.4.2 Il Meccanismo Tecnico Astratto**](#142-il-meccanismo-tecnico-astratto)
  - [**1.4.3 Differenze Sostanziali tra Implementazioni**](#143-differenze-sostanziali-tra-implementazioni)
    - [**Istio (Envoy-based, feature-rich)**](#istio-envoy-based-feature-rich)
    - [**Linkerd (Rust proxy, minimalist)**](#linkerd-rust-proxy-minimalist)
  - [**1.4.4 Differenza Sostanziale: xDS Protocol e Configuration Propagation**](#144-differenza-sostanziale-xds-protocol-e-configuration-propagation)
  - [**1.4.5 Implicazioni per il Testing**](#145-implicazioni-per-il-testing)
- [**1.5 PATTERN 4: SERVERLESS - L'ASTRAZIONE COMPUTAZIONALE**](#15-pattern-4-serverless---lastrazione-computazionale)
  - [**1.5.1 Il Problema Architetturale Universale**](#151-il-problema-architetturale-universale)
  - [**1.5.2 Il Meccanismo Tecnico Astratto**](#152-il-meccanismo-tecnico-astratto)
  - [**1.5.3 Differenze Sostanziali tra Implementazioni**](#153-differenze-sostanziali-tra-implementazioni)
    - [**AWS Lambda (Micro-VM, tightly integrated)**](#aws-lambda-micro-vm-tightly-integrated)
    - [**Azure Functions (Container-based, flexible)**](#azure-functions-container-based-flexible)
    - [**Knative (Open Source, Kubernetes-based)**](#knative-open-source-kubernetes-based)
  - [**1.5.4 Differenza Sostanziale: Event Model e Invocation Type**](#154-differenza-sostanziale-event-model-e-invocation-type)
    - [**Synchronous Invocation (Request-Response)**](#synchronous-invocation-request-response)
    - [**Asynchronous Invocation (Fire-and-Forget)**](#asynchronous-invocation-fire-and-forget)
  - [**1.5.5 Implicazioni per il Testing**](#155-implicazioni-per-il-testing)
- [**2.1 PREMESSA: DAL PROTOCOLLO AL MECCANISMO**](#21-premessa-dal-protocollo-al-meccanismo)
- [**2.2 MECCANISMO 1: REST - STATELESS RESOURCE-ORIENTED**](#22-meccanismo-1-rest---stateless-resource-oriented)
  - [**2.2.1 Il Meccanismo Fondamentale**](#221-il-meccanismo-fondamentale)
  - [**2.2.2 Vulnerabilità Strutturali del Meccanismo**](#222-vulnerabilità-strutturali-del-meccanismo)
    - [**Over-fetching (Proprietà Intrinseca)**](#over-fetching-proprietà-intrinseca)
    - [**BOLA - Broken Object Level Authorization (Conseguenza di Resource Identification)**](#bola---broken-object-level-authorization-conseguenza-di-resource-identification)
    - [**Mass Assignment (Conseguenza di Flexibility Serialization)**](#mass-assignment-conseguenza-di-flexibility-serialization)
  - [**2.2.3 Differenze Sostanziali tra "Varianti REST"**](#223-differenze-sostanziali-tra-varianti-rest)
    - [**REST con HATEOAS (Hypermedia as Engine of Application State)**](#rest-con-hateoas-hypermedia-as-engine-of-application-state)
    - [**REST con Schema (OpenAPI/Swagger)**](#rest-con-schema-openapiswagger)
- [**2.3 MECCANISMO 2: GRAPHQL - QUERY LANGUAGE SU GRAFO**](#23-meccanismo-2-graphql---query-language-su-grafo)
  - [**2.3.1 Il Meccanismo Fondamentale**](#231-il-meccanismo-fondamentale)
  - [**2.3.2 Vulnerabilità Strutturali del Meccanismo**](#232-vulnerabilità-strutturali-del-meccanismo)
    - [**Query Complexity Explosion (Conseguenza di Graph Traversal)**](#query-complexity-explosion-conseguenza-di-graph-traversal)
    - [**Introspection Schema Leakage (Conseguenza di Schema-first Design)**](#introspection-schema-leakage-conseguenza-di-schema-first-design)
    - [**Batching Rate Limiting Bypass (Conseguenza Single Endpoint)**](#batching-rate-limiting-bypass-conseguenza-single-endpoint)
  - [**2.3.3 Differenza Sostanziale: Federation vs Monolith**](#233-differenza-sostanziale-federation-vs-monolith)
    - [**Monolithic GraphQL**](#monolithic-graphql)
    - [**Apollo Federation**](#apollo-federation)
- [**2.4 MECCANISMO 3: GRPC - BINARY RPC SU HTTP/2**](#24-meccanismo-3-grpc---binary-rpc-su-http2)
  - [**2.4.1 Il Meccanismo Fondamentale**](#241-il-meccanismo-fondamentale)
  - [**2.4.2 Vulnerabilità Strutturali del Meccanismo**](#242-vulnerabilità-strutturali-del-meccanismo)
    - [**Payload Opacity (Conseguenza Binary Serialization)**](#payload-opacity-conseguenza-binary-serialization)
    - [**Deserialization Vulnerabilities (Conseguenza Binary Parsing)**](#deserialization-vulnerabilities-conseguenza-binary-parsing)
    - [**Stream Exhaustion (Conseguenza HTTP/2 Streaming)**](#stream-exhaustion-conseguenza-http2-streaming)
  - [**2.4.3 Differenza Sostanziale: Reflection vs No-Reflection**](#243-differenza-sostanziale-reflection-vs-no-reflection)
    - [**gRPC con Server Reflection**](#grpc-con-server-reflection)
    - [**gRPC senza Reflection (Production Default)**](#grpc-senza-reflection-production-default)
- [**2.5 MECCANISMO 4: SOAP - XML RPC CON WS-\* STACK**](#25-meccanismo-4-soap---xml-rpc-con-ws--stack)
  - [**2.5.1 Il Meccanismo Fondamentale**](#251-il-meccanismo-fondamentale)
  - [**2.5.2 Vulnerabilità Strutturali del Meccanismo**](#252-vulnerabilità-strutturali-del-meccanismo)
    - [**XML External Entity (XXE) Injection (Conseguenza XML Parsing)**](#xml-external-entity-xxe-injection-conseguenza-xml-parsing)
    - [**XML Bomb (Billion Laughs) (Conseguenza Recursive Entity)**](#xml-bomb-billion-laughs-conseguenza-recursive-entity)
    - [**XML Signature Wrapping (Conseguenza WS-Security)**](#xml-signature-wrapping-conseguenza-ws-security)
  - [**2.5.3 Differenza Sostanziale: SOAP 1.1 vs 1.2**](#253-differenza-sostanziale-soap-11-vs-12)
    - [**SOAP 1.1**](#soap-11)
    - [**SOAP 1.2**](#soap-12)
- [**2.6 MECCANISMO 5: WEBSOCKET - FULL-DUPLEX PERSISTENTE**](#26-meccanismo-5-websocket---full-duplex-persistente)
  - [**2.6.1 Il Meccanismo Fondamentale**](#261-il-meccanismo-fondamentale)
  - [**2.6.2 Vulnerabilità Strutturali del Meccanismo**](#262-vulnerabilità-strutturali-del-meccanismo)
    - [**Cross-Site WebSocket Hijacking (CSWSH) (Conseguenza di No CORS Preflight)**](#cross-site-websocket-hijacking-cswsh-conseguenza-di-no-cors-preflight)
    - [**Stateful Rate Limiting Bypass (Conseguenza Persistent Connection)**](#stateful-rate-limiting-bypass-conseguenza-persistent-connection)
  - [**2.6.3 Differenza Sostanziale: WebSocket Subprotocol**](#263-differenza-sostanziale-websocket-subprotocol)
- [**2.7 MECCANISMO 6: SERVER-SENT EVENTS (SSE) - UNIDIRECTIONAL STREAMING**](#27-meccanismo-6-server-sent-events-sse---unidirectional-streaming)
  - [**2.7.1 Il Meccanismo Fondamentale**](#271-il-meccanismo-fondamentale)
  - [**2.7.2 Vulnerabilità Strutturali del Meccanismo**](#272-vulnerabilità-strutturali-del-meccanismo)
    - [**Token Expiration Mid-Stream (Conseguenza Long-Lived Connection)**](#token-expiration-mid-stream-conseguenza-long-lived-connection)
    - [**Connection Timeout Silente (Conseguenza Load Balancer Idle Timeout)**](#connection-timeout-silente-conseguenza-load-balancer-idle-timeout)
- [**3.1 IL PRINCIPIO DELL'IMPEDANCE MISMATCH**](#31-il-principio-dellimpedance-mismatch)
- [**3.2 PATTERN DI MISMATCH RICORRENTI**](#32-pattern-di-mismatch-ricorrenti)
  - [**Pattern 1: State Mismatch**](#pattern-1-state-mismatch)
  - [**Pattern 2: Protocol Translation Loss**](#pattern-2-protocol-translation-loss)
  - [**Pattern 3: Payload Opacity**](#pattern-3-payload-opacity)
  - [**Pattern 4: Semantic Routing Failure**](#pattern-4-semantic-routing-failure)
  - [**Pattern 5: Resource Accounting Mismatch**](#pattern-5-resource-accounting-mismatch)
- [**3.3 MATRICE CRITICA: DOVE TESTARE COSA**](#33-matrice-critica-dove-testare-cosa)
- [**3.4 IMPLICAZIONI FINALI PER IL TOOL**](#34-implicazioni-finali-per-il-tool)
- [**CONCLUSIONI DEL CAPITOLO**](#conclusioni-del-capitolo)


# **CAPITOLO 1: STATO DELL'ARTE \- ARCHITETTURE E PROTOCOLLI PER L'ESPOSIZIONE DI API IN AMBIENTE CLOUD**

---

## **INTRODUZIONE AL CAPITOLO**

Quando si progetta un tool per l'assessment automatizzato della sicurezza delle API in ambiente cloud, il primo ostacolo non è tecnico ma epistemologico: cosa significa "testare un'API" quando quella stessa API può essere esposta attraverso un API Gateway tradizionale, un Kubernetes Ingress Controller, un Service Mesh, o un'architettura serverless? E cosa cambia se il protocollo utilizzato è REST, GraphQL, gRPC, SOAP, WebSocket o Server-Sent Events?

La tentazione naturale è compilare un catalogo descrittivo: "Kong funziona così, AWS API Gateway ha queste feature, REST usa HTTP, GraphQL usa query..." Questo approccio, pur completo, fallisce nel fornire ciò che serve realmente: una comprensione astratta dei **pattern architetturali** e dei **meccanismi protocollo** che permetta di identificare dove e come testare, indipendentemente dall'implementazione specifica.

Questo capitolo adotta un approccio diverso, orientato all'astrazione tecnica e alle differenze sostanziali. L'obiettivo non è documentare ogni tecnologia esistente, ma estrarre i principi fondamentali che governano l'esposizione delle API moderne, evidenziando dove le implementazioni divergono in modi rilevanti per la sicurezza. Solo comprendendo "come funziona sotto il cofano" possiamo progettare strategie di testing efficaci.

Il capitolo si articola in tre sezioni progressive:

**Sezione 1 \- Pattern Architetturali per l'Esposizione di API**: Analizza le quattro categorie architetturali dominanti (API Gateway, Kubernetes Ingress/Gateway, Service Mesh, Serverless), astraendo il pattern tecnico universale e identificando le differenze implementative sostanziali tra vendor e progetti.

**Sezione 2 \- Meccanismi Protocollo e Superfici di Attacco**: Esamina sei protocolli API (REST, GraphQL, gRPC, SOAP, WebSocket, SSE), focalizzandosi non sulla sintassi ma sui meccanismi tecnici che determinano come i dati vengono serializzati, trasmessi e interpretati, e quali vulnerabilità strutturali emergono da questi meccanismi.

**Sezione 3 \- Interazioni Architettura-Protocollo e Implicazioni per il Testing**: Sintetizza come pattern architetturali e meccanismi protocollo interagiscono, identificando dove nascono complessità e blind spot che il tool di testing dovrà affrontare.

---

# **SEZIONE 1: PATTERN ARCHITETTURALI PER L'ESPOSIZIONE DI API**

## **1.1 PREMESSA: DALL'IMPLEMENTAZIONE AL PATTERN**

Quando si analizzano le architetture per l'esposizione di API, il rischio è perdersi nelle peculiarità implementative: "Kong usa Nginx+Lua, AWS API Gateway è fully-managed, Azure offre self-hosted gateway..." Questi dettagli, pur rilevanti in fase di deployment, oscurano il pattern architetturale sottostante.

L'approccio corretto è identificare prima il **problema architetturale universale** che ogni categoria risolve, poi astrarre il **meccanismo tecnico** con cui viene risolto, e solo infine evidenziare le **differenze sostanziali** tra implementazioni dove queste differenze impattano la superficie di attacco o le strategie di testing.

## **1.2 PATTERN 1: API GATEWAY \- IL MEDIATORE CENTRALIZZATO**

### **1.2.1 Il Problema Architetturale Universale**

In un'architettura microservizi, ogni servizio espone la propria interfaccia. Un'applicazione con cinquanta microservizi ha potenzialmente cinquanta endpoint distinti, ciascuno con proprie politiche di autenticazione, rate limiting, versioning. Dal punto di vista del client esterno, questa frammentazione è ingestibile. Dal punto di vista della sicurezza, ogni endpoint è un potenziale vettore di attacco che richiede protezione individuale.

Il pattern API Gateway risolve questo problema introducendo un **single point of entry**: un proxy reverse specializzato che intercetta tutto il traffico esterno, applica policy trasversali (autenticazione, rate limiting, logging), e route le richieste ai backend appropriati. Il gateway diventa il gatekeeper: nessun client esterno può raggiungere i microservizi senza passare attraverso di esso.

### **1.2.2 Il Meccanismo Tecnico Astratto**

Indipendentemente dall'implementazione, un API Gateway opera secondo questo flusso:

\[Client Esterno\]  
    ↓ (1. Richiesta HTTPS)  
\[Gateway Layer \- TLS Termination\]  
    ↓ (2. Decifrazione TLS)  
\[Authentication Layer\]  
    ↓ (3. Validazione credenziali \- JWT/API Key/OAuth)  
\[Authorization Layer\]  
    ↓ (4. Verifica permessi per risorsa richiesta)  
\[Rate Limiting Layer\]  
    ↓ (5. Token bucket / leaky bucket algorithm)  
\[Routing Layer\]  
    ↓ (6. Mappatura URL path → Backend Service)  
\[Backend Communication\]  
    ↓ (7. Proxy request \- tipicamente HTTP plaintext su rete interna)  
\[Microservizio Backend\]

Questo pattern è universale. Le implementazioni divergono su **dove** e **come** ciascun layer è implementato, ma il pattern rimane costante.

### **1.2.3 Differenze Sostanziali tra Implementazioni**

Le differenze che impattano testing e sicurezza si concentrano su tre dimensioni:

#### **A. Architettura del Data Plane**

**Kong (Nginx-based, self-hosted)**

Il data plane di Kong è costruito su Nginx esteso con OpenResty (runtime Lua). Ogni richiesta attraversa una pipeline di plugin Lua eseguiti sequenzialmente. Il meccanismo è sincrono e blocking: se un plugin impiega 100ms (esempio: query database per validazione), quella latency si somma al tempo totale della richiesta.

La conseguenza per il testing: plugin mal configurati o lenti introducono vulnerabilità DoS facilmente sfruttabili. Un attacker può creare richieste che triggherano plugin computazionalmente costosi, causando degradation delle performance per tutti i client.

**AWS API Gateway (managed service)**

Il data plane è completamente opaco (managed by AWS). Non esiste accesso diretto ai server sottostanti. La configurazione avviene dichiarativamente via API/Console, e AWS gestisce deployment, scaling, patching.

La conseguenza per il testing: impossibile testare vulnerabilità infrastructure-level (esempio: exploit kernel, container escape). Il testing si limita alla configurazione delle policy e al comportamento esposto via API. Questo riduce la superficie di attacco testabile, ma introduce dipendenza da trust verso AWS.

**Azure API Management (hybrid: managed \+ self-hosted)**

Azure offre sia managed gateway (simile ad AWS) sia self-hosted gateway deployabile come container Docker/Kubernetes. Il self-hosted gateway comunica con management plane cloud-based per configurazione.

La conseguenza per il testing: in deployment hybrid, il canale di comunicazione gateway↔management plane è una superficie di attacco aggiuntiva. Se un attacker compromette questo canale (MITM, credential theft), può alterare configurazioni gateway senza accesso diretto al management plane.

#### **B. Meccanismo di Rate Limiting**

**Token Bucket vs Leaky Bucket**

**Kong** implementa rate limiting tramite plugin configurabili che supportano token bucket algorithm: ogni client ha un bucket con N token, ogni richiesta consuma 1 token, il bucket si riempie a rate R token/sec. Quando il bucket è vuoto, richieste vengono rifiutate.

**AWS API Gateway** usa **leaky bucket variant**: richieste entrano in una coda (bucket), processate a rate costante. Se la coda si riempie, nuove richieste vengono droppate.

La differenza sostanziale per testing: token bucket permette **burst** (un client può inviare N richieste simultanee consumando tutti i token, poi attende refill). Leaky bucket **appiattisce** il traffico (rate costante indipendentemente da burst). Testare rate limiting richiede comprendere quale algoritmo è implementato: inviare burst per testare token bucket, stream costante per testare leaky bucket.

#### **C. TLS Termination e Backend Communication**

**Tutti i gateway terminano TLS al gateway layer**, ma differiscono su cosa accade post-termination:

* **Kong**: Backend communication può essere configurata HTTP plaintext, HTTPS con TLS self-signed, o mTLS. Default: HTTP plaintext su rete interna VPC.  
* **AWS API Gateway**: Backend communication è HTTP plaintext verso Lambda/EC2 in VPC, o HTTPS verso endpoint pubblici. Non supporta mTLS nativo per backend privati.  
* **Azure API Management**: Self-hosted gateway supporta mTLS verso backend, managed gateway no.

La differenza sostanziale per testing: se backend communication è plaintext, un attacker con accesso alla rete interna (lateral movement da container compromesso) può sniffare traffico API in chiaro. Testing deve verificare non solo security perimetrale (gateway→client), ma anche security interna (gateway→backend).

### **1.2.4 Implicazioni per il Testing**

Un tool di testing deve:

1. **Riconoscere l'implementazione**: Fingerprinting via header HTTP (`Server: kong/3.x`, `X-Amzn-RequestId` per AWS), error messages, behavior specifico.

2. **Testare il pattern universale**: Indipendentemente dal vendor, testare autenticazione bypass, authorization flaws, rate limiting bypass, injection via routing parameters.

3. **Testare le differenze sostanziali**:

   * Per **Kong**: plugin enumeration (quali plugin attivi?), plugin misconfiguration, Lua code injection se plugin custom.  
   * Per **AWS**: IAM (Identity and Access Management) policy audit, Lambda authorizer logic flaws, CloudWatch log analysis per anomaly detection.  
   * Per **Azure**: self-hosted gateway communication channel security, policy XML injection (Azure usa policy basate su XML).

---

## **1.3 PATTERN 2: KUBERNETES INGRESS E GATEWAY API**

### **1.3.1 Il Problema Architetturale Universale**

Kubernetes risolve orchestrazione container, ma non fornisce meccanismo nativo per esporre servizi HTTP/HTTPS al mondo esterno. Un Service di tipo ClusterIP è raggiungibile solo all'interno del cluster. Un Service di tipo LoadBalancer crea un load balancer cloud-provider-specific (costoso e non portabile). Serve un'astrazione Kubernetes-native per routing HTTP con feature di reverse proxy.

Kubernetes Ingress (legacy) e Gateway API (moderno) risolvono questo problema definendo risorse declarative che specificano routing rules, e delegando l'implementazione a controller specializzati.

### **1.3.2 Il Meccanismo Tecnico Astratto**

Il pattern è separation of concerns tra **configurazione** (risorse Kubernetes) e **implementazione** (controller):

\[Developer\]  
    ↓ (Scrive risorsa Ingress/HTTPRoute YAML)  
\[Kubernetes API Server\]  
    ↓ (Persiste risorsa in etcd)  
\[Ingress/Gateway Controller\]  
    ↓ (Watch Kubernetes API per risorse nuove/modificate)  
    ↓ (Traduce risorsa in configurazione reverse proxy)  
\[Reverse Proxy \- Nginx/Envoy/Traefik\]  
    ↓ (Applica nuova configurazione, reload/hot-reload)  
\[Traffico HTTP/HTTPS\]  
    ↓ (Route basato su hostname/path nelle risorsa)  
\[Kubernetes Service → Pod backend\]

Il pattern è universale. Le implementazioni differiscono su quale reverse proxy usano e come traducono risorse Kubernetes in configurazione proxy.

### **1.3.3 Differenza Sostanziale: Ingress vs Gateway API**

#### **Ingress (Legacy Model)**

Ingress è una risorsa Kubernetes che definisce routing HTTP basico:

* **Hostname-based routing**: richieste a `api.example.com` vanno al Service A, richieste a `app.example.com` vanno al Service B.  
* **Path-based routing**: richieste a `/api/v1/users` vanno al Service Users, `/api/v1/products` vanno al Service Products.  
* **TLS termination**: specifica certificati TLS da usare per hostname.

Il problema strutturale di Ingress: feature avanzate (rate limiting, authentication, header rewrite) richiedono **annotation controller-specific**:

metadata:  
  annotations:  
    nginx.ingress.kubernetes.io/rate-limit: "100"  
    traefik.ingress.kubernetes.io/rate-limit: "qps: 100"

Queste annotation non sono portabili. Migrare da Nginx a Traefik richiede riscrivere tutte le annotation.

#### **Gateway API (Modern Model)**

Gateway API risolve questo con **role-oriented design** e risorse tipizzate:

* **GatewayClass**: definisce il tipo di controller (Nginx, Istio, Cilium). Gestito da infrastructure provider.  
* **Gateway**: istanza di una GatewayClass, definisce listener (porta, protocollo, TLS). Gestito da cluster operator.  
* **HTTPRoute/GRPCRoute/TCPRoute**: definisce routing granulare per protocollo. Gestito da application developer.

Il vantaggio: specification è standardizzata. Un HTTPRoute che specifica header matching funziona identicamente su Nginx, Istio, Cilium (tutti implementano la spec).

### **1.3.4 Differenze Sostanziali tra Controller Implementation**

#### **Nginx Ingress Controller**

Nginx traduce Ingress resource in file `nginx.conf`. Ogni modifica richiede reload Nginx process (hot-reload senza downtime, ma introduce latency \~100ms).

Implicazione per testing: esiste window temporale tra modifica Ingress e applicazione configurazione. Un attacker potrebbe sfruttare questa race condition: creare risorsa malevola, triggerare traffico prima che Nginx reload, cancellare risorsa prima che admin noti.

#### **Envoy-based Controller (Istio Gateway, Contour)**

Una rete di proxy intelligenti (chiamati Envoy) messi a fianco di ogni tuo servizio. Envoy usa xDS protocol per configuration updates dinamiche senza reload. Controller traduce Gateway API resource in configurazione xDS, push a Envoy via gRPC stream. Envoy applica configurazione atomicamente.

Implicazione per testing: non esiste window temporale di inconsistenza. Ma xDS protocol stesso è superficie di attacco: se attacker compromette control plane, può iniettare configurazioni malevole via xDS push.

#### **Cilium Gateway (eBPF-based)**

Cilium implementa Gateway API direttamente nel CNI layer usando eBPF programs nel kernel:  Invece di avere un programma che gira "sopra" il sistema operativo, Cilium inietta le regole di rete direttamente dentro il **Kernel**. Non c'è reverse proxy user-space separato. Routing e policy enforcement avvengono a livello kernel.

Implicazione per testing: performance eccezionali (no context switch user-space), ma superficie di attacco incluse vulnerability kernel eBPF subsystem. Testing richiede comprendere eBPF security model (verifier, capability checks).

### **1.3.5 Implicazioni per il Testing**

Un tool deve:

1. **Distinguere Ingress vs Gateway API**: Resource type (`kind: Ingress` vs `kind: HTTPRoute`) determina quale spec è implementata.

2. **Identificare controller**: Via annotation (`kubernetes.io/ingress.class: nginx`) o GatewayClass reference. Controller diversi hanno behavior diverso.

3. **Testare portability**: Un HTTPRoute dovrebbe funzionare identicamente su controller diversi. Testing cross-controller verifica compliance a spec.

4. **Testare configuration drift**: In cluster con controller multipli (esempio: Nginx per HTTP, Istio per gRPC), verificare che policy siano consistent tra controller.

---

## **1.4 PATTERN 3: SERVICE MESH \- L'INFRASTRUTTURA INVISIBILE**

### **1.4.1 Il Problema Architetturale Universale**

API Gateway e Ingress gestiscono traffico **North-South** (external→internal). Ma in architetture microservizi, il volume dominante è traffico **East-West** (service-to-service interno). Come si implementa mTLS tra tutti i servizi senza modificare codice applicativo? Come si gestiscono retry, timeout, circuit breaker in modo consistente? Come si osserva traffico per debugging?

Il pattern Service Mesh risolve introducendo un **data plane distribuito** (proxy che intercettano traffico service-to-service) e un **control plane centralizzato** (che configura i proxy e aggrega telemetry).

### **1.4.2 Il Meccanismo Tecnico Astratto**

Il pattern universale è proxy injection \+ control plane configuration:

\[Service A Pod\]  
  \[Application Container\] → (chiama Service B via localhost)  
      ↓ (iptables rules redirect a proxy)  
  \[Sidecar Proxy \- Envoy/linkerd2-proxy\]  
      ↓ (Intercetta traffico outbound)  
      ↓ (mTLS encryption con certificato da Control Plane)  
      ↓ (Service Discovery via Control Plane)  
      ↓ (Load Balancing L7 tra endpoint Service B)  
\[Network\]  
      ↓ (Traffico cifrato)  
\[Service B Pod\]  
  \[Sidecar Proxy\]  
      ↓ (mTLS decryption)  
      ↓ (Authorization policy enforcement)  
      ↓ (Metrics collection)  
  \[Application Container\] ← (Riceve richiesta plaintext)

Il control plane (**Istiod** per Istio, **Linkerd** control plane) gestisce:

* Certificate Authority: emette certificati X.509 per workload identity  
* Service Discovery: mappa service name → endpoint IP  
* Configuration distribution: push policy (VirtualService, DestinationRule) ai sidecar

Questo pattern è universale. Le implementazioni differiscono su **quale proxy** usano e **come** configurano il data plane.

### **1.4.3 Differenze Sostanziali tra Implementazioni**

#### **Istio (Envoy-based, feature-rich)**

**Data Plane**: Envoy proxy (C++), altamente configurabile, supporta HTTP/1.1, HTTP/2, gRPC, TCP, WebSocket.

**Control Plane**: Istiod (monolitico dal 2020), traduce risorse Istio high-level (VirtualService, DestinationRule) in configurazioni Envoy low-level via xDS protocol.

**Differenza sostanziale \- Sidecar vs Ambient Mode**:

Tradizionale sidecar mode: ogni Pod ha due container (app \+ Envoy). Overhead memoria/CPU significativo (\~128MB \+ 0.5 vCPU per sidecar).

Ambient mode (GA 2024): elimina sidecar. Introduce **ztunnel** (proxy Layer 4, one-per-node, Rust-based) per mTLS, e **Waypoint proxy** (Layer 7, one-per-namespace, optional) per traffic management.

Implicazione per testing: architettura sidecar richiede testare ogni Pod individualmente (ogni sidecar può avere configurazione differente). Architettura ambient richiede testare ztunnel node-level e waypoint namespace-level (configurazione più centralizzata).

#### **Linkerd (Rust proxy, minimalist)**

**Data Plane**: linkerd2-proxy (Rust), proxy custom ultraleggero (\~10MB memory footprint). Supporta solo HTTP/1.1, HTTP/2, gRPC. No TCP/WebSocket.

**Control Plane**: Linkerd control plane (Go), architettura microservizi (destination, identity, proxy-injector).

**Differenza sostanziale \- Performance vs Features**:

Linkerd sacrifica features per performance. Non supporta traffic splitting avanzato (canary deployment richiede external tool Flagger), no service mesh federation, no VM workload support.

Ma performance sono eccellenti: overhead 10-15% rispetto a no-mesh, contro 25-35% di Istio.

Implicazione per testing: Linkerd è più semplice da testare (meno feature \= meno superficie di attacco), ma coverage è limitata (no test per TCP proxying, WebSocket, etc).

### **1.4.4 Differenza Sostanziale: xDS Protocol e Configuration Propagation**

Questa differenza, tecnica ma critica, impatta direttamente testing.

**Istio xDS Model (Push-based)**:

Quando un administrator crea/modifica una VirtualService, Istiod:

1. Valida la risorsa  
2. Traduce in configurazione Envoy (Listener, Cluster, Route)  
3. **Push** immediatamente ai sidecar Envoy interessati via gRPC stream

Implicazione: configurazione si propaga in secondi (fast). Ma in cluster molto grandi (1000+ Pod), push storm può sovraccaricare Istiod.

**Linkerd Model (Pull-based con cache)**:

Linkerd proxy fa periodiche poll al destination service per endpoint updates. Configuration propagation è **eventual consistent**, non immediata.

Implicazione: esiste window temporale (secondi-minuti) dove configurazione nuova non è ancora applicata. Testing deve considerare eventual consistency: verificare non solo che configurazione sia corretta, ma anche che sia effettivamente applicata a tutti i proxy.

### **1.4.5 Implicazioni per il Testing**

Un tool deve:

1. **Rilevare presenza Service Mesh**: Via label/annotation Pod (`sidecar.istio.io/inject: "true"`), presence di container sidecar (`istio-proxy`, `linkerd-proxy`).

2. **Testare mTLS enforcement**: Non assumere che "Service Mesh \= cifrato". Verificare che mTLS sia effettivamente enforced (mode STRICT vs PERMISSIVE).

3. **Testare authorization policies**: Service Mesh permette policy granulari (Service A può chiamare Service B solo su path `/api/v1`). Testing deve verificare enforcement di queste policy, non solo configurazione.

4. **Testare configuration consistency**: In multi-cluster o con eventual consistency model, verificare che policy sia applicata uniformemente a tutti i proxy.

---

## **1.5 PATTERN 4: SERVERLESS \- L'ASTRAZIONE COMPUTAZIONALE**

### **1.5.1 Il Problema Architetturale Universale**

Server always-on sprecano risorse: un servizio usato 10 minuti/giorno consuma CPU 24/7. Gestire scaling (aggiungere server quando carico aumenta) è complesso e lento. Gestire patching, monitoring, HA (High Availability) richiede overhead operativo significativo.

Il pattern Serverless elimina questi problemi: invece di deployare server, si deployano **funzioni event-driven** che:

* Vengono eseguite on-demand (triggered da eventi)  
* Scalano automaticamente (da zero a migliaia di istanze)  
* Pagano solo execution time effettivo (no idle cost)

### **1.5.2 Il Meccanismo Tecnico Astratto**

Il pattern universale è **event triggering \+ ephemeral execution**:

\[Event Source \- HTTP request/S3 upload/DynamoDB change\]  
    ↓ (Trigger evento)  
\[Serverless Platform\]  
    ↓ (Se function non running → Cold Start)  
        ↓ (Provisioning execution environment \- micro-VM/container)  
        ↓ (Download code function)  
        ↓ (Initialize runtime \- Python/Node/Java)  
    ↓ (Se function warm → Riusa environment esistente)  
\[Function Execution\]  
    ↓ (Handler function riceve event object)  
    ↓ (Business logic \- query DB, process data, call API)  
\[Function Response\]  
    ↓ (Return value/HTTP response)  
\[Serverless Platform\]  
    ↓ (Mantiene environment warm per N minuti)  
    ↓ (Poi termina per liberare risorse)

Questo pattern è universale. Le implementazioni differiscono su **isolation model** (micro-VM vs container), **cold start duration**, e **integration con ecosystem**.

### **1.5.3 Differenze Sostanziali tra Implementazioni**

#### **AWS Lambda (Micro-VM, tightly integrated)**

**Isolation**: Lambda usa **Firecracker microVM** (virtualizzazione leggera). Ogni function execution ottiene micro-VM dedicata (kernel Linux minimal, 125MB RAM overhead).

**Cold Start**: 100-500ms per runtime interpretati (Python, Node), fino a 1-2s per runtime JIT (Java, .NET). Provisioned Concurrency (environment pre-warmed) elimina cold start ma costa.

**Integration**: Nativa con AWS ecosystem (API Gateway, DynamoDB, S3, EventBridge). Function può assumere IAM role per accesso risorse AWS.

**Differenza sostanziale \- VPC Integration**:

Lambda può accedere a risorse VPC private (RDS, ElastiCache). Meccanismo: Hyperplane ENI (Elastic Network Interface) pooling. AWS mantiene pool di ENI pre-create nella VPC, Lambda alloca ENI dal pool.

Implicazione: cold start VPC-integrated Lambda è \~100-200ms overhead (vs \~10ms per Lambda senza VPC). Testing deve misurare latency separatamente per VPC vs no-VPC.

#### **Azure Functions (Container-based, flexible)**

**Isolation**: Azure Functions usa **container** (non micro-VM). Execution environment è container Docker con runtime pre-configurato.

**Cold Start**: Simile a Lambda (100-500ms), ma consumption plan ha cold start più lunghi (1-2s) perché container start è più lento di microVM.

**Integration**: Nativa con Azure ecosystem (Cosmos DB, Blob Storage, Event Grid). Supporta anche **Durable Functions** (stateful workflows, unique ad Azure).

**Differenza sostanziale \- Durable Functions**:

Permette orchestrare function sequences con stato persistente. Pattern: function chaining, fan-out/fan-in, human interaction (workflow attende approval).

Implicazione per testing: Durable Functions introduce stato (violando stateless serverless model). Testing deve verificare state consistency, replay attacks (orchestrator può re-execute function con stesso input).

#### **Knative (Open Source, Kubernetes-based)**

**Isolation**: Knative usa **Kubernetes Pod** standard. Nessun isolation addizionale oltre Kubernetes namespace/network policy.

**Cold Start**: Più lungo (5-10s) perché Pod start richiede pull image, scheduling, init container. Mitigabile con minScale \> 0 (mantiene sempre N Pod warm).

**Integration**: Kubernetes-native. Integra con Kubernetes Service, ConfigMap, Secret. No integration specifica cloud provider.

**Differenza sostanziale \- Revision-based deployment**:

Knative introduce concetto di **Revision**: ogni deploy crea immutable revision. Traffic può essere split tra revision (blue-green, canary).

Implicazione per testing: un Service Knative può avere URL multipli (`myservice-v1`, `myservice-v2`, `myservice-latest`). Discovery deve identificare tutte le revision attive.

### **1.5.4 Differenza Sostanziale: Event Model e Invocation Type**

#### **Synchronous Invocation (Request-Response)**

HTTP API trigger Lambda/Function, attende response, ritorna al client. Timeout tipico: 30s-15min (varia per platform).

Implicazione per testing: testabile come normale HTTP API. Fuzzing, injection, authorization bypass standard.

#### **Asynchronous Invocation (Fire-and-Forget)**

Event (S3 upload, DynamoDB stream) trigger Lambda, platform mette event in queue, ritorna subito. Lambda processa da queue asynchronously. Se fail, retry automatico (configurabile 0-2 retry).

Implicazione per testing: non c'è response immediata. Testing richiede verificare side-effects (es: file processato, record DB aggiornato). Anche: testare retry logic (cosa succede se function fail 3 volte? Event va in DLQ \- Dead Letter Queue).

### **1.5.5 Implicazioni per il Testing**

Un tool deve:

1. **Identificare platform serverless**: Via metadata HTTP response (AWS: `X-Amzn-RequestId`, Azure: `x-ms-request-id`), timing patterns (cold start latency spikes).

2. **Testare cold start exploitation**: Inviare burst request dopo periodo idle, verificare se cold start causa timeout/error exploitable.

3. **Testare IAM/identity**: Lambda assume IAM role. Verificare che role abbia least privilege (no `AdministratorAccess`), che function non possa escalate privilege.

4. **Testare event injection**: Per async invocation, verificare input validation (event malformato può causare crash/retry storm).

5. **Testare secrets management**: Verificare che secrets (DB password, API key) non siano hardcoded nel code o loggati in CloudWatch/Application Insights.

# 

# **SEZIONE 2: MECCANISMI PROTOCOLLO E SUPERFICI DI ATTACCO**

## **2.1 PREMESSA: DAL PROTOCOLLO AL MECCANISMO**

Quando si analizzano protocolli API, la tentazione è catalogare sintassi: "REST usa GET/POST/PUT, GraphQL usa query/mutation, gRPC usa protobuf..." Questo approccio, pur corretto, non rivela le proprietà fondamentali che determinano sicurezza.

L'approccio corretto è astrarre i **meccanismi tecnici** sottostanti: come i dati vengono serializzati, come il trasporto gestisce stato, come client e server negoziano formato. Solo comprendendo questi meccanismi possiamo identificare vulnerabilità strutturali (non bug implementation-specific, ma proprietà intrinseche del design protocollo).

## **2.2 MECCANISMO 1: REST \- STATELESS RESOURCE-ORIENTED**

### **2.2.1 Il Meccanismo Fondamentale**

REST non è un protocollo (non c'è RFC che definisce "REST protocol"), ma uno **stile architetturale** basato su principi:

**Principio 1 \- Resource Identification**: Ogni entità (user, product, order) è una risorsa identificata da URL univoco.

**Principio 2 \- Uniform Interface**: Manipolazione risorse tramite metodi HTTP standard (GET=read, POST=create, PUT=replace, PATCH=modify, DELETE=remove).

**Principio 3 \- Statelessness**: Ogni richiesta contiene tutte le informazioni necessarie. Server non mantiene session state tra richieste.

**Principio 4 \- Representation**: Risorsa ha multiple rappresentazioni (JSON, XML, HTML). Client e server negoziano via content negotiation (header `Accept`, `Content-Type`).

Il meccanismo tecnico astratto:

\[Client\]  
    ↓ (HTTP Request: GET /users/123)  
    ↓ (Headers: Accept: application/json, Authorization: Bearer \<token\>)  
\[Server\]  
    ↓ (Parsing: metodo GET, risorsa /users/123, formato desiderato JSON)  
    ↓ (Authentication: valida Bearer token)  
    ↓ (Authorization: verifica che token permetta accesso user 123\)  
    ↓ (Resource retrieval: query DB per user ID 123\)  
    ↓ (Serialization: oggetto user → JSON)  
\[Client\]  
    ← (HTTP Response: 200 OK, Content-Type: application/json)  
    ← (Body: {"id": 123, "name": "Alice"})

### **2.2.2 Vulnerabilità Strutturali del Meccanismo**

Le vulnerabilità emergono non da bug implementation, ma dal meccanismo stesso:

#### **Over-fetching (Proprietà Intrinseca)**

REST ritorna l'intera rappresentazione di una risorsa. Se client vuole solo `name`, GET a `/users/123` ritorna comunque `{id, name, email, dateOfBirth, address, ...}`.

Questo non è un bug: REST non ha meccanismo nativo per field selection. È una **conseguenza diretta** del principio "resource representation".

Implicazione sicurezza: campi sensibili (`passwordHash`, `internalId`) inclusi nella response anche se client non li richiede \= excessive data exposure.

Testing: verificare quali campi sono ritornati, comparare con principio least privilege (client dovrebbe ricevere solo dati necessari per use case).

#### **BOLA \- Broken Object Level Authorization (Conseguenza di Resource Identification)**

REST identifica risorse tramite ID nell'URL: `/users/123`, `/orders/456`. ID sono spesso sequenziali o prevedibili.

Il meccanismo non fornisce authorization built-in. È responsabilità developer verificare che richiedente abbia permesso per risorsa specifica.

Implicazione sicurezza: se authorization check è assente o flawed, attacker può iterare ID (`/users/1`, `/users/2`, ...) accedendo a risorse altrui.

Testing: autenticarsi con user A, richiedere risorsa user B, verificare se accesso è negato. Questo richiede multi-user testing (non supportato da scanner HTTP generici).

#### **Mass Assignment (Conseguenza di Flexibility Serialization)**

REST non impone schema. Un POST/PUT può contenere qualsiasi campo JSON. Se backend deserializza direttamente in oggetto DB senza whitelist, attacker può iniettare campi non documentati:

POST /users  
{"username": "attacker", "email": "evil@test.com", "isAdmin": true}

Se `isAdmin` mappa a colonna DB, attacker crea account admin.

Testing: fuzzing con campi aggiuntivi (isAdmin, role, privileges), verificare se backend li processa.

### **2.2.3 Differenze Sostanziali tra "Varianti REST"**

REST puro (Fielding's dissertation) è raro. La maggioranza delle "REST API" sono **REST-like** con deviazioni.

#### **REST con HATEOAS (Hypermedia as Engine of Application State)**

Risposte includono link a risorse correlate:

{  
  "id": 123,  
  "name": "Alice",  
  "\_links": {  
    "orders": "/users/123/orders",  
    "profile": "/users/123/profile"  
  }  
}

Implicazione testing: crawler può seguire `_links` per discover endpoint. Ma HATEOAS è raramente implementato, rendendo discovery più difficile.

#### **REST con Schema (OpenAPI/Swagger)**

API documenta schema in formato OpenAPI (YAML/JSON). Schema definisce endpoint, parametri, response format.

Implicazione testing: schema è gold mine per testing. Permette generazione automatica test cases, fuzzing basato su type constraints, identificazione endpoint non documentati (shadow API).

Ma: schema è optional, spesso outdated, non enforced a runtime.

---

## **2.3 MECCANISMO 2: GRAPHQL \- QUERY LANGUAGE SU GRAFO**

### **2.3.1 Il Meccanismo Fondamentale**

GraphQL rivoluziona il modello REST con approccio radicalmente diverso: invece di endpoint multipli per risorse diverse, **single endpoint** (`/graphql`) che accetta query in domain-specific language.

Il meccanismo astratto:

**Schema-first**: Server definisce schema GraphQL (types, fields, relationships) fortemente tipizzato.

**Client-driven**: Client specifica esattamente quali field desidera. Server ritorna solo quei field (risolve over-fetching REST).

**Graph traversal**: Schema è grafo di tipi. Query traversa grafo seguendo edges (relazioni tra tipi).

Il meccanismo tecnico:

\[Client\]  
    ↓ (POST /graphql)  
    Body: {"query": "{ user(id: 123\) { name posts { title } } }"}  
\[GraphQL Server\]  
    ↓ (Lexing & Parsing: query string → Abstract Syntax Tree)  
    ↓ (Validation: AST vs schema \- field "user" esiste? field "name" esiste su type User?)  
    ↓ (Execution: per ogni field nell'AST, chiama resolver function)  
        Resolver user(id: 123\) → query DB users  
        Resolver posts → query DB posts WHERE userId=123  
    ↓ (Composition: assembla risultati in JSON)  
\[Client\]  
    ← (Response: {"data": {"user": {"name": "Alice", "posts": \[...\]}}})

### **2.3.2 Vulnerabilità Strutturali del Meccanismo**

#### **Query Complexity Explosion (Conseguenza di Graph Traversal)**

GraphQL permette query annidate arbitrariamente:

query { users { posts { comments { author { posts { comments { ... } } } } } } }

Ogni livello moltiplica resolver execution. 10 users × 100 posts/user × 50 comments/post \= 50.000 resolver calls.

Implicazione sicurezza: DoS via computationally expensive query. Server esaurisce CPU/memoria, database overload.

Testing: generare query con nesting crescente, misurare response time e carico server. Verificare se server implementa query complexity limits (depth limit, cost analysis).

#### **Introspection Schema Leakage (Conseguenza di Schema-first Design)**

GraphQL espone schema via introspection query:

{ \_\_schema { types { name fields { name type { name } } } } }

Ritorna tutti tipi, field, relationship. Per attacker: mappa completa della struttura dati.

Best practice: disabilitare introspection in produzione. Ma: schema è ricostruibile via **field suggestion errors**:

{ user { invalidField } }  
→ Error: "Did you mean 'username', 'email', 'firstName'?"

Iterando, attacker ricostruisce schema (tool: Clairvoyance).

Implicazione: introspection disabled ≠ schema segreto. È security theater, non difesa reale.

Testing: tentare introspection. Se disabled, usare field suggestion brute-force. Comparare schema ottenuto con documentazione (rivela shadow field).

#### **Batching Rate Limiting Bypass (Conseguenza Single Endpoint)**

GraphQL supporta alias per inviare query multiple in singola richiesta:

{ user1: user(id: 1\) {...}, user2: user(id: 2\) {...}, ..., user1000: user(id: 1000\) {...} }

API Gateway vede: 1 HTTP POST. Backend esegue: 1000 resolver calls.

Implicazione: rate limiting HTTP-based (100 req/sec) bypassato. 100 POST × 1000 alias \= 100.000 operazioni/sec.

Testing: inviare batch query, verificare se rate limiting è enforced per operazione GraphQL, non HTTP request.

### **2.3.3 Differenza Sostanziale: Federation vs Monolith**

#### **Monolithic GraphQL**

Single GraphQL server con schema completo. Tutti resolver in un codebase.

Pro: semplice. Contro: non scala per team multipli (merge conflict su schema).

#### **Apollo Federation**

Schema distribuito: ogni microservizio espone subgraph (schema parziale). Apollo Gateway compone subgraph in supergraph.

Meccanismo:

\[Client Query\]  
    ↓ (Gateway riceve query)  
\[Query Planning\]  
    ↓ (Gateway analizza: quali subgraph servono per rispondere?)  
    ↓ (Genera sub-query per ciascun subgraph)  
\[Parallel Execution\]  
    ├→ Subgraph Products  
    ├→ Subgraph Reviews  
    └→ Subgraph Users  
\[Response Merging\]  
    ↓ (Gateway combina risultati)  
\[Client\]

Implicazione testing: testare non solo supergraph exposed, ma anche subgraph individualmente. Verificare che entity resolution (join tra subgraph) funzioni correttamente, non esponga data leakage (subgraph A ritorna field che subgraph B non dovrebbe vedere).

---

## **2.4 MECCANISMO 3: GRPC \- BINARY RPC SU HTTP/2**

### **2.4.1 Il Meccanismo Fondamentale**

gRPC è Remote Procedure Call: client invoca metodi su server remoto come se fossero locali. Differenza chiave con REST/GraphQL: RPC è **action-oriented** (chiama funzioni), non resource-oriented.

Il meccanismo si basa su due pillar tecnologici:

**Protocol Buffers (protobuf)**: serializzazione binaria. Schema definito in `.proto` file, compilato in code. Payload non è human-readable (bytes), ma estremamente compatto (3-10x più piccolo di JSON).

**HTTP/2**: trasporto. Sfrutta multiplexing (richieste parallele su singola connessione), header compression (HPACK), server push, streaming bidirezionale.

Il meccanismo tecnico:

\[Client gRPC\]  
    ↓ (Chiama method: stub.GetUser(request))  
    ↓ (Serializzazione: oggetto request → protobuf bytes)  
\[HTTP/2 Layer\]  
    ↓ (Header frame: :method POST, :path /UserService/GetUser)  
    ↓ (Data frame: protobuf payload)  
\[Server gRPC\]  
    ↓ (Deserializzazione: protobuf bytes → oggetto)  
    ↓ (Esecuzione: business logic)  
    ↓ (Serializzazione response → protobuf bytes)  
\[Client\]  
    ← (HTTP/2 Data frame)  
    ← (Deserializzazione: bytes → oggetto response)

### **2.4.2 Vulnerabilità Strutturali del Meccanismo**

#### **Payload Opacity (Conseguenza Binary Serialization)**

Protobuf è binario. WAF/IDS non possono ispezionare payload senza deserializzazione (richiede `.proto` schema).

Implicazione: injection attacks (SQL, XSS) in payload protobuf passano inosservate attraverso WAF. WAF vede solo bytes: `08 7B 12 05 ...`, non può determinare se contiene `'; DROP TABLE users--`.

Testing: crafted payload malevoli richiedono encoding protobuf corretto (richiede `.proto` file). Scanner HTTP generici inutili.

#### **Deserialization Vulnerabilities (Conseguenza Binary Parsing)**

Protobuf parser vulnerabili a buffer overflow, heap corruption se payload malformato:

* CVE-2021-22570: heap overflow protobuf C++  
* CVE-2022-1941: DoS protobuf stack overflow

Implicazione: payload crafted possono causare crash server, potenzialmente RCE.

Testing: fuzzing protobuf richiede mutation-based fuzzer che comprende format (bit flipping random su bytes non funziona \- genera sempre deserialize error).

#### **Stream Exhaustion (Conseguenza HTTP/2 Streaming)**

gRPC supporta bidirectional streaming: client e server inviano messaggi continuamente senza chiudere stream.

HTTP/2 flow control dovrebbe prevenire abusi, ma configurazione spesso permissiva. Attacker può aprire stream, inviare messaggi lentamente indefinitamente, esaurendo risorse server.

Testing: aprire N stream, inviare messaggi a rate basso ma costante, misurare memory/thread usage server.

### **2.4.3 Differenza Sostanziale: Reflection vs No-Reflection**

#### **gRPC con Server Reflection**

Server espone schema via gRPC reflection protocol (simile a GraphQL introspection). Client può query per list di service, method, message type.

Tool `grpcurl` usa reflection:

grpcurl \-plaintext localhost:9090 list  
\# Output: UserService, ProductService

Implicazione testing: discovery è trivial se reflection enabled.

#### **gRPC senza Reflection (Production Default)**

Reflection disabled per security. Schema non è discoverable.

Implicazione testing: discovery richiede ottenere `.proto` file out-of-band (Git repo, reverse engineering client binary, social engineering). Senza schema, testing è blind.

---

## **2.5 MECCANISMO 4: SOAP \- XML RPC CON WS-\* STACK**

### **2.5.1 Il Meccanismo Fondamentale**

SOAP è legacy (anni '90-2000), ma ancora diffuso in enterprise/banking/government.

Il meccanismo: RPC (come gRPC), ma XML-based (non binario). Ogni messaggio è wrappato in SOAP Envelope (struttura XML rigida):

\<soap:Envelope\>  
  \<soap:Header\> \<\!-- metadata: autenticazione, routing \--\>  
  \</soap:Header\>  
  \<soap:Body\> \<\!-- payload: chiamata method con parametri \--\>  
  \</soap:Body\>  
\</soap:Envelope\>

Il contratto è definito in WSDL (Web Services Description Language): XML che specifica operazioni disponibili, input/output type, endpoint URL.

### **2.5.2 Vulnerabilità Strutturali del Meccanismo**

#### **XML External Entity (XXE) Injection (Conseguenza XML Parsing)**

XML supporta entity: alias definiti in DTD (Document Type Definition). Entity external possono referenziare file locali o URL remote:

\<\!DOCTYPE foo \[\<\!ENTITY xxe SYSTEM "file:///etc/passwd"\>\]\>  
\<soap:Body\>\<UserId\>\&xxe;\</UserId\>\</soap:Body\>

Parser espande `&xxe;` leggendo `/etc/passwd`. Se server risponde con errore contenente valore UserId, attacker ottiene file content.

Implicazione: file disclosure, SSRF (Server-Side Request Forgery).

Testing: inviare payload XXE, verificare se parser espande entity external (best: parser dovrebbe rifiutare DTD external).

#### **XML Bomb (Billion Laughs) (Conseguenza Recursive Entity)**

Entity possono essere ricorsive:

\<\!ENTITY lol "lol"\>  
\<\!ENTITY lol2 "\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;"\>  
\<\!ENTITY lol9 "\&lol8;\&lol8;..."\> \<\!-- 10^9 expansion \--\>

Parser tenta espandere `lol9`, alloca gigabyte RAM, crash.

Testing: inviare XML bomb, verificare se server reject (timeout, error) o crash (DoS).

#### **XML Signature Wrapping (Conseguenza WS-Security)**

WS-Security permette firmare digitalmente messaggi SOAP. Attacker può manipolare XML mantenendo signature valida (sfruttando che signature referenzia element by ID, non position).

Testing: complesso. Richiede comprendere XML Signature spec, crafted payload che bypass validation.

### **2.5.3 Differenza Sostanziale: SOAP 1.1 vs 1.2**

#### **SOAP 1.1**

Header `SOAPAction` obbligatorio (indica operation chiamata). Content-Type: `text/xml`.

#### **SOAP 1.2**

`SOAPAction` deprecato (operation nel body). Content-Type: `application/soap+xml`.

Implicazione testing: fingerprinting richiede check version (namespace SOAP envelope, Content-Type header).

---

## **2.6 MECCANISMO 5: WEBSOCKET \- FULL-DUPLEX PERSISTENTE**

### **2.6.1 Il Meccanismo Fondamentale**

WebSocket rivoluziona HTTP request-response introducendo **connessione persistente bidirezionale**: client e server inviano messaggi indipendentemente, senza overhead di apertura/chiusura connessione.

Il meccanismo:

**Handshake**: HTTP Upgrade request. Client invia GET con header `Upgrade: websocket`, server risponde `101 Switching Protocols`.

**Post-Handshake**: connessione TCP rimane aperta, usata per scambiare WebSocket frame (struttura binaria con opcode, payload length, masking key, payload data).

**Masking**: frame client→server DEVONO essere maskati (XOR con random key). Previene cache poisoning attack.

### **2.6.2 Vulnerabilità Strutturali del Meccanismo**

#### **Cross-Site WebSocket Hijacking (CSWSH) (Conseguenza di No CORS Preflight)**

WebSocket handshake è HTTP, ma NON esegue CORS preflight (a differenza di fetch/XHR). Browser invia direttamente richiesta upgrade, includendo cookie.

Attacker può crafted pagina che apre WebSocket verso vittima:

// evil.com  
var ws \= new WebSocket('wss://victim.com/chat');  
ws.onmessage \= (e) \=\> sendToAttacker(e.data);

Se `victim.com` non valida `Origin` header durante handshake, connessione è accettata, messaggi leak a attacker.

Testing: deploy pagina su domain controllato, tentare aprire WebSocket verso target, verificare se connessione è permessa (Origin validation assente).

#### **Stateful Rate Limiting Bypass (Conseguenza Persistent Connection)**

1 handshake HTTP \= 1 "request" per rate limiter. Ma post-handshake, client può inviare N frame senza ulteriori HTTP request.

Implicazione: rate limiting HTTP (100 req/sec) bypassato. 100 handshake × 1000 frame/handshake \= 100.000 messaggi/sec.

Testing: stabilire connessione, inviare frame a rate elevato, verificare se rate limiting è enforced.

### **2.6.3 Differenza Sostanziale: WebSocket Subprotocol**

WebSocket supporta subprotocol negotiation via header `Sec-WebSocket-Protocol`:

Sec-WebSocket-Protocol: chat, superchat

Server seleziona subprotocol supportato. Subprotocol definisce formato payload (JSON, protobuf, custom binary).

Implicazione testing: senza conoscere subprotocol, payload è opaco. Fuzzing richiede reverse engineering formato.

---

## **2.7 MECCANISMO 6: SERVER-SENT EVENTS (SSE) \- UNIDIRECTIONAL STREAMING**

### **2.7.1 Il Meccanismo Fondamentale**

SSE fornisce streaming server→client tramite long-lived HTTP connection. A differenza di WebSocket (bidirezionale), SSE è simplex.

Il meccanismo:

Client invia GET con `Accept: text/event-stream`. Server risponde `200 OK`, `Content-Type: text/event-stream`, e mantiene connessione aperta. Poi invia eventi (text-based, newline-delimited):

data: {"message": "update"}

event: notification  
data: {"alert": "new message"}  
id: 123

Browser fornisce API `EventSource` che gestisce auto-reconnection.

### **2.7.2 Vulnerabilità Strutturali del Meccanismo**

#### **Token Expiration Mid-Stream (Conseguenza Long-Lived Connection)**

SSE connection può durare ore. Se autenticazione usa JWT con expiry (1h), token scade mid-stream.

Se server valida JWT solo durante handshake, stream continua con token scaduto (security issue). Se server chiude stream quando token scade, client riconnette ma JWT già expired (UX issue).

Testing: stabilire SSE con JWT short-lived, attendere expiry, verificare comportamento.

#### **Connection Timeout Silente (Conseguenza Load Balancer Idle Timeout)**

Load balancer assume HTTP connection brevi, configurato con idle timeout (60s). Se SSE è inattiva (no eventi), LB chiude connessione.

Workaround: server invia heartbeat (comment line `: heartbeat`) ogni \<60s.

Testing: stabilire SSE, non inviare eventi, attendere \>timeout, verificare se connection chiusa o mantenuta alive.

**SEZIONE 3: INTERAZIONI E IMPLICAZIONI PER IL TESTING**

## **3.1 IL PRINCIPIO DELL'IMPEDANCE MISMATCH**

Quando architetture e protocolli collaborano, le loro **assunzioni di design devono essere compatibili**. Il problema emerge quando un layer viola le assunzioni dell'altro.

**Esempio paradigmatico**: API Gateway assume traffico stateless HTTP request-response. WebSocket richiede connessione stateful persistente. Questa incompatibilità genera blind spot:

* Rate limiting Gateway conta HTTP handshake, ignora frame WebSocket post-handshake  
* WAF Gateway ispeziona HTTP payload, cieco su frame WebSocket  
* Logging Gateway trunca entries (1024 bytes), ma frame WebSocket può essere 32KB

Questi non sono bug configurazione. Sono **proprietà emergenti** dell'impedance mismatch tra design architetturali incompatibili.

## **3.2 PATTERN DI MISMATCH RICORRENTI**

Analizzando interazioni, emergono pattern di failure ricorrenti:

### **Pattern 1: State Mismatch**

**Architettura assume stateless**, protocollo richiede stateful.

Esempi:

* WebSocket \+ API Gateway  
* SSE \+ Load Balancer  
* gRPC bidirectional streaming \+ Service Mesh sidecar

Conseguenza: infrastructure progettata per request-response fallisce con persistent connections. Rate limiting, timeout, resource allocation inadeguati.

### **Pattern 2: Protocol Translation Loss**

**Transcoding** introduce metadata loss o semantic mismatch.

Esempi:

* gRPC-Web → gRPC (Envoy transcoding)  
* HTTP/2 → HTTP/1.1 downgrade (Istio Gateway misconfigured)

Conseguenza: log mismatch (gateway vede HTTP, backend processa gRPC), security policy gap (WAF valida HTTP, backend deserializza protobuf con diversa validation).

### **Pattern 3: Payload Opacity**

**Infrastructure non può ispezionare** payload binario o cifrato.

Esempi:

* gRPC protobuf attraverso WAF  
* WebSocket frame post-upgrade attraverso API Gateway

Conseguenza: injection attacks (XSS, SQLi) in payload passano inosservati attraverso security layer. Defense-in-depth broken.

### **Pattern 4: Semantic Routing Failure**

**Infrastructure route su metadata HTTP**, protocollo route su payload semantic.

Esempi:

* GraphQL single endpoint `/graphql` con batching  
* SOAP single endpoint con operation in XML body

Conseguenza: URL-based routing, rate limiting, authorization inefficaci. Gateway non comprende semantic applicativo.

### **Pattern 5: Resource Accounting Mismatch**

**Infrastructure misura richieste HTTP**, protocollo esegue N operazioni per richiesta.

Esempi:

* GraphQL batching (1 HTTP POST \= 1000 query)  
* gRPC streaming (1 HTTP/2 stream \= infinite messages)  
* WebSocket (1 handshake \= 1000 frame)

Conseguenza: rate limiting, billing, capacity planning basati su HTTP metrics completamente inaccurati.

## **3.3 MATRICE CRITICA: DOVE TESTARE COSA**

Questa matrice sintetizza quali combinazioni architettura-protocollo richiedono testing specifico:

| Protocollo | Con API Gateway | Con Kubernetes Ingress | Con Service Mesh | Con Serverless |
| ----- | ----- | ----- | ----- | ----- |
| **REST** | Standard (authn, authz, rate limiting) | Annotation-specific config | mTLS enforcement | IAM role privilege escalation |
| **GraphQL** | Batching rate limit bypass | Single endpoint routing | Field-level authz in mesh policy | Cold start query complexity |
| **gRPC** | Binary payload WAF bypass | Backend-protocol annotation | Memory exhaustion streaming | Reflection discovery in Lambda |
| **SOAP** | XXE through gateway | XML bomb DoS | WS-Security validation | Legacy integration testing |
| **WebSocket** | Rate limit post-handshake, WAF bypass, logging truncation | Health probe mismatch | Stateful sidecar issues | Connection tracking DynamoDB |
| **SSE** | Token expiry mid-stream | LB idle timeout | Heartbeat overhead | EventSource reconnect logic |

## **3.4 IMPLICAZIONI FINALI PER IL TOOL**

Un toolork di security assessment per API cloud-native deve:

1. **Riconoscere architettura deployata**: Fingerprinting via header HTTP, metadata, behavior pattern.

2. **Riconoscere protocollo utilizzato**: Content-Type, endpoint pattern, payload structure.

3. **Identificare combinazione architettura-protocollo**: Non testare "GraphQL" o "API Gateway" isolatamente, ma "GraphQL attraverso API Gateway".

4. **Selezionare test specifici per combinazione**: Matrice sopra guida selezione. GraphQL \+ Gateway richiede batching test, gRPC \+ Mesh richiede memory monitoring.

5. **Usare tool protocol-specific**: Scanner HTTP generici inadeguati. Serve orchestrazione tool specializzati (grpcurl, graphql-cop, wscat) basata su protocol detected.

6. **Verificare enforcement effettivo, non configuration dichiarata**: Introspection disabled ≠ schema segreto. Rate limiting configured ≠ protection. Testare comportamento runtime.

---

## **CONCLUSIONI DEL CAPITOLO**

Questo capitolo ha fornito una base teorica per comprendere il panorama moderno delle API cloud-native attraverso astrazione tecnica e analisi delle differenze sostanziali.

**Sezione 1** ha astratto quattro pattern architetturali (API Gateway, Kubernetes Ingress/Gateway, Service Mesh, Serverless), identificando il problema universale che risolvono, il meccanismo tecnico comune, e le differenze implementative che impattano testing.

**Sezione 2** ha analizzato sei meccanismi protocollo (REST, GraphQL, gRPC, SOAP, WebSocket, SSE), focalizzandosi non sulla sintassi ma sui principi tecnici che determinano vulnerabilità strutturali.

**Sezione 3** ha sintetizzato come pattern architetturali e meccanismi protocollo interagiscono, identificando cinque pattern di impedance mismatch ricorrenti e una matrice di testing priorities.

L'approccio seguito \- astrarre invece di catalogare, evidenziare differenze sostanziali invece di elencare feature, orientare tutto verso implicazioni testing \- fornisce la base necessaria per progettare un tool che opera efficacemente su architetture e protocolli eterogenei. I capitoli successivi costruiranno su questa fondazione teorica per definire metodologie di testing concrete e architettura del tool Python.

