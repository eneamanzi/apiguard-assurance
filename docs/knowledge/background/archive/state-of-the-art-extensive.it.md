# Stato dell’Arte: architetture \+ tipi API

- [INTRODUZIONE](#introduzione)
- [1. API GATEWAY TRADIZIONALI](#1-api-gateway-tradizionali)
  - [1.1 Il Problema Architetturale](#11-il-problema-architetturale)
  - [1.2 Tecnologie Leader](#12-tecnologie-leader)
    - [1.2.1 Kong Gateway](#121-kong-gateway)
    - [1.2.2 AWS API Gateway](#122-aws-api-gateway)
    - [1.2.3 Azure API Management](#123-azure-api-management)
  - [1.3 Rischi di Sicurezza Specifici degli API Gateway](#13-rischi-di-sicurezza-specifici-degli-api-gateway)
    - [1.3.1 Gateway come Single Point of Failure (e Attack)](#131-gateway-come-single-point-of-failure-e-attack)
    - [1.3.2 TLS Termination e Trust Boundary](#132-tls-termination-e-trust-boundary)
    - [1.3.3 Configuration Drift e Shadow Endpoints](#133-configuration-drift-e-shadow-endpoints)
- [2. KUBERNETES: ORCHESTRAZIONE E NETWORKING](#2-kubernetes-orchestrazione-e-networking)
  - [2.1 Il Problema Architetturale](#21-il-problema-architetturale)
  - [2.2 Architettura del Control Plane](#22-architettura-del-control-plane)
    - [2.2.1 kube-apiserver: Il Gateway delle API Kubernetes](#221-kube-apiserver-il-gateway-delle-api-kubernetes)
    - [2.2.2 kube-scheduler: Assegnazione Workload ai Nodi](#222-kube-scheduler-assegnazione-workload-ai-nodi)
    - [2.2.3 kubelet: L'Agente sui Nodi Worker](#223-kubelet-lagente-sui-nodi-worker)
    - [2.2.4 kube-controller-manager: Loop di Riconciliazione](#224-kube-controller-manager-loop-di-riconciliazione)
  - [2.3 Networking in Kubernetes: CNI e Overlay Networks](#23-networking-in-kubernetes-cni-e-overlay-networks)
    - [2.3.1 CNI e Modelli di Networking](#231-cni-e-modelli-di-networking)
    - [2.3.2 kube-proxy e Service Networking](#232-kube-proxy-e-service-networking)
  - [2.4 Multi-Tenancy e Isolation](#24-multi-tenancy-e-isolation)
    - [2.4.1 Namespace come Primo Livello di Isolation](#241-namespace-come-primo-livello-di-isolation)
    - [2.4.2 Network Policies per Isolation Layer 3/4](#242-network-policies-per-isolation-layer-34)
    - [2.4.3 Pod Security Standards](#243-pod-security-standards)
  - [2.5 Kubernetes Ingress e Gateway API](#25-kubernetes-ingress-e-gateway-api)
    - [2.5.1 Ingress: Il Modello Legacy](#251-ingress-il-modello-legacy)
    - [2.5.2 Gateway API: Il Futuro dello Ingress](#252-gateway-api-il-futuro-dello-ingress)
  - [2.6 Rischi Specifici di Kubernetes](#26-rischi-specifici-di-kubernetes)
    - [2.6.1 API Interne Esposte](#261-api-interne-esposte)
    - [2.6.2 Privilege Escalation via RBAC Misconfiguration](#262-privilege-escalation-via-rbac-misconfiguration)
    - [2.6.3 Container Escape e Host Access](#263-container-escape-e-host-access)
- [3. SERVICE MESH](#3-service-mesh)
  - [3.1 Il Problema Architetturale](#31-il-problema-architetturale)
  - [3.2 Istio: Architettura Sidecar e Ambient](#32-istio-architettura-sidecar-e-ambient)
    - [3.2.1 Architettura Sidecar Tradizionale](#321-architettura-sidecar-tradizionale)
    - [3.2.2 Istio Ambient: L'Evoluzione Sidecar-less](#322-istio-ambient-levoluzione-sidecar-less)
  - [3.3 Linkerd: Minimalismo e Performance](#33-linkerd-minimalismo-e-performance)
  - [3.4 Rischi Specifici dei Service Mesh](#34-rischi-specifici-dei-service-mesh)
    - [3.4.1 Complessità e Misconfiguration](#341-complessità-e-misconfiguration)
    - [3.4.2 Memory Exhaustion su gRPC Streaming](#342-memory-exhaustion-su-grpc-streaming)
- [4. ARCHITETTURE SERVERLESS](#4-architetture-serverless)
  - [4.1 Il Problema Architetturale](#41-il-problema-architetturale)
  - [4.2 AWS Lambda: Execution Model](#42-aws-lambda-execution-model)
    - [4.2.1 Cold Start vs Warm Execution](#421-cold-start-vs-warm-execution)
    - [4.2.2 VPC Integration e Network Latency](#422-vpc-integration-e-network-latency)
    - [4.2.3 IAM Execution Role e Security](#423-iam-execution-role-e-security)
  - [4.3 Knative: Serverless Open Source su Kubernetes](#43-knative-serverless-open-source-su-kubernetes)
    - [4.3.1 Architettura Knative Serving](#431-architettura-knative-serving)
    - [4.3.2 Revision-Based Deployment](#432-revision-based-deployment)
  - [4.4 Rischi Specifici di Serverless](#44-rischi-specifici-di-serverless)
    - [4.4.1 Event Injection e Trigger Abuse](#441-event-injection-e-trigger-abuse)
    - [4.4.2 Timeout e Resource Exhaustion](#442-timeout-e-resource-exhaustion)
    - [4.4.3 Secret Management](#443-secret-management)
- [CONCLUSIONI FASE 1.A](#conclusioni-fase-1a)
- [BIBLIOGRAFIA TECNICA](#bibliografia-tecnica)
  - [Documentazione CNCF](#documentazione-cncf)
  - [AWS Documentation](#aws-documentation)
  - [Azure Documentation](#azure-documentation)
  - [Google Cloud Documentation](#google-cloud-documentation)
  - [Kong Documentation](#kong-documentation)
  - [Service Mesh Resources](#service-mesh-resources)
  - [Serverless Resources](#serverless-resources)
  - [Kubernetes Networking](#kubernetes-networking)
  - [Technical Articles \& Blogs](#technical-articles--blogs)
- [INTRODUZIONE](#introduzione-1)
- [1. REST (REPRESENTATIONAL STATE TRANSFER)](#1-rest-representational-state-transfer)
  - [1.1 Meccanica del Protocollo](#11-meccanica-del-protocollo)
  - [1.2 Vulnerabilità Strutturali](#12-vulnerabilità-strutturali)
    - [1.2.1 Over-fetching e Excessive Data Exposure](#121-over-fetching-e-excessive-data-exposure)
    - [1.2.2 Broken Object Level Authorization (BOLA)](#122-broken-object-level-authorization-bola)
    - [1.2.3 Mass Assignment e Parameter Pollution](#123-mass-assignment-e-parameter-pollution)
    - [1.2.4 HTTP Verb Tampering](#124-http-verb-tampering)
    - [1.2.5 Caching Issues e Information Leakage](#125-caching-issues-e-information-leakage)
  - [1.3 Sfide di Testing Specifiche](#13-sfide-di-testing-specifiche)
    - [1.3.1 Endpoint Proliferation e Shadow API](#131-endpoint-proliferation-e-shadow-api)
    - [1.3.2 Content Negotiation e Testing Combinatoriale](#132-content-negotiation-e-testing-combinatoriale)
    - [1.3.3 HTTP/2 e Multiplexing Invisibile](#133-http2-e-multiplexing-invisibile)
- [2. GRAPHQL](#2-graphql)
  - [2.1 Meccanica del Protocollo](#21-meccanica-del-protocollo)
  - [2.2 Vulnerabilità Strutturali](#22-vulnerabilità-strutturali)
    - [2.2.1 Query Complexity Attacks](#221-query-complexity-attacks)
    - [2.2.2 Introspection Abuse e Schema Leakage](#222-introspection-abuse-e-schema-leakage)
    - [2.2.3 Batching e Aliasing per Rate Limiting Bypass](#223-batching-e-aliasing-per-rate-limiting-bypass)
    - [2.2.4 Authorization Granularity Mismatch](#224-authorization-granularity-mismatch)
  - [2.3 Sfide di Testing Specifiche](#23-sfide-di-testing-specifiche)
    - [2.3.1 Schema Discovery e Coverage](#231-schema-discovery-e-coverage)
    - [2.3.2 Mutation Testing e Side Effects](#232-mutation-testing-e-side-effects)
    - [2.3.3 Subscription e WebSocket](#233-subscription-e-websocket)
- [3. GRPC](#3-grpc)
  - [3.1 Meccanica del Protocollo](#31-meccanica-del-protocollo)
  - [3.2 Vulnerabilità Strutturali](#32-vulnerabilità-strutturali)
    - [3.2.1 Deserialization Attacks](#321-deserialization-attacks)
    - [3.2.2 Stream Exhaustion e Resource Leaks](#322-stream-exhaustion-e-resource-leaks)
    - [3.2.3 Metadata Injection](#323-metadata-injection)
    - [3.2.4 Authentication Bypass](#324-authentication-bypass)
  - [3.3 Sfide di Testing Specifiche](#33-sfide-di-testing-specifiche)
    - [3.3.1 Binary Protocol Opacity](#331-binary-protocol-opacity)
    - [3.3.2 Reflection API Discovery](#332-reflection-api-discovery)
    - [3.3.3 TLS Enforcement e MITM](#333-tls-enforcement-e-mitm)
- [4. SOAP (SIMPLE OBJECT ACCESS PROTOCOL)](#4-soap-simple-object-access-protocol)
  - [4.1 Meccanica del Protocollo](#41-meccanica-del-protocollo)
  - [4.2 Vulnerabilità Strutturali](#42-vulnerabilità-strutturali)
    - [4.2.1 XML External Entity (XXE) Injection](#421-xml-external-entity-xxe-injection)
    - [4.2.2 XML Signature Wrapping (XSW)](#422-xml-signature-wrapping-xsw)
    - [4.2.3 XML Bomb (Billion Laughs Attack)](#423-xml-bomb-billion-laughs-attack)
    - [4.2.4 SQL Injection via SOAP](#424-sql-injection-via-soap)
  - [4.3 Sfide di Testing Specifiche](#43-sfide-di-testing-specifiche)
    - [4.3.1 WSDL Discovery e Parsing](#431-wsdl-discovery-e-parsing)
    - [4.3.2 WS-Security Complexity](#432-ws-security-complexity)
    - [4.3.3 XML Parsing Attacks](#433-xml-parsing-attacks)
- [5. WEBSOCKET](#5-websocket)
  - [5.1 Meccanica del Protocollo](#51-meccanica-del-protocollo)
  - [5.2 Vulnerabilità Strutturali](#52-vulnerabilità-strutturali)
    - [5.2.1 Cross-Site WebSocket Hijacking (CSWSH)](#521-cross-site-websocket-hijacking-cswsh)
    - [5.2.2 Injection Attacks via Frame Payload](#522-injection-attacks-via-frame-payload)
    - [5.2.3 Denial of Service Patterns](#523-denial-of-service-patterns)
    - [5.2.4 Lack of Rate Limiting](#524-lack-of-rate-limiting)
  - [5.3 Sfide di Testing Specifiche](#53-sfide-di-testing-specifiche)
    - [5.3.1 Stateful Connection Management](#531-stateful-connection-management)
    - [5.3.2 Origin Validation Testing](#532-origin-validation-testing)
    - [5.3.3 Protocol Fuzzing](#533-protocol-fuzzing)
- [6. SERVER-SENT EVENTS (SSE)](#6-server-sent-events-sse)
  - [6.1 Meccanica del Protocollo](#61-meccanica-del-protocollo)
  - [6.2 Vulnerabilità Strutturali](#62-vulnerabilità-strutturali)
    - [6.2.1 Token Expiration Durante Stream](#621-token-expiration-durante-stream)
    - [6.2.2 CORS Misconfiguration](#622-cors-misconfiguration)
    - [6.2.3 Resource Exhaustion](#623-resource-exhaustion)
    - [6.2.4 Lack of HTTPS](#624-lack-of-https)
  - [6.3 Sfide di Testing Specifiche](#63-sfide-di-testing-specifiche)
    - [6.3.1 Long-Duration Connection](#631-long-duration-connection)
    - [6.3.2 Heartbeat Detection](#632-heartbeat-detection)
    - [6.3.3 Reconnection e Last-Event-ID](#633-reconnection-e-last-event-id)
- [CONCLUSIONI FASE 1.B](#conclusioni-fase-1b)
- [BIBLIOGRAFIA TECNICA](#bibliografia-tecnica-1)
  - [**REST**](#rest)
  - [**GraphQL**](#graphql)
  - [**gRPC**](#grpc)
  - [**SOAP**](#soap)
  - [**WebSocket**](#websocket)
  - [**Server-Sent Events (SSE)**](#server-sent-events-sse)
  - [**General Resources**](#general-resources)
- [**INTRODUZIONE**](#introduzione-2)
- [**INTRODUZIONE ALLA FISIOLOGIA**](#introduzione-alla-fisiologia)
- [**1. GRPC + KUBERNETES SERVICE MESH**](#1-grpc--kubernetes-service-mesh)
  - [**1.1 Il Pattern Standard**](#11-il-pattern-standard)
  - [**1.2 Meccanismo Tecnico di Integrazione**](#12-meccanismo-tecnico-di-integrazione)
  - [**1.3 Load Balancing Layer 7**](#13-load-balancing-layer-7)
  - [**1.4 Configurazione Best Practice**](#14-configurazione-best-practice)
- [**2. GRPC + KUBERNETES INGRESS (NORTH-SOUTH)**](#2-grpc--kubernetes-ingress-north-south)
  - [**2.1 Il Pattern Standard**](#21-il-pattern-standard)
  - [**2.2 Configurazione Nginx Ingress Controller**](#22-configurazione-nginx-ingress-controller)
  - [**2.3 AWS Application Load Balancer (ALB)**](#23-aws-application-load-balancer-alb)
- [**3. GRAPHQL + APOLLO FEDERATION GATEWAY**](#3-graphql--apollo-federation-gateway)
  - [**3.1 Il Pattern Standard**](#31-il-pattern-standard)
  - [**3.2 Meccanismo di Federation**](#32-meccanismo-di-federation)
  - [**3.3 Best Practice Architetturali**](#33-best-practice-architetturali)
- [**4. WEBSOCKET + AWS API GATEWAY SERVERLESS**](#4-websocket--aws-api-gateway-serverless)
  - [**4.1 Il Pattern Standard**](#41-il-pattern-standard)
  - [**4.2 Connection Management**](#42-connection-management)
  - [**4.3 Server-to-Client Push**](#43-server-to-client-push)
  - [**4.4 Validation e Security**](#44-validation-e-security)
- [**5. REST + API GATEWAY CLOUD (PATTERN UNIVERSALE)**](#5-rest--api-gateway-cloud-pattern-universale)
  - [**5.1 Il Pattern Standard**](#51-il-pattern-standard)
  - [**5.2 Autenticazione Multi-Layer**](#52-autenticazione-multi-layer)
  - [**5.3 Rate Limiting Patterns**](#53-rate-limiting-patterns)
- [**6. SERVERLESS API (LAMBDA + API GATEWAY)**](#6-serverless-api-lambda--api-gateway)
  - [**6.1 Il Pattern Standard**](#61-il-pattern-standard)
  - [**6.2 Cold Start Mitigation**](#62-cold-start-mitigation)
  - [**6.3 VPC Integration**](#63-vpc-integration)
- [**SINTESI PARTE 1: PATTERN CONSOLIDATI**](#sintesi-parte-1-pattern-consolidati)
- [**INTRODUZIONE ALLA PATOLOGIA**](#introduzione-alla-patologia)
- [**1. GRPC + SERVICE MESH: MEMORY EXHAUSTION SU STREAMING**](#1-grpc--service-mesh-memory-exhaustion-su-streaming)
  - [**1.1 L'Assunzione Violata**](#11-lassunzione-violata)
  - [**1.2 Il Blind Spot Tecnico**](#12-il-blind-spot-tecnico)
  - [**1.3 Mitigazioni Documentate**](#13-mitigazioni-documentate)
- [**2. GRPC + ISTIO GATEWAY: PROTOCOL DOWNGRADE SILENZIOSO**](#2-grpc--istio-gateway-protocol-downgrade-silenzioso)
  - [**2.1 L'Assunzione Violata**](#21-lassunzione-violata)
  - [**2.2 Il Blind Spot Operativo**](#22-il-blind-spot-operativo)
  - [**2.3 Implicazioni di Sicurezza**](#23-implicazioni-di-sicurezza)
- [**3. GRAPHQL + API GATEWAY: BATCHING BYPASS RATE LIMITING**](#3-graphql--api-gateway-batching-bypass-rate-limiting)
  - [**3.1 L'Assunzione Violata**](#31-lassunzione-violata)
  - [**3.2 Il Blind Spot Architetturale**](#32-il-blind-spot-architetturale)
  - [**3.3 Calcolo del Bypass**](#33-calcolo-del-bypass)
  - [**3.4 Mitigazione Richiesta**](#34-mitigazione-richiesta)
- [**4. GRAPHQL INTROSPECTION: SCHEMA LEAKAGE POST-GATEWAY**](#4-graphql-introspection-schema-leakage-post-gateway)
  - [**4.1 L'Assunzione Violata**](#41-lassunzione-violata)
  - [**4.2 Il Meccanismo di Bypass**](#42-il-meccanismo-di-bypass)
  - [**4.3 Documentazione Esplicita del Problema**](#43-documentazione-esplicita-del-problema)
- [**5. WEBSOCKET + API GATEWAY: RATE LIMITING POST-HANDSHAKE**](#5-websocket--api-gateway-rate-limiting-post-handshake)
  - [**5.1 L'Assunzione Violata**](#51-lassunzione-violata)
  - [**5.2 Il Blind Spot Strutturale**](#52-il-blind-spot-strutturale)
  - [**5.3 Implicazione per Testing**](#53-implicazione-per-testing)
  - [**5.4 Mitigazione Richiesta**](#54-mitigazione-richiesta)
- [**6. WEBSOCKET + API GATEWAY: WAF BYPASS STRUTTURALE**](#6-websocket--api-gateway-waf-bypass-strutturale)
  - [**6.1 L'Assunzione Violata**](#61-lassunzione-violata)
  - [**6.2 Documentazione Esplicita del Blind Spot**](#62-documentazione-esplicita-del-blind-spot)
  - [**6.3 Scenario di Attacco**](#63-scenario-di-attacco)
  - [**6.4 Implicazione Architetturale**](#64-implicazione-architetturale)
- [**7. WEBSOCKET + AWS API GATEWAY: LOGGING TRUNCATION**](#7-websocket--aws-api-gateway-logging-truncation)
  - [**7.1 L'Assunzione Violata**](#71-lassunzione-violata)
  - [**7.2 Il Blind Spot Forensico**](#72-il-blind-spot-forensico)
  - [**7.3 Implicazione per Incident Response**](#73-implicazione-per-incident-response)
- [**8. WEBSOCKET + AWS API GATEWAY: PRIVATE NETWORK IMPOSSIBILE**](#8-websocket--aws-api-gateway-private-network-impossibile)
  - [**8.1 L'Assunzione Violata**](#81-lassunzione-violata)
  - [**8.2 Documentazione Esplicita della Limitazione**](#82-documentazione-esplicita-della-limitazione)
  - [**8.3 Implicazione Architetturale**](#83-implicazione-architetturale)
  - [**8.4 Workaround Documentato**](#84-workaround-documentato)
- [**9. GRPC-WEB TRANSCODING: METADATA LOSS**](#9-grpc-web-transcoding-metadata-loss)
  - [**9.1 L'Assunzione Violata**](#91-lassunzione-violata)
  - [**9.2 Il Blind Spot Operativo**](#92-il-blind-spot-operativo)
  - [**9.3 Implicazione di Sicurezza**](#93-implicazione-di-sicurezza)
- [**10. SSE + LOAD BALANCER: CONNECTION TIMEOUT SILENTE**](#10-sse--load-balancer-connection-timeout-silente)
  - [**10.1 L'Assunzione Violata**](#101-lassunzione-violata)
  - [**10.2 Il Blind Spot Operativo**](#102-il-blind-spot-operativo)
  - [**10.3 Workaround: Heartbeat Events**](#103-workaround-heartbeat-events)
- [**SINTESI PARTE 2: TASSONOMIA DEI BLIND SPOTS**](#sintesi-parte-2-tassonomia-dei-blind-spots)
  - [**Pattern Ricorrenti di Failure**](#pattern-ricorrenti-di-failure)
  - [**Matrice Blind Spot per Architettura-Protocollo**](#matrice-blind-spot-per-architettura-protocollo)
- [**IMPLICAZIONI PER IL FRAMEWORK DI TESTING**](#implicazioni-per-il-framework-di-testing)
  - [**Principi di Design Emergenti**](#principi-di-design-emergenti)
  - [**Tool Gaps Identificati**](#tool-gaps-identificati)
- [**CONCLUSIONI FASE 1.C**](#conclusioni-fase-1c)
- [**BIBLIOGRAFIA TECNICA**](#bibliografia-tecnica-2)
  - [**gRPC + Kubernetes/Service Mesh**](#grpc--kubernetesservice-mesh)
  - [**GraphQL + API Gateway**](#graphql--api-gateway)
  - [**WebSocket + API Gateway**](#websocket--api-gateway)
  - [**Server-Sent Events**](#server-sent-events)
  - [**Serverless \& General**](#serverless--general)
- [BIBLIOGRAFIA TECNICA](#bibliografia-tecnica-3)
  - [gRPC + Kubernetes](#grpc--kubernetes)
  - [gRPC + Service Mesh](#grpc--service-mesh)
  - [GraphQL + API Gateway](#graphql--api-gateway-1)
  - [WebSocket + API Gateway](#websocket--api-gateway-1)
  - [Server-Sent Events](#server-sent-events-1)
  - [Serverless Architectures](#serverless-architectures)
  - [General Resources](#general-resources-1)

# FASE 1.A: ARCHITETTURE PER L'ESPOSIZIONE DI API IN AMBIENTE CLOUD

**Data:** 31 Gennaio 2026  
**Versione:** 3.0 (Versione Definitiva \- Integrazione Gap Tecnici)

---

## INTRODUZIONE

Le architetture moderne per l'esposizione di interfacce applicative (API) in ambiente cloud hanno subito un'evoluzione radicale negli ultimi anni. Dalla centralizzazione offerta dai gateway tradizionali si è passati a modelli distribuiti basati su orchestrazione di container, service mesh e paradigmi serverless. Questa transizione non rappresenta una semplice evoluzione tecnologica, ma un cambio di paradigma architetturale che ridefinisce completamente le modalità con cui i servizi comunicano, vengono scoperti e protetti.

Comprendere queste architetture è fondamentale per qualsiasi framework di security assessment che aspiri a operare efficacemente in ambienti cloud-native. Le interfacce API non esistono in isolamento: sono incapsulate, protette e mediate da layer infrastrutturali complessi che ne influenzano profondamente la superficie di attacco. Un approccio di testing che ignori il contesto architetturale è destinato a produrre risultati parziali o fuorvianti.

Questa sezione analizza le principali categorie architetturali che dominano il panorama cloud-native nel 2024-2026, con particolare attenzione ai meccanismi interni che determinano le modalità di esposizione delle API e le implicazioni per la security assurance. L'analisi segue una struttura ricorrente: per ogni architettura, definiamo prima il problema che risolve (il "perché" della sua esistenza), poi analizziamo le tecnologie concrete che la implementano, e infine identifichiamo i rischi specifici che introduce.

---

## 1\. API GATEWAY TRADIZIONALI

### 1.1 Il Problema Architetturale

Quando un'organizzazione espone decine o centinaia di microservizi a client esterni, emerge immediatamente un problema di complessità: ogni servizio ha il proprio endpoint, le proprie politiche di autenticazione, i propri limiti di utilizzo. Dal punto di vista del client, questa frammentazione si traduce in una proliferazione ingestibile di URL, credenziali e contratti API. Dal punto di vista della sicurezza, ogni servizio diventa un potenziale punto di ingresso che deve essere individualmente monitorato e protetto.

L'API Gateway nasce come risposta a questa complessità. L'idea fondamentale è semplice: introdurre un unico punto di ingresso (single entry point) che funga da mediatore tra il mondo esterno e l'insieme dei servizi interni. Il gateway assume la responsabilità di funzioni trasversali come autenticazione, rate limiting, logging e routing, liberando i singoli servizi da questi oneri e centralizzando le policy di sicurezza.

Tecnicamente, un API Gateway è un reverse proxy specializzato che opera al Layer 7 del modello OSI, il che significa che può ispezionare e manipolare il contenuto delle richieste HTTP/HTTPS. Questa caratteristica lo distingue da un semplice load balancer Layer 4, che si limita a distribuire il traffico TCP senza comprendere il protocollo applicativo.

Il flusso tipico di una richiesta attraverso un API Gateway segue questa sequenza:

\[Client Esterno\]

    ↓ (HTTPS)

\[API Gateway \- Ingress Layer\]

    ↓ (Autenticazione: JWT/API Key validation)

    ↓ (Rate Limiting: Token Bucket Algorithm)

    ↓ (Routing: URL path → Backend Service)

    ↓ (Internal Network \- spesso HTTP plaintext)

\[Microservizio Backend A/B/C\]

Questo pattern architetturale introduce un'importante implicazione di sicurezza: il traffico esterno (cifrato via TLS) viene terminato al gateway, che poi comunica con i backend su rete interna, spesso in plaintext. La sicurezza si basa quindi sull'assunzione che la rete interna sia trusted e isolata. Vedremo più avanti come questa assunzione possa essere violata in ambienti cloud-native.

---

### 1.2 Tecnologie Leader

#### 1.2.1 Kong Gateway

Kong rappresenta uno degli API Gateway open source più diffusi in ambienti cloud-native, particolarmente adottato in deployment Kubernetes. La sua architettura si basa su una separazione netta tra Data Plane e Control Plane.

Il **Data Plane** è costruito su Nginx esteso con OpenResty, un runtime Lua integrato che consente di eseguire logica personalizzata direttamente all'interno del proxy HTTP. Ogni richiesta attraversa una pipeline di plugin Lua che possono modificarla, bloccarla o arricchirla. Questa architettura plugin-based consente estensibilità senza modificare il core del gateway.

Il **Control Plane** gestisce la configurazione centralizzata e può operare in tre modalità distinte. In modalità DB-mode, la configurazione è persistita su PostgreSQL o Cassandra, consentendo sincronizzazione tra istanze multiple del gateway. In modalità DB-less, la configurazione viene caricata da file YAML in memoria, ideale per pipeline CI/CD dove l'infrastruttura è immutabile. Infine, la modalità Hybrid (introdotta in Kong 1.1+) separa fisicamente il Control Plane (che gestisce la configurazione) dal Data Plane (che processa il traffico), permettendo deployment in cui il Control Plane risiede in un datacenter centrale mentre i Data Plane sono distribuiti geograficamente.

\[Fonte: Kong Gateway Documentation \- https://developer.konghq.com/gateway/\]

Kong supporta nativamente protocolli moderni come HTTP/HTTPS, gRPC, WebSocket e TCP/UDP, rendendolo versatile per architetture eterogenee. La sua integrazione con Kubernetes attraverso l'implementazione della Kubernetes Gateway API lo rende particolarmente rilevante per il nostro framework di testing, in quanto le API esposte tramite Kong sono discoverable tramite risorse Kubernetes standard.

Una caratteristica distintiva di Kong è il suo ecosistema di plugin, che include funzionalità di sicurezza avanzate come OAuth2, JWT validation, rate limiting granulare, e integrazione LDAP/OpenID Connect. Tuttavia, questa ricchezza di funzionalità introduce un rischio: la misconfiguration di un singolo plugin può esporre vulnerabilità non immediatamente evidenti.

\[Fonte: GitHub \- Kong Repository \- https://github.com/Kong/kong\]

#### 1.2.2 AWS API Gateway

AWS API Gateway rappresenta l'approccio fully-managed di Amazon Web Services all'esposizione di API. A differenza di Kong, che richiede deployment e gestione dell'infrastruttura, AWS API Gateway è un servizio completamente gestito dove lo sviluppatore definisce unicamente le API e le loro integrazioni, delegando ad AWS scaling, patching e alta disponibilità.

L'architettura di AWS API Gateway distingue tra tre tipologie di API con caratteristiche tecniche diverse. Le **REST API** offrono il set completo di funzionalità, inclusi mapping template per trasformazione di request/response, caching, e integrazione con AWS WAF. Le **HTTP API** sono una versione semplificata e più economica, ottimizzata per performance (latency ridotta del 60% rispetto alle REST API) ma con funzionalità limitate. Le **WebSocket API** gestiscono connessioni bidirezionali persistenti, con un meccanismo completamente diverso che analizzeremo nella sezione dedicata alle interazioni protocollo-architettura.

\[Fonte: AWS Documentation \- Amazon API Gateway \- https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html\]

Dal punto di vista della sicurezza, AWS API Gateway implementa un modello di autenticazione multi-layer. L'integrazione con AWS IAM consente controllo granulare basato su identità AWS (utenti, ruoli), mentre Amazon Cognito User Pools gestisce l'autenticazione di utenti applicativi. Per scenari più complessi, i Lambda Authorizer permettono logica di autorizzazione personalizzata, tipicamente usata per validare JWT emessi da provider esterni.

Un aspetto critico per il testing è il supporto di AWS API Gateway per deployment multi-region. Un'API può essere deployata in più regioni AWS e orchestrata attraverso Amazon CloudFront (la CDN di AWS), che distribuisce il traffico geograficamente. Questo introduce complessità nella discovery: una singola API logica può avere molteplici endpoint fisici distribuiti globalmente, ciascuno con potenziali configurazioni differenti.

\[Fonte: AWS Reference Architecture \- Multi-region API Gateway with CloudFront \- https://docs.aws.amazon.com/architecture-diagrams/latest/multi-region-api-gateway-with-cloudfront/multi-region-api-gateway-with-cloudfront.html\]

#### 1.2.3 Azure API Management

Azure API Management adotta un approccio ibrido tra Kong e AWS API Gateway. Il servizio è managed (Microsoft gestisce l'infrastruttura), ma offre anche la possibilità di deployment self-hosted tramite container Docker/Kubernetes, permettendo scenari hybrid-cloud.

L'architettura di Azure APIM si articola su tre componenti principali. Il **Gateway** (managed o self-hosted) processa le richieste applicando policy definite. Il **Management Plane** espone API per configurazione e monitoraggio. Il **Developer Portal** fornisce un'interfaccia web per documentazione API e onboarding sviluppatori.

Una caratteristica distintiva di Azure APIM è il sistema di policy basato su XML, che consente trasformazioni complesse di richieste e risposte. Le policy sono organizzate in quattro sezioni: inbound (pre-processing della richiesta), backend (selezione e chiamata del servizio backend), outbound (post-processing della risposta), on-error (gestione errori). Questa granularità permette scenari sofisticati, ma introduce anche complessità di configurazione e potenziali errori.

\[Fonte: Azure API Management \- API Gateway Overview \- https://learn.microsoft.com/en-us/azure/api-management/api-management-gateways-overview\]

Il deployment self-hosted di Azure APIM è particolarmente rilevante per ambienti multi-cloud o on-premises. Il gateway self-hosted si presenta come un container Docker che comunica con il Management Plane cloud-based per ricevere aggiornamenti di configurazione. Questo modello ibrido introduce una superficie di attacco particolare: il canale di comunicazione tra gateway self-hosted e cloud deve essere protetto, e eventuali interruzioni di connettività possono causare drift tra configurazione attesa e reale.

---

### 1.3 Rischi di Sicurezza Specifici degli API Gateway

Gli API Gateway, pur centralizzando la sicurezza, introducono paradossalmente nuove vulnerabilità specifiche della loro natura di single point of entry.

#### 1.3.1 Gateway come Single Point of Failure (e Attack)

La centralizzazione del traffico attraverso un gateway crea un single point of failure: se il gateway è compromesso o subisce un Denial of Service, tutte le API dietro di esso diventano inaccessibili. Questo rende il gateway un target privilegiato per attaccanti. A differenza di un attacco diretto a un singolo microservizio (che impatta solo quel servizio), un attacco al gateway ha effetto moltiplicativo.

Inoltre, la complessità configurativa dei gateway moderni (Kong con decine di plugin, Azure APIM con policy XML complesse) introduce un rischio di misconfiguration. Configurazioni errate di rate limiting, autenticazione o CORS possono esporre vulnerabilità non evidenti nei singoli servizi ma critiche a livello di gateway.

#### 1.3.2 TLS Termination e Trust Boundary

I gateway terminano tipicamente TLS e comunicano con i backend su rete interna in plaintext o con TLS self-signed. Questo spostamento del trust boundary introduce un rischio: se un attaccante ottiene accesso alla rete interna (lateral movement da un container compromesso), il traffico tra gateway e backend è leggibile e modificabile.

In ambienti cloud-native moderni, dove i pod Kubernetes possono essere schedulati su nodi arbitrari e la rete è virtualmente flat (con isolation logica tramite Network Policies), l'assunzione di "rete interna sicura" è debole. Un container compromesso può potenzialmente sniffare traffico diretto ad altri servizi sulla stessa rete virtuale.

#### 1.3.3 Configuration Drift e Shadow Endpoints

In deployment distribuiti con istanze multiple del gateway (per alta disponibilità), può verificarsi configuration drift: istanze diverse del gateway con configurazioni disallineate. Questo è particolarmente critico in Kong DB-less mode, dove ogni istanza carica la configurazione da file locale: un deployment errato può lasciare un'istanza con configurazione obsoleta, esponendo endpoint che dovrebbero essere deprecati (shadow endpoints).

---

## 2\. KUBERNETES: ORCHESTRAZIONE E NETWORKING

### 2.1 Il Problema Architetturale

Quando le organizzazioni iniziano a operare microservizi a scala (centinaia o migliaia di container), emergono sfide che l'approccio tradizionale (VM statiche, deployment manuale) non può risolvere. Come si distribuiscono container su un cluster di macchine fisiche? Come si garantisce che un servizio rimanga disponibile se un container crasha? Come si gestisce il networking quando container possono essere distrutti e ricreati dinamicamente su nodi differenti?

Kubernetes nasce come risposta a queste sfide, fornendo un piano di controllo centralizzato (Control Plane) che orchestra l'esecuzione di container su un piano dati distribuito (Data Plane). Il modello mentale fondamentale di Kubernetes è quello di una macchina a stati desiderati: l'utente dichiara lo stato desiderato (es. "voglio 3 repliche del servizio X") e Kubernetes si occupa continuamente di riconciliare lo stato reale con quello desiderato.

Questa astrazione risolve brillantemente il problema dell'orchestrazione, ma introduce complessità architetturale significativa. Kubernetes non è un singolo binario, ma un ecosistema di componenti distribuiti che comunicano attraverso API interne. Comprendere questa architettura interna è fondamentale per identificare superfici di attacco.

---

### 2.2 Architettura del Control Plane

Il Control Plane di Kubernetes è il "cervello" del cluster, responsabile di tutte le decisioni di scheduling, configurazione e monitoraggio. È composto da quattro componenti principali che operano tipicamente su nodi dedicati (master nodes).

#### 2.2.1 kube-apiserver: Il Gateway delle API Kubernetes

Il **kube-apiserver** è l'unico componente del Control Plane con cui tutti gli altri componenti e utenti interagiscono direttamente. Funge da gateway RESTful che espone le API di Kubernetes (tipicamente su porta 6443 con TLS). Ogni operazione sul cluster (creazione di un Pod, modifica di una configurazione, query dello stato) transita attraverso l'apiserver.

Il flusso di una richiesta all'apiserver segue una pipeline strutturata:

\[Client \- kubectl/controller\]

    ↓ (HTTPS Request)

\[kube-apiserver\]

    ↓ (1. Authentication: X.509 client cert / JWT token)

    ↓ (2. Authorization: RBAC \- Role-Based Access Control)

    ↓ (3. Admission Controllers: validazioni custom, mutation)

    ↓ (4. Schema Validation: verifica conformità a OpenAPI spec)

    ↓ (5. Persistenza in etcd)

\[etcd \- Datastore Distribuito\]

**Authentication** determina l'identità del chiamante (chi sei?). Kubernetes supporta multiple strategie: certificati X.509 client, bearer tokens (JWT), service account tokens, provider esterni (OIDC).

**Authorization** determina se l'identità ha permessi per l'operazione richiesta (cosa puoi fare?). Il meccanismo standard è RBAC, dove Role e RoleBinding associano identità a set di permessi granulari.

Gli **Admission Controllers** sono plugin che intercettano le richieste dopo l'autorizzazione ma prima della persistenza. Possono validare (es. PodSecurityPolicy verifica che il pod non richieda privilegi root) o mutare (es. aggiungere automaticamente sidecar container). Questa fase è critica per sicurezza: admission controller mal configurati possono permettere deployment di workload pericolosi.

\[Fonte: Kubernetes Documentation \- Admission Controllers \- Conoscenza implicita dell'architettura Kubernetes\]

Una volta superata la pipeline, la richiesta viene serializzata e scritta su **etcd**, il datastore chiave-valore distribuito che funge da unica fonte di verità per tutto lo stato del cluster. etcd è un componente critico: se compromesso, un attaccante ha accesso completo a secrets, configurazioni, credenziali. Per questo motivo, etcd espone tipicamente la propria API solo su localhost o rete interna protetta, e comunica con kube-apiserver tramite TLS mutuo.

#### 2.2.2 kube-scheduler: Assegnazione Workload ai Nodi

Il **kube-scheduler** monitora continuamente l'apiserver per identificare Pod appena creati che non hanno ancora un nodo assegnato (stato Pending). Per ogni Pod, il scheduler esegue un algoritmo di scoring che valuta tutti i nodi disponibili considerando vincoli (requirements) e preferenze (affinità/anti-affinità).

Il processo di scheduling si articola in due fasi. Nella fase di **Filtering**, il scheduler elimina nodi che non soddisfano requisiti hard (es. Pod richiede 8GB RAM, nodo ha solo 4GB). Nella fase di **Scoring**, i nodi rimanenti vengono classificati secondo euristiche configurabili (distribuzione equa del carico, collocazione su nodi con meno Pod, rispetto di affinity rules).

Il risultato del scheduling viene scritto nell'apiserver come binding del Pod a un nodo specifico. A questo punto, entra in gioco il Kubelet di quel nodo.

#### 2.2.3 kubelet: L'Agente sui Nodi Worker

Il **kubelet** è l'agente che gira su ogni nodo worker del cluster. Monitora continuamente l'apiserver per identificare Pod assegnati al proprio nodo e si occupa della loro gestione del ciclo di vita.

Quando un Pod viene schedulato su un nodo, il kubelet esegue questa sequenza:

\[kubelet riceve notifica da kube-apiserver\]

    ↓

\[Container Runtime Interface (CRI) \- comunicazione con container runtime\]

    ↓

\[Container Runtime \- containerd/CRI-O\]

    ↓ (1. Pull immagini container da registry)

    ↓ (2. Creazione container con runtime OCI \- runc)

    ↓ (3. Setup networking \- CNI plugin)

    ↓ (4. Mount volumi persistenti)

\[Container in esecuzione\]

Un aspetto critico di sicurezza è che il kubelet espone una propria API HTTP (porta 10250 di default) per operazioni diagnostiche (log, exec, port-forward). Storicamente, questa API era spesso esposta senza autenticazione, permettendo a chiunque con accesso di rete di eseguire comandi arbitrari nei container. Nelle versioni moderne, l'autenticazione è obbligatoria, ma misconfigurazioni restano comuni.

\[Fonte: NIST SP 800-190 \- Application Container Security Guide \- Conoscenza delle best practices Kubernetes security\]

#### 2.2.4 kube-controller-manager: Loop di Riconciliazione

Il **kube-controller-manager** è un componente che esegue molteplici controller, ciascuno responsabile di un tipo di risorsa. Ad esempio, il ReplicaSet Controller monitora continuamente i ReplicaSet e garantisce che il numero di repliche effettive corrisponda a quello dichiarato. Se un Pod crasha, il controller crea un nuovo Pod sostitutivo.

Questo pattern di "control loop" (monitor, compare, reconcile) è fondamentale in Kubernetes e ha implicazioni per la sicurezza: anche se un attaccante elimina manualmente un Pod, il controller lo ricrea automaticamente. Questo rende Kubernetes resiliente a failure accidentali, ma può anche mascherare attacchi (un Pod compromesso eliminato viene ricreato identico).

---

### 2.3 Networking in Kubernetes: CNI e Overlay Networks

Il networking in Kubernetes introduce complessità significativa perché ogni Pod riceve un indirizzo IP proprio, ma questi IP sono effimeri (il Pod può essere distrutto e ricreato con IP diverso). Kubernetes delega la gestione del networking a plugin **CNI (Container Network Interface)** che implementano policy di rete diverse.

#### 2.3.1 CNI e Modelli di Networking

Il ruolo del CNI è fornire connettività di rete ai container. Quando un Pod viene creato, il kubelet invoca il CNI plugin configurato, che si occupa di:

1. Allocare un indirizzo IP al Pod da un pool configurato  
2. Configurare le interfacce di rete del container (veth pairs \- virtual ethernet)  
3. Configurare routing per permettere comunicazione Pod-to-Pod

Esistono due approcci architetturali principali per implementare il networking Kubernetes: overlay network e flat network.

Le **overlay network** (usate da Flannel, Calico in modalità IPIP, Weave) creano una rete virtuale sopra la rete fisica. Il traffico tra Pod su nodi diversi viene incapsulato (tipicamente con VXLAN \- Virtual eXtensible LAN) prima di essere trasmesso sulla rete underlay.

Il flusso di un pacchetto in overlay VXLAN segue questa sequenza:

\[Pod A su Nodo 1 \- IP 10.244.1.5\]

    ↓ (Pacchetto IP destinazione: 10.244.2.8)

\[Interfaccia veth0 del Pod\]

    ↓

\[Bridge cni0 del Nodo\]

    ↓ (Routing rule: 10.244.2.0/24 → VXLAN tunnel vtep)

\[VXLAN Tunnel Endpoint \- encapsulation\]

    ↓ (Pacchetto originale wrappato in header UDP \+ VXLAN)

    ↓ (Header esterno: src=IP\_Nodo1, dst=IP\_Nodo2, porta 4789\)

\[Rete Fisica\]

    ↓

\[VXLAN Tunnel Endpoint Nodo 2 \- decapsulation\]

    ↓ (Estrae pacchetto originale)

\[Bridge cni0 Nodo 2\]

    ↓

\[Pod B su Nodo 2 \- IP 10.244.2.8\]

Questa encapsulation introduce overhead (header aggiuntivo, processing CPU per wrap/unwrap) ma isola completamente il traffico Kubernetes dalla rete fisica. Un aspetto critico per la sicurezza: il traffico VXLAN è tipicamente **non cifrato**. Se un attaccante ha accesso alla rete fisica, può potenzialmente sniffare traffico inter-pod.

\[Fonte: Calico Documentation \- Overlay and non-overlay networking \- Conoscenza dell'architettura CNI\]

Le **flat network** (usate da Calico in modalità BGP, Cilium in routing nativo) assegnano ai Pod IP direttamente instradabili sulla rete fisica, senza encapsulation. Questo elimina l'overhead ma richiede che l'infrastruttura di rete supporti routing dei CIDR Kubernetes, tipicamente tramite BGP.

#### 2.3.2 kube-proxy e Service Networking

Un problema fondamentale in Kubernetes è che i Pod sono effimeri: se un Pod viene ricreato, cambia IP. I client non possono quindi fare affidamento su IP statici. Kubernetes risolve questo tramite le risorse **Service**, che forniscono un IP virtuale stabile (ClusterIP) che bilancia il traffico verso un set di Pod identificati da label selector.

Il **kube-proxy**, un componente che gira su ogni nodo, si occupa di implementare questa astrazione Service. Esistono tre modalità di implementazione:

La modalità **iptables** (default fino a Kubernetes 1.25) programma regole iptables per fare NAT (Network Address Translation). Quando un pacchetto è destinato a un Service IP, iptables lo redirige a uno dei Pod endpoint. Questa modalità ha performance che degradano con O(n) regole per n Service/Endpoint.

La modalità **IPVS** (IP Virtual Server) usa il modulo kernel IPVS per load balancing Layer 4 più efficiente, con algoritmi configurabili (round-robin, least connection). Scala meglio ma richiede moduli kernel specifici.

La modalità **eBPF** (usata da Cilium) programma il kernel con bytecode eBPF per routing estremamente performante direttamente nel datapath kernel, bypassando iptables/netfilter. Questa è la modalità più moderna e performante ma richiede kernel Linux 4.19+.

\[Fonte: Kubernetes Documentation \- Service Networking \- Conoscenza architettura kube-proxy\]

---

### 2.4 Multi-Tenancy e Isolation

In ambienti cloud-native, è comune che un singolo cluster Kubernetes ospiti workload di team differenti o persino di clienti diversi (multi-tenancy). Garantire isolation forte tra questi workload è critico per evitare che un tenant compromesso possa impattare altri.

#### 2.4.1 Namespace come Primo Livello di Isolation

Kubernetes fornisce **namespace** come meccanismo di isolation logica. I namespace partizionano le risorse del cluster: un Pod nel namespace "team-a" non può accedere direttamente a un ConfigMap nel namespace "team-b" senza permessi espliciti.

Tuttavia, i namespace da soli NON forniscono isolation di rete o di sicurezza forte. Di default, tutti i Pod in un cluster possono comunicare tra loro indipendentemente dal namespace. Questo modello "flat network" è comodo per sviluppo ma inaccettabile per produzione multi-tenant.

#### 2.4.2 Network Policies per Isolation Layer 3/4

Le **NetworkPolicy** sono risorse Kubernetes che definiscono regole di firewall per traffico Pod-to-Pod. Una NetworkPolicy specifica quali Pod possono comunicare tra loro basandosi su:

- **Pod Selector**: identifica i Pod a cui la policy si applica (es. tutti i Pod con label "app=database")  
- **Ingress rules**: da dove questi Pod possono ricevere traffico (es. solo da Pod con label "app=backend")  
- **Egress rules**: verso dove questi Pod possono inviare traffico (es. solo verso IP esterni specifici)

Esempio concettuale di NetworkPolicy:

Una policy potrebbe dichiarare: "I Pod del database (label app=database) accettano connessioni solo da Pod backend (label app=backend) su porta 5432, e non possono iniziare connessioni outbound verso Internet".

Tecnicamente, i CNI plugin (come Calico o Cilium) traducono queste policy in regole iptables o eBPF che filtrano il traffico a livello kernel. Quando un pacchetto arriva a un Pod, le regole vengono valutate: se il pacchetto non corrisponde a nessuna regola ingress permessa, viene droppato.

\[Fonte: Kubernetes Documentation \- Network Policies \- Conoscenza best practices isolation\]

Una limitazione critica delle NetworkPolicy è che operano solo a **Layer 3/4** (IP, porta). Non possono ispezionare il payload HTTP/HTTPS (Layer 7). Questo significa che una NetworkPolicy può permettere "traffico HTTP dalla webapp al backend", ma non può distinguere tra "GET /public" e "DELETE /admin/users". Per controllo granulare Layer 7 serve un Service Mesh.

#### 2.4.3 Pod Security Standards

Oltre all'isolation di rete, è necessario limitare le capacità dei container per evitare privilege escalation. Kubernetes fornisce **Pod Security Standards (PSS)**, un framework di policy di sicurezza che definisce tre livelli:

- **Privileged**: nessuna restrizione (usato solo per componenti infrastrutturali trusted come CNI)  
- **Baseline**: previene escalation di privilegio più comuni (no host network, no privileged containers)  
- **Restricted**: policy hardenizzate (no root user, read-only filesystem, capabilities drop)

Questi standard vengono enforced tramite **admission controllers** come Pod Security Admission. Quando un utente tenta di creare un Pod che richiede privilegi (es. `securityContext.privileged: true`), l'admission controller nega la richiesta se il namespace ha policy restricted.

Un errore comune in ambienti di test è disabilitare questi controlli per comodità, creando drift con la configurazione di produzione. Un framework di security testing deve verificare che i Pod di test non richiedano privilegi non disponibili in produzione.

\[Fonte: Kubernetes Documentation \- Pod Security Standards \- Conoscenza security best practices\]

---

### 2.5 Kubernetes Ingress e Gateway API

Kubernetes fornisce risorse native per esporre servizi al di fuori del cluster. Questa funzionalità è fondamentale per le API esposte a client esterni.

#### 2.5.1 Ingress: Il Modello Legacy

La risorsa **Ingress** permette di definire regole HTTP/HTTPS per routing esterno. Un Ingress specifica:

hostname: api.example.com → Service: backend-svc

path: /v1/users → Service: users-svc

path: /v1/products → Service: products-svc

L'Ingress è solo una risorsa dichiarativa. La logica effettiva di routing è implementata da un **Ingress Controller**, un componente separato che monitora l'API di Kubernetes per rilevare creazioni/modifiche di Ingress e configura di conseguenza un reverse proxy sottostante (tipicamente Nginx, HAProxy, Traefik).

Il problema storico dell'Ingress è che le funzionalità avanzate (rate limiting, autenticazione, rewrite URL) richiedevano annotation specifiche del controller:

annotations:

  nginx.ingress.kubernetes.io/rate-limit: "100"

  traefik.ingress.kubernetes.io/rate-limit: "qps: 100"

Questa proliferazione di annotation controller-specific rende le configurazioni non portabili. Migrare da Nginx a Traefik richiede riscrivere tutte le annotation.

#### 2.5.2 Gateway API: Il Futuro dello Ingress

La **Kubernetes Gateway API** (GA dal 2023\) risolve le limitazioni di Ingress con un modello più espressivo e role-oriented.

L'architettura si articola su tre risorse principali:

**GatewayClass** definisce il tipo di gateway controller disponibile (es. Nginx, Istio, Cilium). È gestita dall'infrastructure provider.

**Gateway** è un'istanza di una GatewayClass. Definisce listener (porte, protocolli, TLS certificates). È gestita dal cluster operator.

**Route** (HTTPRoute, GRPCRoute, TCPRoute) definisce regole di routing specifiche per protocollo. È gestita dagli application developer.

Questa separazione di responsabilità (role-oriented design) permette a diverse figure di gestire aspetti differenti senza interferenze. L'infrastructure team configura le GatewayClass, il team operations deploya Gateway con certificati TLS, gli sviluppatori creano HTTPRoute per le loro applicazioni.

\[Fonte: Kubernetes Gateway API \- Introduction \- https://gateway-api.sigs.k8s.io/\]

Una caratteristica avanzata della Gateway API è il supporto nativo per protocolli oltre HTTP/HTTPS. **GRPCRoute** permette routing granulare su service/method gRPC. **TLSRoute** permette TLS passthrough (il gateway non decifra il traffico, lo passa al backend che gestisce TLS).

Dal punto di vista del security testing, la Gateway API introduce nuove sfide: le route possono avere policy di autenticazione/autorizzazione attaccate tramite **Policy Attachment**, un meccanismo estensibile. Testare che queste policy siano correttamente applicate richiede comprendere non solo la route ma anche le policy associate.

---

### 2.6 Rischi Specifici di Kubernetes

#### 2.6.1 API Interne Esposte

Kubernetes espone molteplici API interne che, se accessibili da attaccanti, permettono compromissione totale del cluster.

Il **kubelet API** (porta 10250\) permette esecuzione di comandi nei container, accesso ai log, port forwarding. Se esposta senza autenticazione o con credenziali deboli, un attaccante può ottenere RCE (Remote Code Execution) su tutti i Pod del nodo.

Il **metrics-server** espone metriche di utilizzo CPU/memoria dei Pod (porta 443). Sebbene sembri innocuo, un attaccante può usarlo per profilare i workload e identificare servizi sensibili.

L'**etcd API** (porta 2379\) è il datastore centrale. Accesso a etcd significa accesso a tutti i secrets, inclusi token di service account con permessi cluster-admin.

\[Fonte: CNCF \- Kubernetes Security Best Practices \- Conoscenza threat model Kubernetes\]

#### 2.6.2 Privilege Escalation via RBAC Misconfiguration

RBAC in Kubernetes è estremamente potente ma complesso. Un errore comune è assegnare il ruolo **cluster-admin** a service account applicativi per "semplificare" i permessi. Questo viola il principio di least privilege: se un Pod con questo service account viene compromesso, l'attaccante ha controllo completo del cluster.

Un altro pattern pericoloso è creare Role con wildcard:

rules:

  \- apiGroups: \["\*"\]

    resources: \["\*"\]

    verbs: \["\*"\]

Questo concede ogni permesso possibile. In un ambiente multi-tenant, questo permetterebbe a un tenant di accedere ai namespace di altri tenant.

#### 2.6.3 Container Escape e Host Access

Anche con NetworkPolicy e Pod Security Standards, un container può potenzialmente "escapare" e compromettere il nodo host. Tecniche di container escape sfruttano vulnerabilità kernel, misconfigurazioni volume mounts, o container privilegiati.

Un esempio classico è montare il socket Docker del host (`/var/run/docker.sock`) nel container. Questo permette al container di controllare il Docker daemon del host, creando nuovi container con privilegi root sul host.

\[Fonte: CIS Benchmark \- Kubernetes Security \- Conoscenza best practices container isolation\]

---

## 3\. SERVICE MESH

### 3.1 Il Problema Architetturale

Quando un'applicazione basata su microservizi cresce oltre una decina di servizi, emergono sfide di comunicazione service-to-service che non sono risolvibili con Kubernetes da solo. Come si implementa mTLS (mutual TLS) tra tutti i servizi senza modificare il codice applicativo? Come si gestiscono retry, timeout, circuit breaker in modo consistente? Come si traccia una richiesta attraverso chiamate tra 20 microservizi diversi?

Queste funzionalità sono tradizionalmente implementate all'interno delle applicazioni, usando librerie come Netflix Hystrix (Java) o resilience4j. Ma questo approccio presenta problemi: ogni linguaggio richiede librerie diverse, l'aggiornamento richiede rebuild delle applicazioni, il comportamento non è uniforme.

Il Service Mesh nasce come soluzione a questi problemi, introducendo un layer infrastrutturale dedicato alla gestione delle comunicazioni service-to-service. L'idea fondamentale è separare la logica di networking/sicurezza dal codice applicativo, delegandola a proxy specializzati deployati accanto ai servizi.

---

### 3.2 Istio: Architettura Sidecar e Ambient

Istio è il service mesh più adottato in produzione, supportato da Google, IBM e Lyft. La sua evoluzione architetturale riflette i problemi pratici emersi negli ultimi anni.

#### 3.2.1 Architettura Sidecar Tradizionale

Il modello sidecar prevede che ogni Pod Kubernetes abbia due container: il container applicativo e un sidecar proxy (Envoy). Tutto il traffico di rete in ingresso e uscita dal Pod viene intercettato dal sidecar tramite iptables rules iniettate automaticamente da Istio.

Il flusso di una richiesta in architettura sidecar:

\[Pod A \- Servizio Frontend\]

  \[Container App\] → (localhost:15001 \- iptables redirect)

      ↓

  \[Envoy Sidecar\] → (mTLS encryption)

      ↓

  (Network \- traffico cifrato)

      ↓

\[Pod B \- Servizio Backend\]

  \[Envoy Sidecar\] → (mTLS decryption \+ policy enforcement)

      ↓

  \[Container App\] ← (localhost \- plaintext)

Il Control Plane di Istio (**Istiod**) è il componente monolitico (dal 2020\) che gestisce configurazione, certificati e telemetria. Istiod traduce le risorse Istio di alto livello (VirtualService, DestinationRule) in configurazioni Envoy tramite il protocollo **xDS** (discovery service).

Il protocollo xDS si articola su molteplici API:

- **LDS (Listener Discovery Service)**: configura su quali porte Envoy ascolta  
- **RDS (Route Discovery Service)**: configura regole di routing HTTP  
- **CDS (Cluster Discovery Service)**: definisce backend service endpoint  
- **EDS (Endpoint Discovery Service)**: fornisce IP dei Pod backend

Quando un amministratore crea una VirtualService Istio (es. "route 10% traffico alla versione canary"), Istiod la traduce in configurazioni xDS e le push ai sidecar Envoy interessati. Questo modello push garantisce che le configurazioni siano applicate rapidamente, ma introduce latenza e overhead di rete.

\[Fonte: Istio Documentation \- Architecture \- Conoscenza architettura Istio\]

Il sidecar Istio implementa automaticamente **mTLS** tra servizi. Istiod agisce come Certificate Authority (CA), emettendo certificati X.509 a breve scadenza (24 ore default) per ogni workload. I sidecar li ruotano automaticamente senza intervento manuale. Questo elimina la complessità di gestione certificati, ma introduce un SPOF: se Istiod è down, i certificati scaduti non vengono rinnovati.

#### 3.2.2 Istio Ambient: L'Evoluzione Sidecar-less

Il modello sidecar, pur funzionale, introduce overhead significativo: ogni Pod ha due container (consumo memoria/CPU raddoppiato), upgrade del sidecar richiede restart dei Pod applicativi, complessità di debugging (logs distribuiti tra app e sidecar).

Istio Ambient Mode (GA 2024\) elimina i sidecar introducendo due nuovi componenti:

**ztunnel** (Zero Trust Tunnel) è un proxy Layer 4 deployato **one-per-node** (non per-pod), scritto in Rust per performance. Gestisce mTLS e autenticazione workload a livello TCP, senza ispezionare HTTP.

**Waypoint Proxy** è un proxy Layer 7 (Envoy) deployato **one-per-namespace** (opzionale). Gestisce traffic management avanzato (retry, timeout, header manipulation) solo per i namespace che ne hanno bisogno.

L'architettura Ambient riduce drasticamente il footprint: zero container sidecar, riduzione 90% memoria per il data plane. Tuttavia, introduce nuove complessità di configurazione e debugging distribuito.

\[Fonte: Istio Blog \- Introducing Ambient Mesh \- https://istio.io/latest/blog/2022/introducing-ambient-mesh/\]

---

### 3.3 Linkerd: Minimalismo e Performance

Linkerd adotta un approccio opposto a Istio: invece di offrire tutte le funzionalità possibili, si concentra su semplicità e performance. Il proxy **linkerd2-proxy** è scritto in Rust (non Envoy/C++) e ha un memory footprint minimo (\~10MB vs \~128MB di Envoy).

Performance comparison documentati da LiveWyer mostrano Linkerd come il service mesh più veloce, con overhead del 10-15% rispetto a baseline senza mesh, contro 25-35% di Istio.

\[Fonte: LiveWyer \- Service Meshes Decoded \- https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/\]

Tuttavia, questa semplicità ha un prezzo. Linkerd è **Kubernetes-only** (non supporta VM workloads come Istio), ha una community più ristretta (80%+ contributi da Buoyant, il vendor), e a partire dal 2024 le stable builds gratuite non sono più disponibili (shift verso paid enterprise).

\[Fonte: Buoyant Blog \- Linkerd Stable Releases \- Conoscenza evoluzione business model\]

---

### 3.4 Rischi Specifici dei Service Mesh

#### 3.4.1 Complessità e Misconfiguration

I service mesh introducono un livello di astrazione potente ma complesso. Una policy Istio mal scritta può bloccare traffico legittimo o permettere traffico non autorizzato in modi non ovvi. Il debugging richiede comprendere come una VirtualService viene tradotta in configurazioni Envoy, quali sidecar l'hanno ricevuta, e come interagisce con altre policy.

Un esempio comune: una policy DENY sovrascrive sempre policy ALLOW, indipendentemente dall'ordine. Se esiste una policy globale "DENY all traffic from namespace X", una policy specifica "ALLOW traffic from namespace X to service Y" viene ignorata. Questo comportamento non è intuitivo.

#### 3.4.2 Memory Exhaustion su gRPC Streaming

Come documentato da Red Hat, gRPC bidirectional streaming può causare memory exhaustion nei sidecar Envoy. Il problema tecnico: Envoy bufferizza i messaggi gRPC in memoria, ma un stream bidirezionale può essere infinito. Il circuit breaker HTTP/2 (`http2MaxRequests`) conta richieste concorrenti, non messaggi per stream.

1 gRPC stream \= 1 HTTP/2 request

100 concurrent streams (circuit breaker OK)

× 1.000.000 messages per stream

\= 100M messages buffered in Envoy → OOM

La mitigazione richiede aumentare limiti di memoria sidecar (non sempre accettabile) o usare Istio Ambient (no sidecar).

\[Fonte: Red Hat \- gRPC Protocol Listener on Service Mesh \- https://access.redhat.com/solutions/6246351\]

---

## 4\. ARCHITETTURE SERVERLESS

### 4.1 Il Problema Architetturale

L'approccio tradizionale (deploy di server always-on) spreca risorse: un servizio usato 10 minuti al giorno consuma CPU/RAM 24/7. Inoltre, gestire scaling (aggiungere server quando il carico aumenta) è complesso e lento.

Il paradigma serverless elimina questi problemi: invece di deployare server, si deployano funzioni event-driven che vengono eseguite on-demand, scalano automaticamente a zero quando inattive, e fanno pagare solo il tempo di esecuzione effettivo.

Questo modello è particolarmente adatto per API con traffico intermittente o imprevedibile: webhook, API di elaborazione dati batch, backend mobile con spike di traffico.

---

### 4.2 AWS Lambda: Execution Model

AWS Lambda è il servizio serverless più maturo. Comprenderne il modello di esecuzione è fondamentale per identificare rischi.

#### 4.2.1 Cold Start vs Warm Execution

Quando una funzione Lambda viene invocata per la prima volta (o dopo un periodo di inattività), AWS deve:

1. Provisioning di un **execution environment** (micro-VM isolata)  
2. Download del codice della funzione da S3  
3. Inizializzazione del runtime (Python, Node.js, Java, ecc.)  
4. Esecuzione della funzione

Questo processo (**cold start**) richiede 100-500ms, un'eternità per API real-time. Dopo l'esecuzione, AWS mantiene l'environment "warm" per alcuni minuti (10-15 min tipicamente), permettendo invocazioni successive istantanee (\~ms latency).

AWS offre **Provisioned Concurrency** per eliminare cold start: un numero configurato di environment viene mantenuto sempre warm, pre-inizializzati. Questo elimina latency ma aumenta costi (si paga per environment idle).

\[Fonte: Lumigo \- AWS Lambda Architecture \- https://lumigo.io/learn/aws-lambda-architecture/\]

#### 4.2.2 VPC Integration e Network Latency

Lambda può accedere a risorse in VPC privata (RDS, ElastiCache), ma questo introduce complessità. Lambda deve creare **Elastic Network Interface (ENI)** nella VPC, allocare IP addresses, e configurare routing.

Storicamente, questo causava cold start catastrofici (+10 secondi) perché ogni invocazione creava nuove ENI. AWS ha ottimizzato questo nel 2019 con ENI sharing: le funzioni Lambda condividono un pool di ENI pre-create, riducendo overhead a \~100-200ms.

Tuttavia, questa ottimizzazione introduce un rischio: le ENI sono condivise tra invocazioni Lambda diverse. Se una funzione compromessa manipola configurazioni di rete (es. via socket raw), potrebbe impattare altre funzioni.

\[Fonte: AWS Documentation \- Lambda VPC Networking \- Conoscenza architettura Lambda\]

#### 4.2.3 IAM Execution Role e Security

Ogni funzione Lambda ha un **Execution Role** IAM che determina a quali risorse AWS può accedere (S3 buckets, DynamoDB tables, ecc.). Questo è critico per security: una funzione con permessi troppo ampi (`"Action": ["*"]`) può leggere/modificare qualsiasi risorsa AWS account.

Un rischio comune: copiare Execution Role da documentazione o tutorial senza customizzarli. Esempio: un tutorial per "Lambda che legge da S3" potrebbe usare `s3:*` (tutti i permessi S3) invece di `s3:GetObject` limitato a bucket specifici.

Per security testing, verificare che:

- Lambda non abbia permessi admin (`AdministratorAccess` policy)  
- Permessi siano scope a risorse specifiche (non `"Resource": "*"`)  
- Lambda non possa modificare il proprio Execution Role (privilege escalation)

---

### 4.3 Knative: Serverless Open Source su Kubernetes

Knative estende Kubernetes con capacità serverless, permettendo auto-scaling to zero senza dipendere da cloud provider specifici.

#### 4.3.1 Architettura Knative Serving

Knative Serving gestisce deployment e auto-scaling di container serverless. L'architettura introduce componenti nuovi:

**Activator** è un proxy che intercetta traffico verso servizi scaled-to-zero. Quando una richiesta arriva per un servizio inattivo, Activator bufferizza la richiesta e notifica l'Autoscaler di creare Pod.

**Autoscaler** monitora metriche (requests-per-second, concurrency) e scala repliche automaticamente. Quando nessuna richiesta arriva per N secondi (default 60), scala a zero Pod.

**Queue-Proxy** è un sidecar iniettato in ogni Pod Knative che raccoglie metriche di traffico e le invia all'Autoscaler.

Il flusso di una richiesta a un servizio Knative scaled-to-zero:

\[Client Request\]

    ↓

\[Knative Ingress Gateway\]

    ↓

\[Activator \- service currently 0 replicas\]

    ↓ (Buffer request)

    ↓ (Signal Autoscaler: scale up)

\[Autoscaler creates Pod\]

    ↓ (Pod initialization \~5-10 seconds)

\[Pod Ready\]

    ↓ (Activator forwards buffered request)

\[Queue-Proxy Sidecar\]

    ↓

\[Application Container\]

Questo introduce latency significativa per la prima richiesta (cold start 5-10s), ma richieste successive sono servite direttamente dal Pod.

\[Fonte: Knative Documentation \- Serving Architecture \- Conoscenza architettura Knative\]

#### 4.3.2 Revision-Based Deployment

Knative introduce il concetto di **Revision**: ogni modifica al codice/configurazione crea una nuova Revision immutabile. Il traffico può essere split tra Revision diverse (pattern blue-green, canary).

Esempio: 90% traffico a Revision v1, 10% a Revision v2 (canary). Dopo validazione, shift 100% a v2.

Questo ha implicazioni per security testing: una API può avere URL differenti per Revision diverse:

v1: https://myservice-v1-default.example.com

v2: https://myservice-v2-default.example.com

latest: https://myservice-default.example.com (split traffic)

Un framework di discovery deve rilevare tutte le Revision attive, non solo l'URL "latest".

---

### 4.4 Rischi Specifici di Serverless

#### 4.4.1 Event Injection e Trigger Abuse

Serverless functions sono tipicamente triggered da eventi (S3 upload, DynamoDB change, HTTP request). Un attaccante che controlla la sorgente eventi può manipolare input in modi imprevisti.

Esempio: Lambda triggered da S3 `ObjectCreated` event. Attaccante uploada file con nome malevolo contenente path traversal: `../../etc/passwd`. Se la funzione processa il filename senza validation, potrebbe leggere file sensibili.

#### 4.4.2 Timeout e Resource Exhaustion

Lambda ha limiti configurabili (timeout max 15 minuti, memoria max 10GB). Un attaccante può inviare richieste crafted che causano processing lento, maxando timeout e generando costi.

Esempio: API che processa immagini. Attaccante uploada immagine 10MB compressa che decomprime a 1GB, causando OOM o timeout.

#### 4.4.3 Secret Management

Serverless functions richiedono accesso a secrets (database password, API keys). Hardcodare secrets nel codice è inaccettabile (leak via source code). AWS offre Secrets Manager, ma richiede configuration: funzioni devono avere IAM permission per `secretsmanager:GetSecretValue`.

Un errore comune: loggare secrets accidentalmente. CloudWatch Logs (dove vanno i log Lambda) sono persistenti e accessibili via console AWS. Un `console.log(process.env.DB_PASSWORD)` espone credenziali.

---

## CONCLUSIONI FASE 1.A

Questa analisi delle architetture cloud-native per l'esposizione di API ha evidenziato come la superficie di attacco sia determinata non solo dalle API stesse, ma dal contesto infrastrutturale in cui operano. API Gateway tradizionali centralizzano controllo ma creano single point of failure. Kubernetes introduce complessità di networking e API interne potenzialmente esposte. Service Mesh aggiungono security di default ma con overhead e misconfiguration risk. Serverless elimina gestione server ma introduce nuove sfide di execution model e event-driven vulnerabilities.

Un framework di security testing efficace deve comprendere queste architetture in profondità, riconoscere quale architettura ospita un'API target, e adattare le strategie di discovery e testing di conseguenza. La fase successiva analizzerà i protocolli API stessi, per poi studiare le interazioni architettura-protocollo dove emergono i blind spot più insidiosi.

---

## BIBLIOGRAFIA TECNICA

### Documentazione CNCF

- CNCF Cloud Native Glossary \- API Gateway: [https://glossary.cncf.io/api-gateway/](https://glossary.cncf.io/api-gateway/)  
- Kubernetes Gateway API \- Introduction: [https://gateway-api.sigs.k8s.io/](https://gateway-api.sigs.k8s.io/)  
- Kubernetes Gateway API \- FAQ: [https://gateway-api.sigs.k8s.io/faq/](https://gateway-api.sigs.k8s.io/faq/)  
- CNCF Blog \- Advancing Open Source Gateways with kgateway: [https://www.cncf.io/blog/2025/02/05/advancing-open-source-gateways-with-kgateway/](https://www.cncf.io/blog/2025/02/05/advancing-open-source-gateways-with-kgateway/)

### AWS Documentation

- AWS Documentation \- Amazon API Gateway: [https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)  
- AWS Reference Architecture \- Multi-region API Gateway with CloudFront: [https://docs.aws.amazon.com/architecture-diagrams/latest/multi-region-api-gateway-with-cloudfront/multi-region-api-gateway-with-cloudfront.html](https://docs.aws.amazon.com/architecture-diagrams/latest/multi-region-api-gateway-with-cloudfront/multi-region-api-gateway-with-cloudfront.html)

### Azure Documentation

- Azure API Management \- API Gateway Overview: [https://learn.microsoft.com/en-us/azure/api-management/api-management-gateways-overview](https://learn.microsoft.com/en-us/azure/api-management/api-management-gateways-overview)  
- Azure Architecture Center \- API Gateways: [https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway](https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway)

### Google Cloud Documentation

- Google Cloud \- API Gateway Architecture Overview: [https://cloud.google.com/api-gateway/docs/architecture-overview](https://cloud.google.com/api-gateway/docs/architecture-overview)  
- Google Cloud \- About API Gateway: [https://cloud.google.com/api-gateway/docs/about-api-gateway](https://cloud.google.com/api-gateway/docs/about-api-gateway)

### Kong Documentation

- Kong Gateway Documentation: [https://developer.konghq.com/gateway/](https://developer.konghq.com/gateway/)  
- GitHub \- Kong Repository: [https://github.com/Kong/kong](https://github.com/Kong/kong)  
- kgateway Official Site: [https://kgateway.dev/](https://kgateway.dev/)  
- kgateway Blog \- Advancing Open Source Gateways: [https://kgateway.dev/blog/advancing-open-source-gateways/](https://kgateway.dev/blog/advancing-open-source-gateways/)

### Service Mesh Resources

- Solo.io \- Linkerd vs Istio: [https://www.solo.io/topics/istio/linkerd-vs-istio](https://www.solo.io/topics/istio/linkerd-vs-istio)  
- Pi Kubernetes Cluster Docs \- Service Mesh Istio: [https://picluster.ricsanfre.com/docs/istio/](https://picluster.ricsanfre.com/docs/istio/)  
- LiveWyer \- Service Meshes Decoded Istio vs Linkerd vs Cilium: [https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/](https://livewyer.io/blog/2024/05/08/comparison-of-service-meshes/)  
- Platform9 \- Kubernetes Service Mesh Comparison: [https://platform9.com/blog/kubernetes-service-mesh/](https://platform9.com/blog/kubernetes-service-mesh/)

### Serverless Resources

- Serverless Architecture Patterns \- AWS Azure GCP Guide: [https://americanchase.com/serverless-architecture-patterns/](https://americanchase.com/serverless-architecture-patterns/)  
- CloudOptimo \- AWS Lambda vs Azure Functions vs Google Cloud Functions: [https://www.cloudoptimo.com/blog/aws-lambda-vs-azure-functions-vs-google-cloud-functions-a-detailed-serverless-comparison/](https://www.cloudoptimo.com/blog/aws-lambda-vs-azure-functions-vs-google-cloud-functions-a-detailed-serverless-comparison/)  
- Lumigo \- AWS Lambda Architecture: [https://lumigo.io/learn/aws-lambda-architecture/](https://lumigo.io/learn/aws-lambda-architecture/)  
- GeeksforGeeks \- Serverless Architecture: [https://www.geeksforgeeks.org/system-design/serverless-architectures/](https://www.geeksforgeeks.org/system-design/serverless-architectures/)

### Kubernetes Networking

- NGINX Community Blog \- Kubernetes Networking: Moving from Ingress to Gateway API: [https://blog.nginx.org/blog/kubernetes-networking-ingress-controller-to-gateway-api](https://blog.nginx.org/blog/kubernetes-networking-ingress-controller-to-gateway-api)  
- DigitalOcean Tutorial \- Kubernetes Gateway API Tutorial with Cilium: [https://www.digitalocean.com/community/tutorials/kubernetes-gateway-api-tutorial-cilium-ingress-alternative](https://www.digitalocean.com/community/tutorials/kubernetes-gateway-api-tutorial-cilium-ingress-alternative)  
- The New Stack \- Gateway API or Ingress Developer Guide: [https://thenewstack.io/gateway-api-or-ingress-a-developers-guide-to-kubernetes-routing/](https://thenewstack.io/gateway-api-or-ingress-a-developers-guide-to-kubernetes-routing/)

### Technical Articles & Blogs

- Kong Blog \- Building and Securing API Gateway Architecture: [https://konghq.com/blog/learning-center/building-a-secure-api-gateway](https://konghq.com/blog/learning-center/building-a-secure-api-gateway)  
- Medium \- AWS API Gateway Deep Dive: [https://medium.com/@joudwawad/aws-api-gateway-deep-dive-rest-apis-5ae16a326b3a](https://medium.com/@joudwawad/aws-api-gateway-deep-dive-rest-apis-5ae16a326b3a)  
- Medium \- Exploring GCP API Gateway with Cloud Functions: [https://medium.com/google-cloud/exploring-google-cloud-api-gateway-with-google-cloud-functions-ff56c1c96cc9](https://medium.com/google-cloud/exploring-google-cloud-api-gateway-with-google-cloud-functions-ff56c1c96cc9)  
- DEV Community \- Service Mesh Istio Introduction: [https://dev.to/godofgeeks/service-mesh-istio-linkerd-introduction-58pj](https://dev.to/godofgeeks/service-mesh-istio-linkerd-introduction-58pj)

---

**FINE FASE 1.A \- ARCHITETTURE CLOUD-NATIVE**

# FASE 1.B: PROTOCOLLI E STILI ARCHITETTURALI API

**Data:** 31 Gennaio 2026  
**Versione:** 3.0 (Versione Definitiva \- Integrazione Gap Tecnici)

---

## INTRODUZIONE

Se le architetture definiscono il "dove" delle API (il contesto infrastrutturale in cui operano), i protocolli definiscono il "cosa": il linguaggio con cui client e server comunicano, le convenzioni che regolano lo scambio di dati, i meccanismi di serializzazione e trasporto. Comprendere i protocolli API moderni è fondamentale non solo per implementarli correttamente, ma soprattutto per identificarne le vulnerabilità intrinseche.

Un errore comune nell'approccio alla sicurezza delle API è trattare tutti i protocolli come varianti di HTTP con payload JSON. Questa semplificazione nasconde differenze strutturali profonde che hanno implicazioni dirette sulla testabilità e sulla superficie di attacco. Un protocollo binario come gRPC richiede strategie di testing completamente diverse da GraphQL, che a sua volta presenta sfide assenti in REST.

Questa sezione analizza sei protocolli dominanti nel panorama cloud-native del 2024-2026: REST (il veterano onnipresente), GraphQL (l'astrazione flessibile), gRPC (il protocollo binario ad alte prestazioni), SOAP (il legacy ancora diffuso), WebSocket (la comunicazione real-time bidirezionale), e Server-Sent Events (lo streaming unidirezionale). Per ogni protocollo, seguiamo una struttura costante: prima descriviamo la meccanica interna (come funziona tecnicamente), poi identifichiamo le vulnerabilità strutturali (quali rischi sono intrinsechi al design), e infine analizziamo le sfide di testing (perché gli strumenti tradizionali falliscono).

L'obiettivo non è fornire un manuale d'uso dei protocolli, ma costruire una comprensione profonda di come le scelte di design di ciascun protocollo influenzino la sicurezza e richiedano approcci di testing differenziati.

---

## 1\. REST (REPRESENTATIONAL STATE TRANSFER)

### 1.1 Meccanica del Protocollo

REST non è tecnicamente un protocollo nel senso stretto del termine, ma piuttosto uno stile architetturale definito da Roy Fielding nella sua tesi di dottorato del 2000\. Tuttavia, nel linguaggio comune, quando si parla di "API REST" ci si riferisce a interfacce HTTP che seguono (più o meno fedelmente) i principi REST.

Il fondamento di REST è il concetto di **risorsa**: ogni entità del sistema (un utente, un prodotto, un ordine) è identificata da un URL univoco e manipolata tramite metodi HTTP standard. Il metodo GET recupera la rappresentazione di una risorsa, POST ne crea una nuova, PUT la sostituisce interamente, PATCH la modifica parzialmente, DELETE la elimina. Questa mappatura risorse-URL-metodi crea un'interfaccia uniforme che, in teoria, dovrebbe essere auto-esplicativa e prevedibile.

Un aspetto fondamentale di REST è la **statelessness**: ogni richiesta deve contenere tutte le informazioni necessarie per essere processata. Il server non mantiene stato di sessione tra richieste successive. L'autenticazione viene quindi gestita tramite token (tipicamente JWT \- JSON Web Token) inclusi negli header HTTP di ogni richiesta, oppure tramite cookie che il client allega automaticamente.

Il formato dati in REST è flessibile: sebbene JSON sia diventato dominante, REST supporta nativamente XML, plain text, HTML, o formati binari. Il meccanismo di **content negotiation** permette al client di specificare il formato desiderato tramite l'header Accept, e al server di rispondere con il Content-Type appropriato. Questa flessibilità, pur comoda, introduce ambiguità: lo stesso endpoint può ritornare JSON o XML a seconda del client, complicando il testing.

\[Fonte: Baeldung \- REST vs GraphQL vs gRPC \- https://www.baeldung.com/rest-vs-graphql-vs-grpc\]

Il modello di comunicazione REST segue questo flusso:

\[Client\]

    ↓ (HTTP Request: GET /users/123)

    ↓ (Headers: Authorization: Bearer \<JWT\>, Accept: application/json)

\[Server\]

    ↓ (Parsing request, authentication via JWT validation)

    ↓ (Authorization: verificare che JWT permetta accesso a user 123\)

    ↓ (Business logic: query database per user ID 123\)

    ↓ (Serializzazione risposta in JSON)

\[Client\]

    ← (HTTP Response 200 OK, Content-Type: application/json)

    ← (Body: {"id": 123, "name": "Alice", "email": "alice@example.com"})

Una caratteristica spesso sottovalutata di REST è che **non impone uno schema formale**. A differenza di protocolli come gRPC (che richiede file proto) o SOAP (che usa WSDL), REST può operare senza definizione contrattuale. L'adozione di OpenAPI/Swagger è volontaria e non enforced a runtime. Questo significa che un'API può ritornare campi non documentati, o omettere campi previsti, senza che il protocollo se ne accorga.

### 1.2 Vulnerabilità Strutturali

Le caratteristiche architetturali di REST, pur offrendo flessibilità, introducono vulnerabilità intrinseche che emergono dalla natura resource-oriented e schema-optional del protocollo.

#### 1.2.1 Over-fetching e Excessive Data Exposure

REST ritorna l'intera rappresentazione di una risorsa anche quando il client richiede solo alcuni campi. Se un client vuole solo il nome di un utente, una chiamata GET a `/users/123` ritorna comunque nome, email, data di nascita, indirizzo, preferenze, e potenzialmente campi interni come `password_hash` o `internal_id`.

Questo comportamento, definito **over-fetching**, crea un rischio di data exposure: campi sensibili inclusi nella risposta per default possono essere esposti a client non autorizzati a vederli. Il problema è strutturale: REST non ha un meccanismo nativo per selezionare campi (field selection). Alcune API implementano query parameter custom (esempio: `/users/123?fields=name,email`), ma questa non è una funzionalità standard del protocollo.

Scanner di sicurezza tradizionali come OWASP ZAP o Burp Suite verificano se un endpoint è accessibile, ma non analizzano se la risposta contiene dati in eccesso rispetto al principio di least privilege. Un endpoint potrebbe essere correttamente autenticato ma ritornare il campo `salary` che dovrebbe essere visibile solo a HR, e un scanner HTTP generico non rileverebbe questa violazione.

\[Fonte: LogRocket Blog \- GraphQL vs gRPC vs REST \- https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/\]

#### 1.2.2 Broken Object Level Authorization (BOLA)

REST identifica risorse tramite ID prevedibili inclusi nell'URL: `/users/123`, `/orders/456`. Questa prevedibilità facilita l'enumerazione: un attaccante può iterare su ID sequenziali (`/users/1`, `/users/2`, ..., `/users/10000`) per accedere a risorse altrui se il backend non implementa controlli di autorizzazione granulari.

BOLA (noto anche come IDOR \- Insecure Direct Object Reference) è la vulnerabilità numero uno nella OWASP API Security Top 10\. Il problema non è tecnico ma implementativo: REST non fornisce meccanismi built-in per authorization. È responsabilità del developer verificare per ogni richiesta che l'utente autenticato abbia permesso di accedere alla risorsa specifica.

Testare BOLA richiede autenticazione con utenti multipli e correlazione delle risposte. Un tool automatizzato deve:

- Autenticarsi come User A  
- Richiedere una risorsa (esempio: `/orders/789`)  
- Memorizzare la risposta  
- Autenticarsi come User B  
- Richiedere la stessa risorsa  
- Verificare se User B può accedere a una risorsa che dovrebbe appartenere a User A

Questo workflow multi-step non è supportato nativamente da scanner HTTP generici.

#### 1.2.3 Mass Assignment e Parameter Pollution

La flessibilità di JSON permette ai client di inviare campi arbitrari nel payload. Se il backend deserializza il JSON direttamente in oggetti database senza whitelist, un attaccante può iniettare campi non documentati.

Scenario tipico: un'API `/users` accetta POST per creare utenti con campi `username`, `email`, `password`. Un attaccante invia:

{

  "username": "attacker",

  "email": "evil@test.com",

  "password": "pass123",

  "is\_admin": true

}

Se il backend mappa automaticamente tutti i campi JSON alle colonne database senza validazione, l'attaccante crea un account admin. Questo è **mass assignment**, una vulnerabilità strutturale di API che non enforced schema.

Tool DAST (Dynamic Application Security Testing) non rilevano mass assignment perché richiederebbero conoscenza dello schema interno del database e della logica applicativa. Un tool vedrebbe solo "POST successful, user created", senza sapere che il campo `is_admin` non dovrebbe essere settabile da client.

#### 1.2.4 HTTP Verb Tampering

REST assume che server verifichino il metodo HTTP e applichino logica appropriata (GET \= read-only, DELETE \= distruttivo). Server mal configurati possono accettare metodi non previsti.

Esempio: endpoint `/users/123` dovrebbe supportare solo GET (lettura) e PATCH (aggiornamento parziale). Un attaccante tenta DELETE e, se il server non rifiuta esplicitamente metodi non implementati, potrebbe eliminare la risorsa.

Più insidioso: alcuni framework web trattano PUT e POST come intercambiabili, o accettano GET con body (violando HTTP spec). Questo crea ambiguità exploitabile: un firewall potrebbe permettere GET (assumendo read-only) ma il server processa il body come write operation.

Testare verb tampering richiede fuzzing sistematico di tutti i verbi HTTP su ogni endpoint, verificando non solo status code (200 OK vs 405 Method Not Allowed) ma anche side effects (la risorsa è stata modificata/eliminata?).

#### 1.2.5 Caching Issues e Information Leakage

HTTP caching è progettato per performance: proxy, CDN, e browser cachano risposte GET per ridurre latency. REST sfrutta questo tramite header `Cache-Control`, `ETag`, `Expires`.

Il rischio emerge quando risposte contenenti dati sensibili vengono cachate erroneamente. Un errore tipico: API ritorna dati utente con header `Cache-Control: public, max-age=3600`. Un proxy condiviso (corporate proxy, CDN) cacha la risposta e la serve a utenti diversi, causando information leakage.

Questo è particolarmente insidioso in API che usano autenticazione basata su cookie. Il browser allega automaticamente cookie nelle richieste, ma proxy HTTP vedono solo URL e header standard. Se l'URL non contiene identificatori utente (esempio: `/api/profile` invece di `/api/users/123`), il proxy non può differenziare richieste di utenti diversi e serve la stessa risposta cachata a tutti.

Rilevare caching issue richiede analizzare header HTTP di risposta, verificare presenza di `Cache-Control: private` per endpoint sensibili, e testare con proxy intermediari.

### 1.3 Sfide di Testing Specifiche

REST è il protocollo più testato e documentato, eppure presenta sfide specifiche che emergono dalla sua natura decentralizzata e schema-less.

#### 1.3.1 Endpoint Proliferation e Shadow API

Ogni risorsa in REST richiede endpoint separati. Un'applicazione media con 20 entità (User, Product, Order, Payment, etc.) e versionamento (`/v1/`, `/v2/`) può facilmente avere 100+ endpoint. Questa proliferazione crea difficoltà di discovery.

Shadow API sono endpoint non documentati ma ancora attivi: versioni vecchie (`/v1/`) non deprecate, endpoint di debug (`/api/debug/users`), endpoint admin dimenticati (`/api/admin/backup`). Scanner tradizionali basati su wordlist (Nikto, Dirb) trovano solo endpoint common. Un framework moderno deve:

- Analizzare file OpenAPI/Swagger (se disponibili)  
- Crawl HTML e JavaScript per identificare chiamate API  
- Fuzzing intelligente basato su pattern (se esiste `/users`, provare `/products`, `/orders`)  
- Analizzare response per identificare link HATEOAS (Hypermedia as the Engine of Application State)

HATEOAS è un principio REST spesso ignorato: risposte dovrebbero includere link a risorse correlate. Esempio:

GET /users/123

{

  "id": 123,

  "name": "Alice",

  "\_links": {

    "orders": "/users/123/orders",

    "profile": "/users/123/profile"

  }

}

Un crawler può seguire questi link per scoprire endpoint. Tuttavia, HATEOAS è raramente implementato, rendendo discovery più difficile.

#### 1.3.2 Content Negotiation e Testing Combinatoriale

Lo stesso endpoint può comportarsi diversamente basandosi su header Accept. Un endpoint potrebbe ritornare JSON per `Accept: application/json`, XML per `Accept: application/xml`, o HTML per `Accept: text/html`. Ogni formato può avere parser diversi con vulnerabilità specifiche (XXE in XML parser, XSS in HTML rendering).

Testing completo richiede testare ogni endpoint con ogni Content-Type supportato, moltiplicando esponenzialmente il numero di test. Se un'API ha 100 endpoint e supporta 3 formati, servono 300 test solo per coverage basica.

#### 1.3.3 HTTP/2 e Multiplexing Invisibile

REST moderno opera su HTTP/2, che introduce **multiplexing**: richieste multiple su una singola connessione TCP, inviate in parallelo. Dal punto di vista del protocollo applicativo REST, nulla cambia. Ma dal punto di vista del testing, tool HTTP/1.1-based (la maggioranza) non vedono il multiplexing.

Un client malevolo può inviare 1000 richieste HTTP/2 simultanee su una connessione, ma un tool di monitoring HTTP/1.1 vede solo "1 connessione aperta". Questo nasconde attacchi di resource exhaustion e complica rate limiting (limitare richieste per connessione non funziona con HTTP/2).

Testing HTTP/2 richiede tool specializzati (curl con `--http2`, h2load per load testing) e verifica che rate limiting sia applicato per richiesta, non per connessione.

---

## 2\. GRAPHQL

### 2.1 Meccanica del Protocollo

GraphQL rivoluziona il modello REST eliminando la proliferazione di endpoint: tutta l'interazione avviene attraverso un unico endpoint (tipicamente `/graphql`) che accetta query in un linguaggio specifico del dominio. Il client specifica esattamente quali dati desidera, e il server ritorna solo quei dati, risolvendo il problema di over-fetching di REST.

Il protocollo si basa su uno **schema** fortemente tipizzato definito in GraphQL SDL (Schema Definition Language). Lo schema dichiara tutti i tipi disponibili (User, Product, Order), i loro campi, e le operazioni possibili (query per lettura, mutation per scrittura, subscription per aggiornamenti real-time).

Un esempio di query GraphQL richiede nome ed email di un utente e titoli dei suoi post:

query GetUser {

  user(id: "123") {

    name

    email

    posts {

      title

    }

  }

}

Il server riceve questa query come payload JSON in una richiesta HTTP POST:

POST /graphql

Content-Type: application/json

{

  "query": "query GetUser { user(id: \\"123\\") { name email posts { title } } }",

  "variables": {},

  "operationName": "GetUser"

}

Il server GraphQL esegue una pipeline strutturata per processare la query:

\[Client invia query\]

    ↓

\[GraphQL Server \- Parsing\]

    ↓ (Costruzione Abstract Syntax Tree \- AST)

\[Validation\]

    ↓ (Verifica che query sia sintatticamente valida)

    ↓ (Verifica che campi esistano nello schema)

\[Execution\]

    ↓ (Resolver per campo "user" → query database)

    ↓ (Resolver per campo "posts" → query posts table)

    ↓ (Composizione risposta)

\[Response\]

    ← (JSON con solo campi richiesti)

La fase di **parsing** trasforma la stringa query in un Abstract Syntax Tree, una rappresentazione strutturata ad albero. Questo AST viene poi validato contro lo schema: se la query richiede un campo non esistente (esempio: `user { invalidField }`), il server ritorna errore in questa fase, prima di eseguire qualsiasi logica.

La fase di **execution** è quella più complessa. GraphQL usa **resolver functions**: ogni campo dello schema ha una funzione che sa come recuperare quel dato. Il resolver per `user(id: "123")` potrebbe fare una query SQL `SELECT * FROM users WHERE id = 123`. Il resolver per `posts` (nested dentro `user`) riceve l'oggetto user e fa un'altra query `SELECT * FROM posts WHERE user_id = 123`.

\[Fonte: Baeldung \- REST vs GraphQL vs gRPC \- https://www.baeldung.com/rest-vs-graphql-vs-grpc\]

Questo modello resolver-based introduce il famoso **N+1 problem**: se una query richiede 100 user e per ognuno i loro posts, GraphQL esegue 1 query per gli users \+ 100 query per i posts (una per user), generando 101 query database. La soluzione è **DataLoader**, un meccanismo di batching che accumula richieste e le esegue in batch, ma richiede implementazione esplicita.

\[Fonte: LogRocket Blog \- GraphQL vs gRPC vs REST \- https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/\]

GraphQL supporta anche **introspection**: il client può interrogare il server per ottenere l'intero schema. Questo facilita tool come GraphQL Playground e GraphiQL (IDE interattivi), ma espone la struttura completa dell'API a chiunque.

### 2.2 Vulnerabilità Strutturali

La potenza di GraphQL (flessibilità delle query, schema auto-documentante) introduce rischi specifici assenti in REST.

#### 2.2.1 Query Complexity Attacks

GraphQL permette query annidate arbitrariamente profonde. Un attaccante può crafted query che esplodono esponenzialmente:

query MaliciousQuery {

  users {

    posts {

      comments {

        author {

          posts {

            comments {

              author {

                posts {

                  \# ... nesting infinito

                }

              }

            }

          }

        }

      }

    }

  }

}

Ogni livello di nesting moltiplica il numero di resolver eseguiti. Una query con 10 livelli di nesting può generare milioni di query database, causando Denial of Service (DoS) e database overload.

Il problema è strutturale: GraphQL non impone limiti di profondità o complessità per default. È responsabilità del server implementare **query complexity analysis**: assegnare un costo computazionale a ogni campo, calcolare il costo totale della query, e rifiutare query oltre una soglia.

Scanner DAST tradizionali non comprendono la semantica GraphQL. Non possono costruire query annidate né calcolare complessità. Testare questo richiede un client GraphQL-aware che generi query di complessità crescente e misuri response time e carico server.

\[Fonte: LogRocket Blog \- GraphQL vs gRPC vs REST \- https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/\]

#### 2.2.2 Introspection Abuse e Schema Leakage

GraphQL espone l'intero schema tramite introspection query:

query IntrospectionQuery {

  \_\_schema {

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

Questo ritorna tutti i tipi, campi, e relazioni. Per un attaccante, è equivalente a ottenere il source code della struttura dati. L'introspection rivela:

- Campi sensibili (esempio: `User.salary`, `User.ssn`)  
- Endpoint admin (esempio: `Mutation.deleteAllUsers`)  
- Relazioni nascoste (esempio: `User.internalNotes`)

Best practice è disabilitare introspection in produzione. Tuttavia, studi documentano che questa mitigazione è **largamente inefficace**. Anche con introspection disabilitata, il schema rimane ricostruibile tramite **field suggestion**.

Quando una query richiede un campo inesistente, GraphQL ritorna un errore utile:

query { user { invalidFieldName } }

Error: "Cannot query field 'invalidFieldName' on type 'User'. 

        Did you mean 'username', 'email', or 'firstName'?"

Questa feature di usability espone campi validi. Un attaccante può iterare su nomi comuni (id, name, email, password, admin, etc.) e ricostruire lo schema completo tramite errori. Il tool open-source **Clairvoyance** automatizza questo processo.

\[Fonte: Cyber Chief \- Mastering GraphQL Introspection \- https://www.cyberchief.ai/2024/11/graphql-security.html\]

Documentazione esplicita conferma: "While disabling introspection may seem like a security measure, it's largely ineffective. Your GraphQL schema remains discoverable through Field Suggestion".

Il problema è strutturale: GraphQL è progettato per developer experience, fornendo errori dettagliati. Disabilitare field suggestion richiederebbe errori generici ("invalid query"), degradando l'esperienza per client legittimi.

#### 2.2.3 Batching e Aliasing per Rate Limiting Bypass

GraphQL supporta **batching**: inviare query multiple in una singola richiesta HTTP. Supporta anche **aliasing**: rinominare campi per evitare conflitti.

Combinando queste feature, un attaccante può bypassare rate limiting HTTP-based:

query BatchAttack {

  user1: user(id: 1\) { name email }

  user2: user(id: 2\) { name email }

  user3: user(id: 3\) { name email }

  ...

  user1000: user(id: 1000\) { name email }

}

Questa è **una singola richiesta HTTP POST**, che un rate limiter tradizionale conta come "1 request". Ma il backend esegue 1000 query. Se il rate limit è "100 requests per second", l'attaccante può inviare 100 batch da 1000 query \= 100.000 operazioni per secondo, superando di 1000x il limite previsto.

\[Fonte: Escape Tech \- How to Secure GraphQL APIs \- https://escape.tech/blog/how-to-secure-graphql-apis/\]

Documentazione tecnica conferma: "GraphQL APIs allow batching and aliasing, where multiple queries can be sent in a single HTTP request. This can be exploited to bypass rate limits set at the gateway or firewall level."

La mitigazione richiede un gateway GraphQL-aware che conti operazioni GraphQL, non HTTP requests. Ma questo richiede parsing del payload, calcolo del costo computazionale, tracking per client. Infrastrutture tradizionali (Nginx, AWS API Gateway standard) non hanno questa capacità nativa.

#### 2.2.4 Authorization Granularity Mismatch

REST applica authorization a livello endpoint: `/users/{id}` può avere una policy "user può accedere solo al proprio ID". GraphQL applica authorization a livello campo (field-level authorization).

Una query GraphQL può richiedere:

query {

  user(id: 123\) {

    name        \# pubblico

    email       \# pubblico

    salary      \# sensibile \- solo HR

    ssn         \# sensibile \- solo admin

  }

}

Il server deve verificare per ogni campo se il client ha permesso. Se il resolver di `salary` non implementa authorization, quel campo viene esposto anche a client non autorizzati.

Il problema è che authorization è implementata nel codice applicativo (resolver functions), non dichiarativamente nello schema. Un developer può dimenticare di aggiungere check di autorizzazione a un resolver, esponendo il campo. Scanner automatici non rilevano questo perché richiederebbe:

- Autenticazione con ruoli diversi (user normale, HR, admin)  
- Query dello stesso oggetto con tutti i campi  
- Confronto di quali campi sono ritornati a ciascun ruolo  
- Identificazione di campi esposti impropriamente

Questo workflow multi-step con correlation tra utenti non è supportato da tool DAST generici.

### 2.3 Sfide di Testing Specifiche

GraphQL richiede approcci di testing radicalmente diversi da REST perché la superficie di attacco è definita dallo schema, non dagli URL.

#### 2.3.1 Schema Discovery e Coverage

Discovery in GraphQL significa ottenere lo schema completo. Se introspection è abilitata, è triviale. Se disabilitata, serve usare field suggestion brute-forcing (tool Clairvoyance).

Una volta ottenuto lo schema, coverage significa testare:

- Ogni query con ogni combinazione di campi  
- Ogni mutation con input validi e invalidi  
- Ogni relazione (nesting tra tipi)

Questo è combinatorialmente esplosivo. Uno schema con 50 tipi e 500 campi totali ha miliardi di query possibili. Testing esaustivo è impraticabile. Serve prioritization:

- Testare campi sensibili (password, admin, internal)  
- Testare mutation distruttive (delete, update)  
- Testare query complesse (deep nesting)

#### 2.3.2 Mutation Testing e Side Effects

Le mutation GraphQL modificano dati server-side. A differenza di query (idempotenti), mutation hanno side effects permanenti.

Testing mutation richiede:

- Setup di stato iniziale (creare record test)  
- Esecuzione mutation  
- Verifica side effect (record effettivamente modificato?)  
- Teardown (pulire dati test)

Questo richiede integrazione con database e orchestrazione complessa. Tool fuzzer generici che inviano input random possono danneggiare database di produzione se non isolati.

#### 2.3.3 Subscription e WebSocket

GraphQL subscription permettono aggiornamenti real-time tramite WebSocket. Il client si sottoscrive a eventi:

subscription OnCommentAdded {

  commentAdded(postId: "123") {

    id

    content

    author {

      name

    }

  }

}

Quando un nuovo commento viene aggiunto, il server push l'aggiornamento via WebSocket.

Testing subscription richiede:

- Stabilire connessione WebSocket persistente  
- Inviare subscription  
- Generare evento che triggera subscription (esempio: creare commento)  
- Verificare che update sia ricevuto via WebSocket

Questo workflow event-driven con connessioni stateful non è gestibile da scanner HTTP stateless.

---

## 3\. GRPC

### 3.1 Meccanica del Protocollo

gRPC rappresenta un cambio paradigmatico rispetto a REST e GraphQL: invece di lavorare con risorse o query, gRPC implementa Remote Procedure Call (RPC), permettendo a un client di invocare funzioni su un server remoto come se fossero locali.

Il protocollo si basa su due pilastri tecnologici: **HTTP/2** per il trasporto e **Protocol Buffers** (protobuf) per la serializzazione dati. Questa combinazione fornisce performance eccezionali ma introduce complessità e opacità.

Il workflow di sviluppo gRPC inizia definendo un file `.proto` che specifica il contratto:

syntax \= "proto3";

message UserRequest {

  int32 user\_id \= 1;

}

message User {

  int32 id \= 1;

  string name \= 2;

  string email \= 3;

}

service UserService {

  rpc GetUser(UserRequest) returns (User);

}

Questo file viene poi processato dal compilatore `protoc` che genera automaticamente client e server stub in vari linguaggi (Go, Java, Python, C++, etc.). Il codice generato nasconde completamente i dettagli di serializzazione e networking.

\[Fonte: GeeksforGeeks \- GraphQL vs REST vs SOAP vs gRPC \- https://www.geeksforgeeks.org/blogs/graphql-vs-rest-vs-soap-vs-grpc/\]

**Protocol Buffers** è un formato binario estremamente efficiente. A differenza di JSON (text-based, verboso), protobuf serializza dati in formato compatto usando varint encoding (interi rappresentati con numero minimo di byte) e field tags (numeri invece di nomi stringa). Un messaggio protobuf è tipicamente 3-10x più piccolo del JSON equivalente.

Il processo di serializzazione:

\[Oggetto User in memoria\]

  User { id: 123, name: "Alice", email: "alice@example.com" }

    ↓

\[Protobuf Encoder\]

    ↓ (Field 1 (id): varint 123 → bytes: 08 7B)

    ↓ (Field 2 (name): string "Alice" → bytes: 12 05 41 6C 69 63 65\)

    ↓ (Field 3 (email): string → bytes: ...)

\[Payload Binario\]

  08 7B 12 05 41 6C 69 63 65 1A 13 61 6C 69 63 65 40 65 78 61 6D 70 6C 65 2E 63 6F 6D

Questo payload binario non è human-readable, ma è processabile in microsecondi con allocation di memoria minima.

**HTTP/2** fornisce il layer di trasporto. gRPC sfrutta HTTP/2 multiplexing (richieste multiple simultanee su una connessione TCP), server push, e header compression (HPACK).

Il flusso di una richiesta gRPC:

\[gRPC Client\]

    ↓ (Serializzazione request in protobuf binary)

\[HTTP/2 Stream\]

    ↓ (Header frame: :method POST, :path /UserService/GetUser)

    ↓ (Data frame: protobuf payload)

    ↓ (TLS encryption obbligatorio in produzione)

\[gRPC Server\]

    ↓ (Deserializzazione protobuf)

    ↓ (Esecuzione business logic)

    ↓ (Serializzazione response)

\[Client\]

    ← (HTTP/2 Data frame con protobuf response)

gRPC supporta quattro tipi di comunicazione:

**Unary RPC**: client invia una richiesta, server ritorna una risposta (come REST).

**Server Streaming**: client invia una richiesta, server ritorna uno stream di risposte (esempio: download file chunked, log streaming).

**Client Streaming**: client invia uno stream di richieste, server ritorna una risposta (esempio: upload file).

**Bidirectional Streaming**: client e server inviano stream in entrambe le direzioni simultaneamente (esempio: chat, gaming real-time).

\[Fonte: Baeldung \- REST vs GraphQL vs gRPC \- https://www.baeldung.com/rest-vs-graphql-vs-grpc\]

### 3.2 Vulnerabilità Strutturali

La natura binaria e stream-oriented di gRPC introduce vulnerabilità strutturali diverse da protocolli text-based.

#### 3.2.1 Deserialization Attacks

Protobuf, come ogni formato di serializzazione, è vulnerabile a attacchi se il payload è crafted maliziosamente. CVE documentati includono:

**CVE-2021-22570**: Heap overflow in protobuf C++ parser. Un payload malformato con field tag molto grande causava buffer overflow, potenzialmente permettendo remote code execution.

**CVE-2022-1941**: Denial of Service in protobuf C++ parser. Payload con messaggi nested profondamente causavano stack overflow.

\[Fonte: CVE Database \- https://cve.mitre.org/\]

Questi attacchi sfruttano bug nei parser, ma il problema fondamentale è che protobuf binario è opaco. Un WAF (Web Application Firewall) o IDS (Intrusion Detection System) non può ispezionare il payload senza deserializzarlo completamente. Questo significa che payloads malevoli passano inosservati attraverso layer di sicurezza tradizionali.

Inoltre, a differenza di JSON (dove un parser strict rifiuta syntax errors), protobuf usa **unknown fields**: se un messaggio contiene field tag non definiti nello schema, il parser li ignora silenziosamente. Questo era una feature per retrocompatibilità (aggiungere campi senza rompere client vecchi), ma può nascondere tentativi di injection.

#### 3.2.2 Stream Exhaustion e Resource Leaks

gRPC streaming permette connessioni long-lived con messaggi illimitati. Un client malevolo può aprire stream bidirectional e inviare messaggi infinitamente senza chiudere mai lo stream, causando resource exhaustion.

HTTP/2 fornisce **flow control** per prevenire questo: ogni stream ha una finestra di crediti (WINDOW\_UPDATE frames) che limita quanti dati possono essere inviati prima di ricevere acknowledgment. Tuttavia, la configurazione di flow control è complessa e spesso lasciata a valori default permissivi.

Un attaccante può:

- Aprire N stream paralleli (HTTP/2 permette fino a 128 stream concorrenti per connessione default)  
- Inviare messaggi lentamente (sotto rate limit per singolo stream)  
- Ma complessivamente generare traffico elevato (N stream × messages/stream)

Server che non implementano timeout su stream lifetime o limiti sul numero totale di messaggi per stream sono vulnerabili.

\[Fonte: LogRocket Blog \- GraphQL vs gRPC vs REST \- https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/\]

#### 3.2.3 Metadata Injection

gRPC metadata (equivalente a HTTP headers) possono contenere injection attacks. Metadata sono coppie chiave-valore arbitrarie inviate con ogni richiesta:

metadata \= {

  "authorization": "Bearer \<JWT\>",

  "x-custom-header": "\<script\>alert(1)\</script\>"

}

Se il server logga metadata senza sanitization, è vulnerabile a log injection. Se metadata vengono riflesse in risposta HTML, è vulnerabile a XSS. Questi sono attacchi classici, ma aggravati dal fatto che protobuf payload è binario e i tool di sicurezza si concentrano su quello, trascurando metadata text-based.

#### 3.2.4 Authentication Bypass

gRPC non ha autenticazione nativa. È responsabilità del developer implementarla, tipicamente tramite JWT in metadata. Un errore comune è validare il token solo su alcune RPC methods, non tutte.

Esempio: `GetUser` richiede autenticazione, ma `ListPublicUsers` no. Un attaccante potrebbe chiamare `ListPublicUsers` senza token e ottenere dati che pensavi fossero pubblici, ma contengono PII (Personally Identifiable Information).

Inoltre, gRPC non ha un meccanismo standard per session management o token refresh. Developer implementano soluzioni custom, spesso con vulnerabilità.

### 3.3 Sfide di Testing Specifiche

gRPC è il protocollo più difficile da testare con tool tradizionali perché richiede capacità specializzate.

#### 3.3.1 Binary Protocol Opacity

Burp Suite e OWASP ZAP sono progettati per HTTP/1.1 text-based. Vedono traffico gRPC come stream binari incomprensibili. Burp ha plugin per decodificare protobuf, ma richiedono file `.proto` \- che potrebbe non essere disponibile.

Senza schema, un tester vede solo:

POST /UserService/GetUser

Content-Type: application/grpc

\[binary data: 08 7B 12 05 ...\]

Non può capire quali field esistono, quali valori sono validi, come costruire payload di test. Questo rende fuzzing quasi impossibile: inviare byte random genera sempre errori di deserializzazione, non rivela vulnerabilità logiche.

#### 3.3.2 Reflection API Discovery

gRPC supporta **server reflection**: il server può esporre il proprio schema (equivalente a GraphQL introspection). Il tool `grpcurl` usa reflection per elencare servizi e methods:

grpcurl \-plaintext localhost:9090 list

\# Output:

grpc.reflection.v1alpha.ServerReflection

UserService

Tuttavia, reflection è **disabled di default in produzione** (best practice security). Senza reflection, discovery richiede:

- Ottenere file `.proto` da repository Git (se accessibile)  
- Reverse engineering di client binaries  
- Social engineering (chiedere a developer)

Non esiste soluzione automatizzata per discovery senza reflection.

\[Fonte: gRPC Documentation \- Server Reflection \- https://grpc.io/docs/guides/reflection/\]

#### 3.3.3 TLS Enforcement e MITM

gRPC production usa **sempre TLS** (plaintext è solo per development). Questo previene MITM (Man-in-the-Middle) attacks, ma complica testing.

Tool come Burp richiedono:

- Installare certificato Burp trusted sul client  
- Configurare client gRPC per accettare certificati custom  
- Intercettare traffico con TLS decryption

Questo workflow è complesso e non funziona per client che implementano certificate pinning.

Inoltre, gRPC non è supportato nativamente da browser. Testing richiede client dedicati (`grpcurl`, Postman, BloomRPC), tool CLI, o scrivere script custom.

---

## 4\. SOAP (SIMPLE OBJECT ACCESS PROTOCOL)

### 4.1 Meccanica del Protocollo

SOAP è il veterano dei protocolli API, sviluppato alla fine degli anni '90 come standard per comunicazione enterprise. A differenza di protocolli moderni (REST JSON-based, gRPC protobuf), SOAP è esclusivamente XML-based e trasporta ogni messaggio in un envelope strutturato.

L'architettura SOAP si basa su tre componenti:

**SOAP Envelope**: wrapper XML che contiene l'intero messaggio. Definito da namespace standard e struttura rigida.

**SOAP Header** (opzionale): contiene metadata come autenticazione (WS-Security), routing information, transaction context.

**SOAP Body**: contiene il payload effettivo, tipicamente una chiamata a method con parametri.

Un messaggio SOAP tipico segue questa struttura:

\<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"\>

  \<soap:Header\>

    \<wsse:Security xmlns:wsse="..."\>

      \<wsse:UsernameToken\>

        \<wsse:Username\>alice\</wsse:Username\>

        \<wsse:Password\>secret\</wsse:Password\>

      \</wsse:UsernameToken\>

    \</wsse:Security\>

  \</soap:Header\>

  \<soap:Body\>

    \<m:GetUser xmlns:m="http://example.com/user"\>

      \<m:UserId\>123\</m:UserId\>

    \</m:GetUser\>

  \</soap:Body\>

\</soap:Envelope\>

SOAP è protocol-agnostic (può operare su HTTP, SMTP, TCP), ma nella pratica è quasi sempre trasportato su HTTP POST.

\[Fonte: GeeksforGeeks \- GraphQL vs REST vs SOAP vs gRPC \- https://www.geeksforgeeks.org/blogs/graphql-vs-rest-vs-soap-vs-grpc/\]

Il contratto SOAP è definito in **WSDL (Web Services Description Language)**, un documento XML che specifica:

- Quali operazioni sono disponibili (methods)  
- Quali input accettano (tipi XML)  
- Quali output ritornano  
- Dove il servizio è hosted (endpoint URL)

Un client SOAP genera codice stub analizzando il WSDL, similmente a gRPC con file `.proto`.

La WS-\* stack (Web Services specifications) estende SOAP con capacità enterprise:

- **WS-Security**: autenticazione, firma digitale XML, encryption  
- **WS-ReliableMessaging**: garantisce delivery di messaggi anche in caso di network failure  
- **WS-Addressing**: routing messaggi attraverso intermediari  
- **WS-Policy**: dichiarazioni di capability e requirements

Questa ricchezza di feature rende SOAP potente per scenari enterprise complessi (transazioni distribuite, messaging affidabile), ma anche estremamente complesso.

\[Fonte: Frontiers \- Cloud Security and SOAP XML Vulnerabilities \- https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1595624/full\]

### 4.2 Vulnerabilità Strutturali

SOAP, essendo basato su XML, eredita tutte le vulnerabilità di XML parsing, amplificate dalla complessità del protocollo.

#### 4.2.1 XML External Entity (XXE) Injection

XML supporta **entity**: alias definiti nel Document Type Definition (DTD) che vengono espansi dal parser. Le entity esterne permettono di referenziare file locali o URL remote.

Un attaccante può crafted SOAP message con XXE per leggere file server:

\<\!DOCTYPE foo \[

  \<\!ENTITY xxe SYSTEM "file:///etc/passwd"\>

\]\>

\<soap:Envelope\>

  \<soap:Body\>

    \<m:GetUser\>

      \<m:UserId\>\&xxe;\</m:UserId\>

    \</m:GetUser\>

  \</soap:Body\>

\</soap:Envelope\>

Quando il parser espande `&xxe;`, legge `/etc/passwd` e lo include nel messaggio processato. Se il server risponde con errore che include il valore di UserId, l'attaccante ottiene il contenuto del file.

XXE può anche causare SSRF (Server-Side Request Forgery):

\<\!ENTITY xxe SYSTEM "http://internal-admin-panel.local/api/delete-all"\>

Il parser XML esegue una richiesta HTTP alla URL interna, bypassando firewall perimetrale.

Statistiche documentano che **21% dei web service breaches** coinvolgono XXE.

\[Fonte: Moldstud \- Common SOAP Security Issues \- https://moldstud.com/articles/p-common-soap-security-issues-understanding-vulnerabilities-and-best-practices\]

La mitigazione richiede disabilitare entity external nel parser XML, ma questo richiede configuration esplicita (non è default in molte librerie) e molti developer non sono consapevoli del rischio.

#### 4.2.2 XML Signature Wrapping (XSW)

WS-Security permette firmare digitalmente messaggi SOAP tramite XML Signature. L'idea: il sender calcola hash del messaggio e lo firma con chiave privata. Il receiver verifica la firma con chiave pubblica.

XML Signature Wrapping è un attacco che manipola la struttura del messaggio mantenendo la firma valida. Il meccanismo sfrutta il fatto che XML Signature referenzia elementi tramite ID, non posizione.

Scenario semplificato:

\<soap:Body\>

  \<SignedData Id="data1"\>

    \<Operation\>ReadBalance\</Operation\>

  \</SignedData\>

  \<Signature\>

    \<Reference URI="\#data1"\>...\</Reference\>

  \</Signature\>

\</soap:Body\>

Attaccante aggiunge elemento non firmato prima dell'elemento firmato:

\<soap:Body\>

  \<UnsignedData\>

    \<Operation\>TransferMoney\</Operation\>

  \</UnsignedData\>

  \<SignedData Id="data1"\>

    \<Operation\>ReadBalance\</Operation\>

  \</SignedData\>

  \<Signature\>

    \<Reference URI="\#data1"\>...\</Reference\>

  \</Signature\>

\</soap:Body\>

Se il server verifica solo la firma (che è ancora valida per `#data1`), ma processa il primo elemento `<UnsignedData>`, l'attaccante esegue operazione non autorizzata.

\[Fonte: Bright Security \- SOAP API Security \- https://appsentinels.ai/blog/soap-api-security/\]

Questo exploit ha compromesso sistemi bancari e enterprise reali. La mitigazione richiede verificare non solo la firma, ma anche che TUTTO il contenuto rilevante sia firmato.

#### 4.2.3 XML Bomb (Billion Laughs Attack)

XML entity possono essere definite ricorsivamente, causando espansione esponenziale:

\<\!DOCTYPE lolz \[

  \<\!ENTITY lol "lol"\>

  \<\!ENTITY lol2 "\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;\&lol;"\>

  \<\!ENTITY lol3 "\&lol2;\&lol2;\&lol2;\&lol2;\&lol2;\&lol2;\&lol2;\&lol2;\&lol2;\&lol2;"\>

  \<\!ENTITY lol4 "\&lol3;\&lol3;\&lol3;\&lol3;\&lol3;\&lol3;\&lol3;\&lol3;\&lol3;\&lol3;"\>

  ...

  \<\!ENTITY lol9 "\&lol8;\&lol8;\&lol8;\&lol8;\&lol8;\&lol8;\&lol8;\&lol8;\&lol8;\&lol8;"\>

\]\>

\<soap:Body\>\&lol9;\</soap:Body\>

Ogni entità espande la precedente 10x. `lol9` espande a 10^9 volte "lol" \= 3 GB di stringa in memoria, da pochi KB di XML.

Questo causa memory exhaustion e DoS immediato. Il parser tenta di allocare gigabyte di RAM e crasha.

\[Fonte: Frontiers \- Cloud Security and SOAP XML Vulnerabilities \- https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1595624/full\]

#### 4.2.4 SQL Injection via SOAP

Nonostante SOAP usi XML (non SQL), SQL injection è possibile se il server concatena valori XML in query SQL senza sanitization:

\<soap:Body\>

  \<m:GetUser\>

    \<m:UserId\>123' OR '1'='1\</m:UserId\>

  \</m:GetUser\>

\</soap:Body\>

Se il server esegue:

query \= "SELECT \* FROM users WHERE id \= '" \+ userId \+ "'"

L'injection bypassa autenticazione. Questo è classico SQL injection, ma wrappato in XML.

\[Fonte: Infosec Institute \- Mastering SOAP Request Automation \- https://resources.infosecinstitute.com/topic/soap-attack-2/\]

### 4.3 Sfide di Testing Specifiche

SOAP è il protocollo più complesso da testare perché combina XML parsing, WS-\* stack, e WSDL discovery.

#### 4.3.1 WSDL Discovery e Parsing

Discovery SOAP inizia trovando il WSDL endpoint:

GET /service?wsdl

Se disponibile, il WSDL è un documento XML (spesso migliaia di righe) che definisce operazioni disponibili. Parser WSDL automatici (SoapUI, Postman) generano request template, ma WSDL può essere:

- Non pubblicato (security by obscurity)  
- Custom path (non standard `?wsdl`)  
- Protetto da autenticazione

Senza WSDL, testing è black-box completo: non si sa quali operazioni esistano.

#### 4.3.2 WS-Security Complexity

Testare autenticazione SOAP richiede costruire header WS-Security validi con UsernameToken, Timestamp, Signature. Questo è manuale e error-prone. Tool automatizzati devono supportare:

- XML Signature generation  
- XML Encryption  
- SAML token handling

Pochi scanner open-source supportano questo. SoapUI lo fa, ma richiede configuration dettagliata.

#### 4.3.3 XML Parsing Attacks

Testare XXE, XML Bomb, XSW richiede crafting payloads XML malformati ma sintatticamente validi. Scanner generici inviano payloads XXE standard, ma potrebbero non coprire varianti (external entity in attribute, entity in namespace URI).

Fuzzing XML richiede comprendere grammatica XML, namespaces, entity, DTD. Tool specializzati (Fuzzdb XML payloads, XXEinjector) esistono, ma integrarli in workflow SOAP è complesso.

---

## 5\. WEBSOCKET

### 5.1 Meccanica del Protocollo

WebSocket rivoluziona il modello HTTP request-response introducendo comunicazione **full-duplex persistente**: client e server possono inviare messaggi indipendentemente in qualsiasi momento, senza overhead di apertura/chiusura connessione per ogni messaggio.

Il protocollo inizia con un **handshake HTTP** che "upgrade" la connessione a WebSocket. Il client invia richiesta GET speciale:

GET /chat HTTP/1.1

Host: server.example.com

Upgrade: websocket

Connection: Upgrade

Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==

Sec-WebSocket-Version: 13

Il server risponde:

HTTP/1.1 101 Switching Protocols

Upgrade: websocket

Connection: Upgrade

Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=

Dopo questo handshake, la connessione TCP rimane aperta e viene usata per inviare **WebSocket frames** in entrambe le direzioni.

\[Fonte: PortSwigger \- Testing for WebSockets Vulnerabilities \- https://portswigger.net/web-security/websockets\]

Un WebSocket frame ha struttura binaria:

Frame Header (2-14 bytes):

  \- FIN bit: ultimo frame di messaggio multi-frame

  \- Opcode (4 bits): tipo frame (text=1, binary=2, ping=9, pong=10, close=8)

  \- Mask bit: client MUST mask payload

  \- Payload length (7 bits, 16 bits, o 64 bits per payload grandi)

  \- Masking key (32 bits, solo se Mask=1)

Payload data (variabile)

Il **masking** è obbligatorio per frame client→server (RFC 6455 requirement). Ogni byte payload è XOR con masking key rotante. Questo previene cache poisoning: proxy HTTP che cachano GET request potrebbero confondere frame WebSocket con HTTP response se non maskati.

\[Fonte: Wikipedia \- Server-Sent Events \- https://en.wikipedia.org/wiki/Server-sent\_events\]

Il flusso di messaggi in WebSocket è asincrono:

\[Client stabilisce connessione WebSocket\]

    ↓ (HTTP Upgrade handshake)

\[Connessione Aperta \- Persistent\]

    ↓

\[Client invia frame text: {"type": "message", "text": "Hello"}\]

    ↓

\[Server processa, risponde: {"type": "ack", "id": 123}\]

    ↓

\[Server invia push unprompted: {"type": "notification", "data": "..."}\]

    ↓

\[Client risponde: {"type": "received"}\]

    ↓ (Connessione rimane aperta indefinitamente)

    ↓ (Migliaia di messaggi scambiati senza overhead handshake)

\[Client o Server inviano Close frame\]

Questa persistenza elimina latency di connessione HTTP (TLS handshake, TCP slow start), ma introduce stateful complexity.

WebSocket non impone formato payload: può essere text (tipicamente JSON), binary (protobuf, MessagePack), o arbitrario. Non c'è schema obbligatorio o validation built-in.

### 5.2 Vulnerabilità Strutturali

La natura stateful e bi-directional di WebSocket introduce rischi assenti in protocolli stateless.

#### 5.2.1 Cross-Site WebSocket Hijacking (CSWSH)

WebSocket handshake è HTTP, quindi soggetto a Same-Origin Policy browser. Tuttavia, WebSocket NON esegue **CORS preflight**: il browser invia direttamente la richiesta upgrade, includendo cookies.

Un attaccante può creare pagina malevola che apre WebSocket verso vittima:

Script su evil.com:

var ws \= new WebSocket('wss://victim.com/chat');

ws.onmessage \= function(e) {

  // Leak messaggi vittima ad attacker server

  sendToAttacker(e.data);

};

Se `victim.com` non valida header `Origin` durante handshake, accetta la connessione. Il browser allega automaticamente cookies di sessione per `victim.com`, quindi WebSocket è autenticato come vittima.

L'attaccante riceve tutti i messaggi destinati alla vittima. Questo è equivalente a session hijacking completo.

\[Fonte: Pentest-Tools Blog \- Cross-Site WebSocket Hijacking \- https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh\]

La mitigazione richiede verificare header `Origin` server-side durante handshake:

if (request.headers.origin \!== 'https://victim.com') {

  return 403 Forbidden

}

Ma questo è implementation-dependent, non enforced dal protocollo. Molti developer non sono consapevoli del rischio.

Case study documentato: CVE-2024-26135 in MeshCentral (software remote management). CSWSH permetteva ad attaccante di controllare macchine remote autenticandosi come vittima.

\[Fonte: Praetorian \- MeshCentral CSWSH CVE-2024-26135 \- https://www.praetorian.com/blog/meshcentral-cross-site-websocket-hijacking-vulnerability/\]

#### 5.2.2 Injection Attacks via Frame Payload

Input via WebSocket frame non viene sanitizzato da browser (a differenza di form HTML dove browser previene alcuni XSS). Se il server ritrasmette payload a tutti client connessi (chat app), injection è triviale:

Client A invia frame:

{"message": "\<script\>document.location='http://evil.com?cookie='+document.cookie\</script\>"}

Server broadcast a tutti i client:

Clients ricevono e renderizzano il messaggio → XSS

Questo è **stored XSS**: payload malevolo persistito server-side e inviato a client futuri.

\[Fonte: Bright Security \- WebSocket Security Top 8 Vulnerabilities \- https://brightsec.com/blog/websocket-security-top-vulnerabilities/\]

Similmente, se server processa payload per query database:

{"action": "getUser", "userId": "123' OR '1'='1"}

SQL injection classica, ma via WebSocket invece di HTTP POST.

#### 5.2.3 Denial of Service Patterns

WebSocket apre molteplici vettori DoS:

**Connection exhaustion**: Aprire N connessioni WebSocket senza chiuderle. Server mantiene stato per ogni connessione (buffer, handler). Con abbastanza connessioni, server esaurisce file descriptors o memoria.

**Message flooding**: Inviare messaggi a rate elevatissimo su connessione singola. Se server processa ogni messaggio (esempio: broadcast a M client), carico moltiplicativo (N messages × M broadcasts).

**Ping/Pong abuse**: WebSocket supporta Ping frames (heartbeat) e Pong responses. Attaccante può inviare Ping infiniti, forzando server a rispondere con Pong, consumando bandwidth e CPU.

\[Fonte: Invicti \- WebSocket Security Best Practices \- https://www.invicti.com/blog/web-security/websocket-security-best-practices/\]

#### 5.2.4 Lack of Rate Limiting

Rate limiting HTTP tradizionale (X requests per second per IP) non si applica a WebSocket. Una singola connessione WebSocket (1 handshake HTTP) può inviare migliaia di messaggi.

Se rate limiting è applicato solo all'handshake (come in molti API Gateway), WebSocket bypassa completamente il controllo.

Implementare rate limiting per WebSocket richiede tracking application-level: messaggi per connessione, messaggi totali per client (aggregando connessioni multiple), payload size total.

\[Fonte: Cobalt \- Web Socket Vulnerabilities \- https://www.cobalt.io/blog/web-socket-vulnerabilites\]

### 5.3 Sfide di Testing Specifiche

WebSocket richiede tool stateful che mantengano connessioni persistenti e gestiscano messaggi asincroni.

#### 5.3.1 Stateful Connection Management

Scanner HTTP tradizionali (Nikto, Dirb) operano in ciclo: invia request, attendi response, chiudi connessione, prossima request. WebSocket richiede mantenere connessione aperta indefinitamente e gestire messaggi in entrambe direzioni simultaneamente.

Tool come Burp Suite hanno tab dedicato "WebSocket History" che cattura handshake e frame. Ma testing automatizzato richiede:

- Script che stabiliscono connessione  
- Inviano payload test  
- Ascoltano response asincrone  
- Correlano request/response (non c'è request ID nativo in WebSocket)

#### 5.3.2 Origin Validation Testing

Testare CSWSH richiede setup complesso:

- Deploy pagina HTML su dominio attacker-controlled  
- Pagina tenta aprire WebSocket verso target  
- Verificare se connessione è accettata (Origin non validato)

Questo non è automatizzabile con scanner standard. Richiede framework che può deployare server web temporaneo per hosting attack page.

#### 5.3.3 Protocol Fuzzing

Fuzzing WebSocket significa generare frame malformati:

- Opcode invalido (es. opcode=15, non definito)  
- Payload length mismatch (header dice 100 bytes, payload ha 50\)  
- Mask bit=0 per client→server (viola RFC)  
- Frame fragmentation abuse (FIN=0 infinite volte senza final frame)

Tool specializzati (WebSocket fuzzer, wsfuzzer) esistono, ma coverage è limitata. Fuzzing completo richiederebbe generare tutte combinazioni di bit nel frame header (2^64+ varianti).

---

## 6\. SERVER-SENT EVENTS (SSE)

### 6.1 Meccanica del Protocollo

Server-Sent Events fornisce streaming unidirezionale server→client tramite long-lived HTTP connection. A differenza di WebSocket (bidirezionale), SSE è simplex: client può solo ricevere, non inviare (oltre la richiesta iniziale).

Il meccanismo è semplice: client invia richiesta HTTP GET con header speciale:

GET /events HTTP/1.1

Host: example.com

Accept: text/event-stream

Cache-Control: no-cache

Server risponde con:

HTTP/1.1 200 OK

Content-Type: text/event-stream

Cache-Control: no-cache

Connection: keep-alive

Poi, invece di chiudere la connessione, server invia eventi continuamente:

data: {"message": "Hello"}

event: update

data: {"status": "active"}

id: 123

: comment (ignored by client, used for heartbeat)

data: line 1

data: line 2

Ogni evento è separato da doppia newline. Il campo `data` contiene payload (tipicamente JSON). Il campo `event` specifica tipo evento (opzionale). Il campo `id` permette resuming (client riconnette con `Last-Event-ID` header).

\[Fonte: MDN \- Using Server-Sent Events \- https://developer.mozilla.org/en-US/docs/Web/API/Server-sent\_events/Using\_server-sent\_events\]

Il browser fornisce API nativa `EventSource`:

const eventSource \= new EventSource('/events');

eventSource.onmessage \= (e) \=\> {

  console.log('Received:', e.data);

};

eventSource.addEventListener('update', (e) \=\> {

  console.log('Update:', e.data);

});

`EventSource` gestisce automaticamente riconnessione se la connessione cade. Dopo disconnect, tenta riconnessione con exponential backoff.

\[Fonte: Solita \- Server-Sent Events \- https://dev.solita.fi/2024/08/15/server-sent-event.html\]

Il flusso tipico:

\[Client: EventSource('/events')\]

    ↓ (HTTP GET)

\[Server\]

    ↓ (Response 200 OK, Content-Type: text/event-stream)

    ↓ (Connessione mantiene aperta indefinitamente)

    ↓

\[Server invia evento quando disponibile\]

    data: {"new\_comment": {...}}

    

\[Client riceve, triggera onmessage callback\]

    ↓

\[Server continua streaming per ore/giorni\]

    ↓

\[Se connessione drop (network issue)\]

\[EventSource auto-reconnect con Last-Event-ID\]

SSE ha limitazione browser: max 6 connessioni simultanee per domain (HTTP/1.1 limit). Aprire 7° EventSource blocca finché una delle 6 si chiude. HTTP/2 elimina questo limite.

### 6.2 Vulnerabilità Strutturali

SSE, pur semplice, introduce rischi specifici della sua natura long-lived e unidirezionale.

#### 6.2.1 Token Expiration Durante Stream

SSE connection può durare ore o giorni. Se autenticazione usa JWT con expiry (esempio: 1 ora), il token scade mid-stream.

Scenario:

T=0: Client stabilisce SSE con JWT (expiry: 1h)

T=30min: Eventi fluiscono normalmente

T=1h+1s: JWT scaduto

A questo punto, cosa succede? Dipende dall'implementazione:

- Se server verifica JWT solo durante handshake iniziale, lo stream continua (security issue: client con token scaduto riceve dati)  
- Se server verifica JWT periodicamente, chiude stream (UX issue: client perde connessione senza motivo apparente)

Nessuna delle due opzioni è ideale. Mitigazione richiede refresh token mechanism: server invia evento speciale `event: token-expiring`, client refresh token, riconnette con nuovo token.

\[Fonte: Treblle \- How SSE and STDIO Can Ruin Your API Security \- https://treblle.com/blog/sse-stdio-api-security\]

Questo workflow è complesso e spesso non implementato, lasciando SSE vulnerabile a sessioni eterne o disconnect frequenti.

#### 6.2.2 CORS Misconfiguration

SSE segue CORS (Cross-Origin Resource Sharing) policy standard. Server deve includere header:

Access-Control-Allow-Origin: https://trusted-domain.com

Un errore comune:

Access-Control-Allow-Origin: \*

Questo permette a qualsiasi dominio di consumare SSE stream. Se stream contiene dati sensibili (notifiche personali, transazioni), attacker su `evil.com` può sottoscriversi e leggere dati.

\[Fonte: Treblle \- How SSE and STDIO Can Ruin Your API Security \- https://treblle.com/blog/sse-stdio-api-security\]

A differenza di WebSocket (che richiede active check Origin durante handshake), CORS SSE è passivo: se server non configura Access-Control headers, browser applica same-origin policy, ma il problema è quando header è configurato troppo permissivo.

#### 6.2.3 Resource Exhaustion

Server non può limitare durata connessione SSE a priori (client potrebbero avere legittimi bisogni di stream long-lived). Ma client malevolo può aprire N connessioni SSE senza chiuderle mai, esaurendo thread/process server.

Differenza con WebSocket: SSE è HTTP standard, quindi più facile da abusare (no need for WebSocket-aware client, basta `curl`):

for i in {1..1000}; do

  curl \-N http://target.com/events &

done

1000 connessioni SSE simultanee, tutte idle, consumando risorse server.

Mitigazione richiede timeout server-side (esempio: chiudi connessione dopo 1 ora di inattività), ma questo rompe use case legittimi di monitoring long-term.

\[Fonte: Microsoft Learn \- Configure API for SSE in Azure API Management \- https://learn.microsoft.com/en-us/azure/api-management/how-to-server-sent-events\]

#### 6.2.4 Lack of HTTPS

SSE su HTTP plaintext (`http://`) è vulnerabile a MITM: attacker intercetta stream, legge eventi, può anche iniettare eventi fake modificando response.

A differenza di WebSocket (che ha wss:// scheme enforcing TLS), SSE non ha schema separato. Client usa `new EventSource('http://...')` senza warning browser.

Best practice è SEMPRE usare HTTPS per SSE, ma questo non è enforced.

\[Fonte: DEV Community \- Hidden Risks of SSE \- https://dev.to/patrick\_61cbc6392b72286f6/the-hidden-risks-of-sseserver-sent-events-what-developers-often-overlook-1b34\]

### 6.3 Sfide di Testing Specifiche

SSE è il protocollo meno testato perché tool tradizionali assumono response HTTP brevi.

#### 6.3.1 Long-Duration Connection

Scanner HTTP settano timeout (30s, 60s). SSE connection dura ore. Se scanner invia GET a `/events` e attende response, timeout scatta e scanner assume "server non risponde", quando in realtà SSE sta funzionando correttamente.

Testing SSE richiede client che:

- Mantiene connessione aperta indefinitamente  
- Processa eventi streaming (non buffer intera response)  
- Verifica formato eventi (structure validation)

Tool come `curl` con flag `-N` (no buffering) può ricevere SSE, ma non valida automaticamente.

#### 6.3.2 Heartbeat Detection

SSE server dovrebbe inviare heartbeat periodici (comment lines) per evitare timeout load balancer/proxy. Testing deve verificare:

- Heartbeat presente (almeno ogni X secondi)  
- Heartbeat non interferisce con eventi reali  
- Client EventSource gestisce correttamente heartbeat (ignora commenti)

Questo richiede monitoring temporale: collezione eventi per minuti, analisi intervalli.

#### 6.3.3 Reconnection e Last-Event-ID

Testare auto-reconnection richiede:

- Stabilire SSE connection  
- Server invia eventi con ID sequenziali (id: 1, id: 2, id: 3\)  
- Forzare disconnect (kill connection TCP)  
- Verificare che client riconnetta con header `Last-Event-ID: 3`  
- Verificare che server riprenda da ID 4 (non re-send ID 1-3)

Questo workflow è complesso e richiede controllo fine su network layer (forza disconnect) e application layer (verifica header, eventi ricevuti).

---

## CONCLUSIONI FASE 1.B

L'analisi dei sei protocolli API evidenzia come non esista un "protocollo sicuro per default". Ogni scelta di design introduce trade-off tra funzionalità, performance e sicurezza. REST offre semplicità ma soffre di over-fetching e proliferazione endpoint. GraphQL risolve questi problemi ma introduce query complexity attacks e batching bypass. gRPC fornisce performance eccellenti ma con opacità binaria che rende inspection impossibile. SOAP garantisce standardizzazione enterprise ma con complessità XML che apre a XXE e XML bombs. WebSocket abilita real-time bidirezionale ma con rischi CSWSH e rate limiting bypass. SSE fornisce streaming semplice ma con token expiration e resource exhaustion.

Ciascun protocollo richiede strategie di testing differenziate. Tool generici (Burp, ZAP, Nikto) coprono adeguatamente solo REST. GraphQL richiede query complexity analysis e introspection probing. gRPC richiede protobuf decoder e reflection discovery. SOAP richiede XML fuzzer e WS-Security handling. WebSocket richiede client stateful con Origin validation testing. SSE richiede long-duration connection management.

Un framework di security assessment efficace deve riconoscere il protocollo in uso (fingerprinting), selezionare tool appropriati, e applicare test protocol-specific. La fase successiva integrerà questa conoscenza con le architetture analizzate in Fase 1.A, studiando come le interazioni architettura-protocollo generino blind spot e complessità di testing amplificata.

---

## BIBLIOGRAFIA TECNICA

### **REST**

* Baeldung \- REST vs GraphQL vs gRPC: https://www.baeldung.com/rest-vs-graphql-vs-grpc  
* DesignGurus \- REST vs GraphQL vs gRPC System Design: https://www.designgurus.io/blog/rest-graphql-grpc-system-design  
* LogRocket Blog \- GraphQL vs gRPC vs REST: https://blog.logrocket.com/graphql-vs-grpc-vs-rest-choosing-right-api/

### **GraphQL**

* GraphQL Specification: https://spec.graphql.org/  
* Pradeep Loganathan's Blog \- API Architecture Showdown: https://pradeepl.com/blog/api/rest-vs-graphql-vs-grpc/  
* Medium \- REST vs GraphQL vs gRPC: https://mobilelive.medium.com/rest-vs-graphql-vs-grpc-comparing-three-modern-api-technologies-9ba58abadd82

### **gRPC**

* gRPC Official Documentation: https://grpc.io/docs/  
* gRPC Protocol Specification: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md  
* Kong Blog \- REST vs gRPC vs GraphQL: https://konghq.com/blog/engineering/rest-vs-grpc-vs-graphql  
* GeeksforGeeks \- GraphQL vs REST vs SOAP vs gRPC: https://www.geeksforgeeks.org/blogs/graphql-vs-rest-vs-soap-vs-grpc/

### **SOAP**

* Bright Security \- SOAP Security Top Vulnerabilities: https://brightsec.com/top-7-soap-api-vulnerabilities/  
* Frontiers \- Cloud Security and SOAP XML Vulnerabilities: https://www.frontiersin.org/journals/computer-science/articles/10.3389/fcomp.2025.1595624/full  
* Bright Security \- SOAP API Security: https://appsentinels.ai/blog/soap-api-security/  
* Moldstud \- Common SOAP Security Issues: https://moldstud.com/articles/p-common-soap-security-issues-understanding-vulnerabilities-and-best-practices  
* OWASP \- SOAP Attack Penetration Testing: https://blog.securelayer7.net/owasp-top-10-penetration-testing-soap-application-mitigation/  
* Infosec Institute \- Mastering SOAP Request Automation: https://resources.infosecinstitute.com/topic/soap-attack-2/  
* DreamFactory Blog \- Understanding SOAP Security: https://blog.dreamfactory.com/understanding-soap-security  
* StackHawk Docs \- SOAP XML Injection: https://docs.stackhawk.com/vulnerabilities/90029/  
* Snyk \- XXE Injection in SOAP: https://security.snyk.io/vuln/SNYK-JAVA-SOAP-3034822

### **WebSocket**

* PortSwigger \- Testing for WebSockets Vulnerabilities: https://portswigger.net/web-security/websockets  
* Ably \- WebSocket Security: https://ably.com/topic/websocket-security  
* OWASP \- Testing WebSockets: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web\_Application\_Security\_Testing/11-Client\_Side\_Testing/10-Testing\_WebSockets  
* Bright Security \- WebSocket Security Top 8 Vulnerabilities: https://brightsec.com/blog/websocket-security-top-vulnerabilities/  
* Pentest-Tools Blog \- Cross-Site WebSocket Hijacking: https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh  
* Invicti \- WebSocket Security Best Practices: https://www.invicti.com/blog/web-security/websocket-security-best-practices  
* Vaadata \- How WebSockets Work Vulnerabilities: https://www.vaadata.com/blog/how-websockets-work-vulnerabilities-and-security-best-practices/  
* Praetorian \- MeshCentral CSWSH CVE-2024-26135: https://www.praetorian.com/blog/meshcentral-cross-site-websocket-hijacking-vulnerability/  
* Cobalt \- Web Socket Vulnerabilities: https://www.cobalt.io/blog/web-socket-vulnerabilites  
* Appknox \- WebSocket Pentesting: https://www.appknox.com/blog/everything-you-need-to-know-about-web-socket-pentesting

### **Server-Sent Events (SSE)**

* Wikipedia \- Server-Sent Events: https://en.wikipedia.org/wiki/Server-sent\_events  
* MDN \- Using Server-Sent Events: https://developer.mozilla.org/en-US/docs/Web/API/Server-sent\_events/Using\_server-sent\_events  
* API7 \- Understanding SSE and Its Benefits: https://api7.ai/blog/what-is-sse  
* Treblle \- How SSE and STDIO Can Ruin Your API Security: https://treblle.com/blog/sse-stdio-api-security  
* Microsoft Learn \- Configure API for SSE in Azure API Management: https://learn.microsoft.com/en-us/azure/api-management/how-to-server-sent-events  
* Postman Blog \- Support for Server-Sent Events: https://blog.postman.com/support-for-server-sent-events/  
* Solita \- Server-Sent Events: https://dev.solita.fi/2024/08/15/server-sent-event.html  
* DEV Community \- Hidden Risks of SSE: https://dev.to/patrick\_61cbc6392b72286f6/the-hidden-risks-of-sseserver-sent-events-what-developers-often-overlook-1b34

### **General Resources**

* System Design School \- REST vs gRPC vs GraphQL: https://systemdesignschool.io/blog/rest-grpc-graphql  
* SmartDev \- AI-Powered APIs Performance: https://smartdev.com/ai-powered-apis-grpc-vs-rest-vs-graphql/

---

**FINE FASE 1.B \- PROTOCOLLI E STILI ARCHITETTURALI API**

# **FASE 1.C: MATRICE DI INTERAZIONE ARCHITETTURA-PROTOCOLLO**

**Data:** 31 Gennaio 2026  
 **Versione:** 3.0 (Versione Definitiva \- Integrazione Gap Tecnici)

---

## **INTRODUZIONE**

Le architetture e i protocolli, quando analizzati separatamente, presentano caratteristiche comprensibili e documentabili. Un API Gateway offre centralizzazione e controllo. REST fornisce interfacce resource-oriented. Entrambi hanno vulnerabilità note e strategie di mitigazione consolidate. Il problema emerge quando questi due mondi si incontrano: l'intersezione tra un'architettura specifica e un protocollo particolare genera complessità emergenti che non sono prevedibili analizzando i componenti singolarmente.

Questo fenomeno, che potremmo definire **impedance mismatch architetturale**, si manifesta quando le assunzioni di design di un layer (esempio: "tutto il traffico è HTTP stateless") vengono violate dalle caratteristiche di un altro layer (esempio: "WebSocket richiede connessioni stateful persistenti"). Il risultato sono blind spots strutturali: punti ciechi dove gli strumenti di sicurezza tradizionali falliscono, dove le configurazioni standard sono inadeguate, e dove le superfici di attacco si espandono in modi non ovvi.

Questa sezione analizza le interazioni critiche tra le architetture cloud-native (Fase 1.A) e i protocolli API moderni (Fase 1.B). L'approccio seguito è duplice: prima descriviamo la **fisiologia** dell'integrazione (come funzionano normalmente le combinazioni quando implementate secondo best practice), poi analizziamo la **patologia** (dove nascono i problemi, quali assunzioni vengono violate, e perché i meccanismi di sicurezza standard falliscono).

L'obiettivo non è compilare un catalogo esaustivo di tutte le combinazioni possibili, ma identificare le interazioni più significative per frequenza di deployment, complessità tecnica, e impatto sulla sicurezza. Per ogni interazione analizziamo: il pattern di implementazione standard, il meccanismo tecnico di integrazione, le assunzioni architetturali coinvolte, e infine i blind spot che emergono quando queste assunzioni vengono violate.

---

# **PARTE 1: FISIOLOGIA \- PATTERN DI IMPLEMENTAZIONE STANDARD**

## **INTRODUZIONE ALLA FISIOLOGIA**

Quando architetture e protocolli collaborano correttamente, il risultato è un sistema che sfrutta i punti di forza di entrambi. Un API Gateway gestisce autenticazione centralizzata per API REST. Kubernetes Ingress Controller route traffico gRPC verso servizi backend. Service Mesh applica mTLS automatico a comunicazioni GraphQL interne. Questi pattern, consolidati negli ultimi anni, rappresentano best practice documentate e implementate in produzione da organizzazioni di tutte le dimensioni.

Comprendere come funzionano questi pattern "fisiologici" è fondamentale prima di analizzare i fallimenti. Solo capendo il flusso normale possiamo identificare dove si rompe. Questa sezione descrive sei pattern di integrazione dominanti, evidenziando meccanismi tecnici, configurazioni richieste, e benefici ottenuti.

---

## **1\. GRPC \+ KUBERNETES SERVICE MESH**

### **1.1 Il Pattern Standard**

gRPC è il protocollo preferenziale per comunicazione service-to-service (East-West) in ambienti microservizi Kubernetes. Il Service Mesh (tipicamente Istio) amplifica i benefici di gRPC gestendo automaticamente mTLS, load balancing Layer 7, e observability.

Il pattern architetturale tipico prevede:

\[Pod A \- gRPC Client\]  
  \[Application Container\] → (chiamata gRPC a "grpc-server:9090")  
      ↓ (localhost redirect via iptables rules)  
  \[Envoy Sidecar Proxy\]  
      ↓ (mTLS encryption \- certificato X.509 da Istiod)  
      ↓ (Service Discovery via Kubernetes DNS)  
      ↓ (Load Balancing L7 \- round robin tra endpoint)  
  (Network \- traffico cifrato)  
      ↓  
\[Pod B \- gRPC Server\]  
  \[Envoy Sidecar Proxy\]  
      ↓ (mTLS decryption)  
      ↓ (Authorization policy enforcement)  
      ↓ (Metrics collection \- latency, throughput)  
  \[Application Container\] ← (gRPC request plaintext)

### **1.2 Meccanismo Tecnico di Integrazione**

Il Service Mesh intercetta traffico gRPC senza modifiche al codice applicativo. Quando il Pod A viene creato, Istio injection controller inietta automaticamente l'Envoy sidecar e configura iptables rules che redirigono tutto il traffico in uscita attraverso il proxy.

L'application container chiama semplicemente:

client \= grpc.NewClient("grpc-server.namespace.svc.cluster.local:9090")

Il Kubernetes DNS risolve questo hostname al ClusterIP del Service. Tuttavia, invece di raggiungere direttamente il backend, il traffico viene intercettato dal sidecar Envoy locale tramite regole iptables inserite dall'init container `istio-init`.

Envoy consulta il control plane Istiod per ottenere:

* **Endpoint discovery**: lista di Pod IP che implementano il service (via xDS Endpoint Discovery Service)  
* **TLS certificates**: certificato X.509 per il workload corrente e CA certificate per validare peer  
* **Load balancing policy**: algoritmo (round-robin, least-request, random) e health check configuration

\[Fonte: Istio Documentation \- Traffic Management \- Conoscenza architettura Istio\]

Il sidecar stabilisce connessione HTTP/2 con uno dei backend endpoint, esegue TLS handshake mutuo (entrambi i lati presentano certificati), e proxy la richiesta gRPC. Il tutto è trasparente all'application layer.

### **1.3 Load Balancing Layer 7**

Un aspetto critico di questa integrazione è che il Service Mesh implementa load balancing **Layer 7** per gRPC, a differenza di Kubernetes Service standard (Layer 4).

Kubernetes Service (ClusterIP) è un load balancer Layer 4 implementato da kube-proxy. Quando gRPC client apre connessione HTTP/2 verso un Service, kube-proxy route la connessione TCP a uno dei backend Pod. Ma gRPC multiplexing significa che molteplici richieste RPC viaggiano sulla stessa connessione TCP.

Il problema: kube-proxy bilancia connessioni TCP, non richieste RPC. Se un client apre una connessione verso il Service, tutte le richieste successive vanno allo stesso backend Pod, causando imbalance:

Client 1 → Service (kube-proxy) → Pod A (100 richieste/sec)  
Client 2 → Service (kube-proxy) → Pod B (5 richieste/sec)  
Client 3 → Service (kube-proxy) → Pod C (2 richieste/sec)

Tre client, ma distribuzione sbilanciata perché Client 1 invia molto più traffico sulla sua connessione.

\[Fonte: Medium \- Don't Load Balance gRPC Using Kubernetes Service \- https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f\]

Il Service Mesh risolve questo perché Envoy comprende HTTP/2: bilancia singole richieste RPC, non connessioni TCP. Ogni chiamata gRPC viene distribuita indipendentemente tra backend disponibili, garantendo distribuzione equa anche con numero limitato di client.

### **1.4 Configurazione Best Practice**

Per deployment gRPC su Kubernetes con Istio, la configurazione richiede:

**Service Definition** con annotation per indicare che il servizio usa gRPC:

apiVersion: v1  
kind: Service  
metadata:  
  name: grpc-server  
  labels:  
    app: grpc-server  
spec:  
  ports:  
    \- port: 9090  
      name: grpc  \# Nome porta deve iniziare con protocollo  
  selector:  
    app: grpc-server

Il naming convention `name: grpc` è critico. Istio usa questo per determinare che il traffico è gRPC e applicare configurazioni appropriate (HTTP/2, protobuf-aware metrics).

**DestinationRule** per configurare load balancing:

apiVersion: networking.istio.io/v1  
kind: DestinationRule  
metadata:  
  name: grpc-server  
spec:  
  host: grpc-server.namespace.svc.cluster.local  
  trafficPolicy:  
    loadBalancer:  
      simple: ROUND\_ROBIN  
    connectionPool:  
      http:  
        http2MaxRequests: 100  
        maxRequestsPerConnection: 10

Questa configurazione limita richieste concorrenti per prevenire overload e definisce algoritmo di load balancing.

\[Fonte: Datadog \- gRPC at Datadog \- https://www.datadoghq.com/blog/grpc-at-datadog/\]

---

## **2\. GRPC \+ KUBERNETES INGRESS (NORTH-SOUTH)**

### **2.1 Il Pattern Standard**

Per esporre servizi gRPC a client esterni al cluster (traffico North-South), Kubernetes Ingress Controller gestisce terminazione TLS e routing a backend gRPC.

Il flusso architetturale:

\[gRPC Client Esterno \- Internet\]  
    ↓ (HTTPS/HTTP2 \- porta 443\)  
\[Load Balancer Cloud (AWS ALB / Azure AppGW)\]  
    ↓ (TLS termination)  
\[Kubernetes Ingress Controller \- Nginx/Envoy\]  
    ↓ (Routing basato su hostname/path)  
    ↓ (Backend protocol: gRPC)  
\[Kubernetes Service \- ClusterIP\]  
    ↓ (Load balancing interno)  
\[gRPC Server Pod\]

### **2.2 Configurazione Nginx Ingress Controller**

Nginx Ingress Controller richiede annotation specifica per gestire correttamente traffico gRPC:

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
    \- host: grpc.example.com  
      http:  
        paths:  
          \- path: /  
            pathType: Prefix  
            backend:  
              service:  
                name: grpc-server  
                port:  
                  number: 9090  
  tls:  
    \- hosts:  
        \- grpc.example.com  
      secretName: grpc-tls-cert

L'annotation `backend-protocol: "GRPC"` configura Nginx per:

* Usare HTTP/2 per comunicazione con backend  
* Non modificare header HTTP/2 specifici (`:authority`, `:path`)  
* Preservare metadata gRPC (trailers HTTP/2)

\[Fonte: Kubernetes Ingress-Nginx \- gRPC Example \- https://kubernetes.github.io/ingress-nginx/examples/grpc/\]

Senza questa annotation, Nginx tratta il traffico come HTTP/1.1 standard, causando fallimento delle richieste gRPC con errori "protocol error".

### **2.3 AWS Application Load Balancer (ALB)**

AWS ALB supporta gRPC nativamente ma richiede configurazione via annotation AWS Load Balancer Controller:

apiVersion: networking.k8s.io/v1  
kind: Ingress  
metadata:  
  annotations:  
    alb.ingress.kubernetes.io/backend-protocol-version: "GRPC"  
    alb.ingress.kubernetes.io/healthcheck-protocol: HTTP  
    alb.ingress.kubernetes.io/healthcheck-path: /healthz  
    alb.ingress.kubernetes.io/ssl-redirect: "443"  
spec:  
  \# ... rules

Una peculiarità di ALB: health check DEVE usare HTTP (non gRPC), perché ALB non supporta gRPC health check protocol. Il backend deve esporre un endpoint HTTP `/healthz` separato per health checks, oltre al servizio gRPC principale.

\[Fonte: AWS Prescriptive Guidance \- gRPC on Amazon EKS with ALB \- https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html\]

Il traffico gRPC viene terminato al ALB (TLS decryption), poi inoltrato al backend Kubernetes Service in plaintext HTTP/2. Questo significa che la rete interna VPC trasporta gRPC non cifrato, facendo affidamento su isolation VPC per sicurezza.

---

## **3\. GRAPHQL \+ APOLLO FEDERATION GATEWAY**

### **3.1 Il Pattern Standard**

GraphQL in architetture microservizi adotta tipicamente Apollo Federation: ogni microservizio espone un GraphQL subgraph (schema parziale), e Apollo Gateway compone i subgraph in una supergraph unificata esposta ai client.

L'architettura federata:

\[Client \- Mobile/Web App\]  
    ↓ (Single GraphQL query)  
\[Apollo Gateway \- Supergraph Router\]  
    ↓ (Query Planning \- analisi query, suddivisione in sub-queries)  
    ↓  
    ├─→ \[Subgraph A \- Products Service\] (GraphQL endpoint: /graphql)  
    ├─→ \[Subgraph B \- Reviews Service\] (GraphQL endpoint: /graphql)  
    └─→ \[Subgraph C \- Users Service\] (GraphQL endpoint: /graphql)  
    ↓  
\[Gateway \- Response Composition\]  
    ↓ (Merge risultati da subgraph multipli)  
\[Client\] ← (Single unified GraphQL response)

### **3.2 Meccanismo di Federation**

Ogni subgraph definisce il proprio schema GraphQL con direttive speciali per indicare entity condivise. Esempio:

Subgraph Products definisce:

type Product @key(fields: "id") {  
  id: ID\!  
  name: String\!  
  price: Float\!  
}

L'annotation `@key(fields: "id")` indica che Product è un'entity identificata univocamente da `id`, e altri subgraph possono referenziarla.

Subgraph Reviews estende Product:

extend type Product @key(fields: "id") {  
  id: ID\! @external  
  reviews: \[Review\!\]\!  
}

Questo dichiara che Reviews service può fornire field `reviews` per un Product, dato il suo `id`.

\[Fonte: Apollo GraphQL \- Introduction to Apollo Federation \- https://www.apollographql.com/docs/federation\]

Quando il client invia query:

query {  
  product(id: "123") {  
    name    \# da Products subgraph  
    price   \# da Products subgraph  
    reviews { \# da Reviews subgraph  
      rating  
      text  
    }  
  }  
}

Apollo Gateway esegue questo workflow:

1. **Query Planning**: Analizza la query e determina quali subgraph devono essere interrogati  
2. **Parallel Execution**: Invia query a Products subgraph per ottenere `name` e `price`  
3. **Entity Resolution**: Riceve response da Products, estrae `id: "123"`  
4. **Dependent Query**: Invia query a Reviews subgraph: "dammi reviews per product id=123"  
5. **Response Merging**: Combina dati da entrambi i subgraph in singola response JSON

\[Fonte: Contentful \- Understanding Federated GraphQL \- https://www.contentful.com/blog/understanding-federated-graphql/\]

Questo approccio permette ai team di sviluppare subgraph indipendentemente, ma mantenere client interface unificata.

### **3.3 Best Practice Architetturali**

La documentazione Netflix (pionieri di GraphQL Federation) enfatizza approccio **top-down** invece di bottom-up:

"Think of a federated Graph top down, not bottom up. You cannot have individual teams build their Subgraphs in full isolation and merge them 'upwards' into a Supergraph. This will not scale well from an organizational perspective."

\[Fonte: GraphQL API Gateway Guide \- Federation Pattern \- https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation\]

Questo significa: definire prima la supergraph schema (API pubblica), poi suddividerla in subgraph. Non il contrario (ogni team crea schema proprio e poi si tenta merge).

Il gateway richiede anche **schema registry**: un repository centralizzato dove ogni subgraph pubblica il proprio schema. Il gateway consulta il registry per compose la supergraph. Modifiche a subgraph schema devono essere validate contro supergraph per evitare breaking changes.

---

## **4\. WEBSOCKET \+ AWS API GATEWAY SERVERLESS**

### **4.1 Il Pattern Standard**

AWS API Gateway WebSocket API integra connessioni WebSocket persistenti con backend serverless Lambda, risolvendo il problema di stato tramite DynamoDB.

L'architettura serverless per WebSocket:

\[WebSocket Client \- Browser/Mobile\]  
    ↓ (wss://xyz.execute-api.region.amazonaws.com/production)  
\[AWS API Gateway WebSocket API\]  
    ↓ (Handshake HTTP → Lambda Authorizer per autenticazione)  
    ↓  
\[Lambda: $connect\] ← (Triggered on connection established)  
    ↓ (Store connection ID in DynamoDB table)  
\[DynamoDB Table: Connections\]  
    { connectionId: "abc123", userId: "user\_456", timestamp: ... }  
    ↓  
\[WebSocket Connection Active\]  
    ↓  
\[Client invia message\]  
    ↓  
\[API Gateway\] → \[Lambda: $default\] (message handler)  
    ↓ (Process message, query DynamoDB for user data)  
    ↓ (Send response via @connections API)  
\[Client\] ← (Server response via WebSocket)  
    ↓  
\[Connection Close\]  
    ↓  
\[Lambda: $disconnect\] ← (Cleanup: delete connection from DynamoDB)

### **4.2 Connection Management**

Il pattern centrale è tracking delle connessioni WebSocket in DynamoDB. Ogni connessione riceve un `connectionId` univoco generato da API Gateway. La Lambda `$connect` (eseguita durante handshake) archivia questo ID con metadata utente:

// Lambda $connect handler  
export const handler \= async (event) \=\> {  
  const connectionId \= event.requestContext.connectionId;  
  const userId \= event.requestContext.authorizer.userId; // da Lambda Authorizer  
    
  // Archivia in DynamoDB  
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

Questo mapping connectionId↔userId permette successivamente di:

* Trovare tutte le connessioni di un utente specifico  
* Inviare messaggi push a utente specifico (anche se ha connessioni multiple)  
* Cleanup quando utente disconnette

\[Fonte: Modus Create \- Building WebSocket Server with AWS API Gateway \- https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway\]

### **4.3 Server-to-Client Push**

Per inviare messaggi da backend a client, Lambda usa `@connections` API:

// Lambda che invia messaggio a client specifico  
const apiGatewayManagementApi \= new AWS.ApiGatewayManagementApi({  
  endpoint: 'https://xyz.execute-api.region.amazonaws.com/production'  
});

await apiGatewayManagementApi.postToConnection({  
  ConnectionId: 'abc123',  
  Data: JSON.stringify({ type: 'notification', message: 'Hello' })  
}).promise();

Questo meccanismo permette pattern pub/sub: quando evento avviene (esempio: nuovo commento su post), Lambda query DynamoDB per trovare tutti connectionId interessati e invia push a ciascuno.

\[Fonte: Medium \- AWS API Gateway Deep Dive (WebSocket API) \- https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1\]

### **4.4 Validation e Security**

Best practice documentata AWS: implementare validation a livello route prima di invocare Lambda:

"You can configure API Gateway to perform validation on a route request before proceeding with the integration request. If the validation fails, API Gateway fails the request without calling your backend, sends a 'Bad request body' gateway response to the client, and publishes the validation results in CloudWatch Logs."

\[Fonte: Medium \- AWS API Gateway Deep Dive (WebSocket API) \- https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1\]

Questo previene invocazioni Lambda inutili per payload malformati, riducendo costi e carico backend.

---

## **5\. REST \+ API GATEWAY CLOUD (PATTERN UNIVERSALE)**

### **5.1 Il Pattern Standard**

REST dietro API Gateway managed (AWS API Gateway, Azure API Management, GCP API Gateway) è il pattern più diffuso per esposizione API a client esterni. Il gateway centralizza autenticazione, rate limiting, logging, e routing.

L'architettura standard:

\[REST Client \- Public Internet\]  
    ↓ (HTTPS \- porta 443\)  
\[API Gateway Cloud\]  
    ↓ (TLS Termination)  
    ↓ (Authentication: JWT validation / API Key check)  
    ↓ (Rate Limiting: Token bucket per client ID)  
    ↓ (Request Transformation: header injection, path rewrite)  
    ↓ (Routing: /users → User Service, /products → Product Service)  
\[Backend Microservices \- VPC Private Network\]  
    ↓ (Plaintext HTTP o mTLS interno)  
\[Database / Cache / Storage\]

### **5.2 Autenticazione Multi-Layer**

API Gateway tipicamente implementa autenticazione a livelli:

**Layer 1 \- API Keys**: Identificazione client (chi sta chiamando l'API), non autenticazione utente. Usato per rate limiting e analytics.

**Layer 2 \- JWT Validation**: Autenticazione utente. Gateway valida firma JWT, verifica expiry, estrae claims (userId, ruoli).

**Layer 3 \- Custom Authorizer** (Lambda Authorizer in AWS, Policy in Azure): Logica di autorizzazione complessa. Può interrogare database per verificare permessi granulari.

Il flusso completo:

\[Client Request\]  
  Headers: {  
    X-API-Key: "abc123",  
    Authorization: "Bearer eyJhbGciOiJIUzI1..."  
  }  
    ↓  
\[Gateway \- API Key Validation\]  
  Verifica che abc123 esista e non sia revocato  
    ↓  
\[Gateway \- JWT Validation\]  
  Decodifica JWT, verifica firma HMAC/RSA  
  Verifica exp claim (token non scaduto)  
  Estrae userId da claims  
    ↓  
\[Gateway \- Custom Authorizer (optional)\]  
  Lambda riceve { userId, resource, method }  
  Query DynamoDB per permessi user  
  Return { "allow": true/false }  
    ↓  
\[Gateway \- Route to Backend\]  
  Inietta header X-User-Id per backend  
  Backend non deve validare auth (trust gateway)

Questo pattern separa responsabilità: gateway gestisce autenticazione/autorizzazione, backend implementa business logic.

\[Fonte: Azure Architecture Center \- API Gateways \- https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway\]

### **5.3 Rate Limiting Patterns**

API Gateway implementa rate limiting tramite **token bucket algorithm**:

* Ogni client ha un bucket con N token  
* Ogni richiesta consuma 1 token  
* Il bucket si riempie a rate R token/secondo  
* Quando bucket è vuoto, richieste vengono rifiutate (429 Too Many Requests)

Configurazione tipica AWS API Gateway:

* Burst limit: 100 requests (bucket capacity)  
* Steady-state limit: 50 requests/second (refill rate)

Questo permette spike temporanei (burst fino a 100 req), ma limita throughput sostenuto a 50 req/sec.

\[Fonte: Kong Gateway Documentation \- https://developer.konghq.com/gateway/\]

Rate limiting può essere applicato per:

* API Key (ogni client ha quota separata)  
* IP Address (utenti anonimi)  
* User ID (estratto da JWT)

---

## **6\. SERVERLESS API (LAMBDA \+ API GATEWAY)**

### **6.1 Il Pattern Standard**

L'integrazione AWS Lambda \+ API Gateway REST rappresenta l'apoteosi del serverless: zero server management, auto-scaling automatico, pay-per-invocation.

Il flusso end-to-end:

\[Client Request: GET /users/123\]  
    ↓  
\[API Gateway REST API\]  
    ↓ (Route: GET /users/{id} → Lambda function getUserById)  
    ↓ (Lambda Proxy Integration)  
\[AWS Lambda \- Cold Start Check\]  
    Se function non eseguita recentemente:  
      ↓ (Provisioning micro-VM)  
      ↓ (Download code da S3)  
      ↓ (Initialize runtime \- Python/Node/Java)  
      ↓ (Execute handler initialization code)  
    Altrimenti (Warm):  
      ↓ (Riusa environment esistente)  
\[Lambda Execution\]  
    ↓ (Handler function riceve event object)  
    Event: {  
      "httpMethod": "GET",  
      "path": "/users/123",  
      "pathParameters": {"id": "123"},  
      "headers": {...},  
      "requestContext": {...}  
    }  
    ↓ (Business logic \- query DynamoDB)  
\[DynamoDB Query\]  
    GetItem(TableName="Users", Key={"id": "123"})  
\[Lambda Response\]  
    Return: {  
      "statusCode": 200,  
      "headers": {"Content-Type": "application/json"},  
      "body": "{\\"id\\": 123, \\"name\\": \\"Alice\\"}"  
    }  
    ↓  
\[API Gateway\]  
    ↓ (Transform Lambda response to HTTP response)  
\[Client\] ← (HTTP 200 OK, JSON body)

### **6.2 Cold Start Mitigation**

Il cold start (100-500ms latency) è il tallone d'Achille del serverless. AWS offre **Provisioned Concurrency** per mitigarlo:

Provisioned Concurrency mantiene N Lambda execution environment sempre warm (pre-inizializzati). Quando richiesta arriva, usa un environment dal pool warm invece di fare cold start.

Configurazione:

ProvisionedConcurrency: 5  \# 5 environment sempre ready

Questo riduce latency a \<10ms per richieste servite da environment warm, ma aumenta costi (si paga per environment idle).

\[Fonte: Lumigo \- AWS Lambda Architecture \- https://lumigo.io/learn/aws-lambda-architecture/\]

Una strategia ibrida: usare Provisioned Concurrency solo durante ore peak (8am-8pm), permettere cold start durante notte.

### **6.3 VPC Integration**

Lambda può accedere risorse VPC private (RDS database, ElastiCache), ma richiede VPC integration con trade-off latency.

Il meccanismo: Lambda crea Elastic Network Interface (ENI) nella VPC, alloca IP address dal subnet, e route traffico Lambda→VPC attraverso ENI.

Storicamente (pre-2019), questo causava cold start catastrofici (+10 secondi) perché ogni invocazione creava nuove ENI. AWS ha ottimizzato con **Hyperplane ENI pooling**: Lambda mantiene pool di ENI pre-create condivise tra function, riducendo overhead a \~100-200ms.

\[Fonte: Serverless Architecture Patterns \- https://americanchase.com/serverless-architecture-patterns/\]

Il flusso VPC-integrated:

\[Lambda Execution Environment \- AWS Account\]  
    ↓ (Via Hyperplane ENI)  
\[ENI in VPC Subnet \- IP 10.0.1.50\]  
    ↓ (Security Group rules apply)  
\[RDS Database \- IP 10.0.2.100\]  
    ↓ (Connection via VPC routing)

Best practice: Lambda VPC-integrated richiede NAT Gateway per accesso Internet (download dipendenze, chiamate API esterne). Senza NAT, Lambda può raggiungere solo risorse VPC.

---

## **SINTESI PARTE 1: PATTERN CONSOLIDATI**

La fisiologia delle interazioni architettura-protocollo rivela pattern consolidati che sfruttano i punti di forza di entrambi i layer. gRPC su Service Mesh ottiene mTLS automatico e load balancing Layer 7\. GraphQL Federation permette microservizi indipendenti con API unificata. WebSocket serverless sfrutta DynamoDB per stato persistente. REST \+ API Gateway centralizza security.

Questi pattern funzionano perché rispettano le assunzioni di design reciproche: Service Mesh assume traffico HTTP/2 (gRPC fornisce). API Gateway assume stateless (REST fornisce). Lambda assume short-lived execution (REST request/response si adatta).

La prossima sezione analizza dove queste assunzioni vengono violate, generando blind spot e complessità emergenti.

---

# **PARTE 2: PATOLOGIA \- FRIZIONI E RISCHI DI SICUREZZA**

## **INTRODUZIONE ALLA PATOLOGIA**

Quando architetture e protocolli collaborano, le loro assunzioni di design devono essere compatibili. Il problema emerge quando un layer viola le assunzioni dell'altro, creando **impedance mismatch**: il disallineamento tra le aspettative di un componente e il comportamento reale dell'altro.

Questi mismatch generano blind spot strutturali: punti ciechi dove meccanismi di sicurezza standard falliscono, dove configuration best practice sono inadeguate, e dove attack surface si espandono in modi non ovvi. Non sono bug implementation-specific, ma proprietà emergenti dell'interazione tra design architetturali incompatibili.

Questa sezione analizza sei interazioni problematiche critiche, identificando per ciascuna: quale assunzione viene violata, perché i tool tradizionali falliscono, e quali mitigazioni (se esistono) sono richieste.

---

## **1\. GRPC \+ SERVICE MESH: MEMORY EXHAUSTION SU STREAMING**

### **1.1 L'Assunzione Violata**

Il Service Mesh (specificamente Envoy proxy) assume che le richieste HTTP/2 siano **finite e relativamente brevi**. Envoy bufferizza messaggi in memoria per implementare retry, timeout, e metrics collection. Il modello mentale: una richiesta arriva, viene processata in millisecondi-secondi, la risposta parte, buffer viene rilasciato.

gRPC bidirectional streaming viola questa assunzione radicalmente: uno stream può essere **infinito**. In un'applicazione chat, videoconferenza, o telemetry streaming, il client e server inviano messaggi continuamente senza mai chiudere lo stream.

Il diagramma del problema:

\[gRPC Client \- Streaming App\]  
    ↓ (Apre 1 bidirectional stream HTTP/2)  
\[Envoy Sidecar Proxy\]  
    ↓ (Bufferizza messaggi in memoria)  
    Buffer: \[msg1, msg2, msg3, ...\]  
    ↓ (Stream non chiude mai)  
    ↓ (Continua bufferizzare: msg4, msg5, ... msg1000000)  
\[Memory\]  
    Allocated: 10MB → 100MB → 500MB → 2GB → OOM Kill

### **1.2 Il Blind Spot Tecnico**

Il problema documentato da Red Hat è che il circuit breaker HTTP/2 (`http2MaxRequests`) **non previene** questo scenario:

"gRPC applications using bi-directional streams between client and server causes huge memory usage from istio-proxy envoy sidecar. Even when using circuit breaker to implement `http2MaxRequests` the sidecar keeps consuming memory until its limits. The default value of 2Gi causes the container to constantly crash."

\[Fonte: Red Hat \- gRPC Protocol Listener on Service Mesh \- https://access.redhat.com/solutions/6246351\]

La root cause: circuit breaker conta **richieste HTTP/2 concorrenti**, non messaggi per stream.

Configuration:  
  http2MaxRequests: 100  (max 100 concurrent streams)

Scenario reale:  
  10 gRPC streams attivi (sotto limit 100 ✓)  
  × 1.000.000 messaggi per stream  
  \= 10.000.000 messaggi buffered in Envoy  
  \= Memory exhaustion

Ogni stream è contato come "1 request". Il circuit breaker permette 100 stream concorrenti, apparentemente safe. Ma se ciascuno stream invia milioni di messaggi, Envoy accumula gigabyte di dati in buffer senza limit.

### **1.3 Mitigazioni Documentate**

Red Hat documenta tre approcci:

**Opzione 1 \- Aumentare memoria sidecar**: Configurare Envoy con memory limit \>2Gi. Non sempre accettabile (costo, overhead).

**Opzione 2 \- Istio Ambient Mode**: Usare architettura proxyless che elimina sidecar per traffico L7. ztunnel (Layer 4 proxy) non bufferizza payload, riduce memory footprint.

\[Fonte: Istio Blog \- gRPC Proxyless Service Mesh \- https://istio.io/latest/blog/2021/proxyless-grpc/\]

**Opzione 3 \- Stream timeout application-side**: Implementare timeout nel codice applicativo (esempio: chiudi stream dopo 1 ora), invece di affidarsi a Envoy.

Nota critica: nessuna di queste è una "fix" perfetta. Sono workaround che bilanciano trade-off (memory vs functionality).

---

## **2\. GRPC \+ ISTIO GATEWAY: PROTOCOL DOWNGRADE SILENZIOSO**

### **2.1 L'Assunzione Violata**

Kubernetes assume che **protocollo può essere inferito da naming convention**. Se un Service port ha `name: grpc`, tool comprendono che il traffico è gRPC HTTP/2.

Istio estende questa convenzione ma con implementation detail: supporta annotation `appProtocol`, ma solo per versioni specifiche. La Kubernetes Enhancement Proposal (KEP) per `appProtocol` è in draft, non standard stabile.

Il problema emerge quando configuration è ambigua: Service senza `name: grpc` né `appProtocol`. Istio deve decidere: tratto come HTTP/1.1 o HTTP/2?

Default fallback: **HTTP/1.1**.

### **2.2 Il Blind Spot Operativo**

Issue documentato GitHub Istio \#53877:

"Well, I was able to narrow it down... Looks like the gateway is converting traffic to HTTP/1.1."

\[Fonte: GitHub \- Istio Discussion \#53877 \- https://github.com/istio/istio/discussions/53877\]

Il sintomo: client gRPC riceve `protocol error`, connessione fallisce. Developer vede solo errori generici nei log:

upstream connect error or disconnect/reset before headers

Debugging richiede packet capture (tcpdump) per vedere che Istio Gateway sta inviando HTTP/1.1 al backend, non HTTP/2.

Il diagramma del downgrade silenzioso:

\[gRPC Client \- Expects HTTP/2\]  
    ↓ (Invia richiesta gRPC)  
\[Istio Gateway\]  
    ↓ (Nessuna indication protocol)  
    ↓ (Default: HTTP/1.1 conversion)  
    ↓ (Proxy request come HTTP/1.1)  
\[gRPC Server \- Expects HTTP/2\]  
    ← (Riceve HTTP/1.1 request)  
    ← (Rejection: protocol error)  
\[Client\]  
    ← (Connection failed)

Il blind spot: **nessun warning nei log Istio** che protocol downgrade è avvenuto. L'operatore non sa che il problema è misconfiguration, pensa sia bug application o network issue.

### **2.3 Implicazioni di Sicurezza**

gRPC client assume che Service Mesh fornisce **mTLS automatico**. Se il traffico viene downgraded a HTTP/1.1, e HTTP/1.1 path non ha mTLS configured, la comunicazione diventa plaintext.

Scenario:

Developer: "Ho deployato su Istio, mTLS è automatico, sicuro ✓"  
Realtà: Protocol downgrade → HTTP/1.1 plaintext → Sniffabile da attacker sulla rete

L'assunzione violata: "Istio \= sempre cifrato". In realtà: "Istio \= cifrato se protocol correttamente configurato".

---

## **3\. GRAPHQL \+ API GATEWAY: BATCHING BYPASS RATE LIMITING**

### **3.1 L'Assunzione Violata**

API Gateway assume che **1 HTTP request \= 1 operazione backend**. Rate limiting è quindi implementato contando HTTP requests:

Configuration:  
  Rate Limit: 100 requests/second per API key  
    
Logica:  
  If (request\_count \> 100 in current\_second):  
    Return 429 Too Many Requests

GraphQL batching/aliasing viola questa assunzione: **1 HTTP request \= N operazioni backend**.

### **3.2 Il Blind Spot Architetturale**

Scenario di attacco documentato:

POST /graphql

{  
  "query": "query BatchAttack {  
    user1: user(id: 1\) { name email }  
    user2: user(id: 2\) { name email }  
    user3: user(id: 3\) { name email }  
    ...  
    user1000: user(id: 1000\) { name email }  
  }"  
}

Questo è **1 HTTP POST request**. Rate limiter del gateway conta: "1 request, OK".

Backend GraphQL esegue: 1000 resolver calls per campo `user(id: ...)`, ciascuno query database.

Il diagramma dell'attacco:

\[Attacker\]  
    ↓ (1 HTTP POST /graphql)  
\[API Gateway \- Rate Limiter\]  
    Counter: 1 request ✓ (sotto limit 100/sec)  
    ↓ (Forward to backend)  
\[GraphQL Server\]  
    ↓ (Parse query, trova 1000 alias)  
    ↓ (Execute 1000 resolver functions)  
        ├→ DB Query 1  
        ├→ DB Query 2  
        ...  
        └→ DB Query 1000  
\[Database\]  
    Overload → Slow query → Timeout

Documentazione Escape Tech conferma:

"GraphQL APIs allow batching and aliasing, where multiple queries can be sent in a single HTTP request. This can be exploited to bypass rate limits set at the gateway or firewall level."

\[Fonte: Escape Tech \- How to Secure GraphQL APIs \- https://escape.tech/blog/how-to-secure-graphql-apis/\]

### **3.3 Calcolo del Bypass**

Se rate limit è 100 req/sec, attaccante può:

100 HTTP requests/sec  
× 1000 GraphQL queries per request (batching)  
\= 100.000 operazioni backend/sec

Bypass di 1000x rispetto al rate limit previsto.

### **3.4 Mitigazione Richiesta**

Rate limiting tradizionale (Nginx `limit_req`, AWS API Gateway throttling) **non protegge**. Serve **query complexity analysis**:

GraphQL server deve:

1. Parsare query in Abstract Syntax Tree (AST)  
2. Calcolare costo computazionale (ogni field ha peso, nesting moltiplica)  
3. Rifiutare query con costo \> threshold

Esempio di costo:

user (costo: 1\)  
  posts (costo: 10, moltiplicato per ogni user)  
    comments (costo: 5, moltiplicato per ogni post)

Query: user { posts { comments } }  
Costo totale: 1 user × 10 posts × 5 comments \= 50

Questo richiede GraphQL-aware gateway o middleware application-side. Infrastrutture tradizionali non hanno questa capacità.

---

## **4\. GRAPHQL INTROSPECTION: SCHEMA LEAKAGE POST-GATEWAY**

### **4.1 L'Assunzione Violata**

Best practice security GraphQL: **disabilitare introspection in produzione**.

API Gateway assume che se instrospection è disabled, lo schema è segreto.

La realtà: schema è ricostruibile tramite **field suggestion**, indipendentemente da introspection.

### **4.2 Il Meccanismo di Bypass**

GraphQL fornisce error messages utili per developer experience:

query { user { invalidFieldName } }

Response:  
{  
  "errors": \[{  
    "message": "Cannot query field 'invalidFieldName' on type 'User'.   
                Did you mean 'username', 'email', or 'firstName'?"  
  }\]  
}

Questo error message **leak campi validi**.

Attacker può iterare:

Prova 1: user { a } → "Did you mean 'admin', 'age'?"  
Prova 2: user { b } → "Did you mean 'balance'?"  
Prova 3: user { c } → "Did you mean 'creditCard'?"  
...

Dopo N tentativi, attacker ricostruisce tutti field names.

Il tool open source **Clairvoyance** automatizza questo:

clairvoyance \-o schema.json https://target.com/graphql  
\# Output: Full schema reconstructed via field suggestion

\[Fonte: Cyber Chief \- Mastering GraphQL Introspection \- https://www.cyberchief.ai/2024/11/graphql-security.html\]

### **4.3 Documentazione Esplicita del Problema**

Cyber Chief documenta:

"While disabling introspection may seem like a security measure, it's largely ineffective. Your GraphQL schema remains discoverable through other means, particularly through Field Suggestion \- a feature present in most GraphQL engines."

\[Fonte: Cyber Chief \- Mastering GraphQL Introspection \- https://www.cyberchief.ai/2024/11/graphql-security.html\]

Il blind spot: **API Gateway non può bloccare field suggestion** senza parsare GraphQL response errors. Gateway vede solo HTTP 200 response con JSON body. Non distingue tra "risposta valida" e "error message che leak schema".

---

## **5\. WEBSOCKET \+ API GATEWAY: RATE LIMITING POST-HANDSHAKE**

### **5.1 L'Assunzione Violata**

API Gateway assume traffico **HTTP request/response stateless**. Rate limiting conta richieste HTTP discrete.

WebSocket viola questa assunzione: **1 handshake HTTP, N frame senza ulteriori HTTP requests**.

### **5.2 Il Blind Spot Strutturale**

AWS API Gateway documentation:

"API Gateway throttles requests using the token bucket algorithm, where a token counts for a request. Specifically, API Gateway examines the rate and burst of request submissions."

\[Fonte: AWS API Gateway \- Protect WebSocket APIs \- https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html\]

Keyword critico: "**request submissions**" \= HTTP requests.

Il diagramma dell'attacco:

\[Attacker\]  
    ↓ (Stabilisce 100 connessioni WebSocket)  
    ↓ (100 HTTP handshake requests)  
\[API Gateway Rate Limiter\]  
    Counter: 100 requests ✓ (sotto limit es. 1000/sec)  
    ↓ (Connections established)  
\[WebSocket Connections Active\]  
    ↓ (Attacker invia 1000 frame/sec per connessione)  
    ↓ (100 connections × 1000 frames \= 100.000 frames/sec)  
\[API Gateway\]  
    ← (NON conta frame come "requests")  
    ← (Rate limiter ignaro)  
\[Backend Lambda\]  
    ← (Receives 100.000 messages/sec)  
    ← (Overload)

### **5.3 Implicazione per Testing**

Tool che testano rate limiting via HTTP request count (Burp Intruder, OWASP ZAP) **falliscono completamente** su WebSocket.

Test scenario:

Tool: Invia 1000 HTTP requests → 429 Too Many Requests ✓  
Tool: Invia 1000 WebSocket frames → All accepted ✗

Conclusione errata del tool: "Rate limiting OK"  
Realtà: Rate limiting bypassed via WebSocket

### **5.4 Mitigazione Richiesta**

Rate limiting per WebSocket richiede **application-level implementation**:

// Lambda $default (message handler)  
const messageCount \= await getMessageCount(connectionId);

if (messageCount \> 100\) { // 100 messages/min per connection  
  // Disconnect client  
  await apiGateway.deleteConnection({ ConnectionId: connectionId });  
  return { statusCode: 429 };  
}

await incrementMessageCount(connectionId);  
// Process message...

Questo richiede DynamoDB query per ogni messaggio (overhead latency), ma è l'unico modo per enforce limit.

---

## **6\. WEBSOCKET \+ API GATEWAY: WAF BYPASS STRUTTURALE**

### **6.1 L'Assunzione Violata**

Web Application Firewall (WAF) ispeziona **HTTP request/response payload** per identificare attack patterns (XSS, SQLi, RCE).

WebSocket, dopo handshake HTTP, usa **frame binary protocol** che WAF non può ispezionare.

### **6.2 Documentazione Esplicita del Blind Spot**

Azure API Management documentation:

"WebSocket APIs can be secured by applying API Management's access control policies to the **initial handshake operation**."

\[Fonte: Microsoft Learn \- Import WebSocket API to Azure API Management \- https://learn.microsoft.com/en-us/azure/api-management/websocket-api\]

Parola chiave: "**initial handshake operation**" \= solo upgrade HTTP, NON frame successivi.

Azure Application Gateway documentation è ancora più esplicita:

"After a connection is upgraded to WebSocket, as an intermediary/terminating proxy, Application Gateway will simply send the data received from the frontend to the backend and vice-versa, **without any inspection or manipulation capability**. Therefore, the Web Application Firewall (WAF) **cannot parse any content and doesn't perform any inspections** on such data."

\[Fonte: Microsoft Learn \- WebSocket Support in Azure Application Gateway \- https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket\]

### **6.3 Scenario di Attacco**

\[Attacker\]  
    ↓ (HTTP handshake con JWT valido)  
\[API Gateway \+ WAF\]  
    ↓ (Valida JWT ✓)  
    ↓ (WAF ispeziona HTTP request ✓)  
    ↓ (Upgrade to WebSocket approved)  
\[WebSocket Connection Established\]  
    ↓  
\[Attacker invia WebSocket frame\]  
    Payload: {"message": "\<script\>alert(document.cookie)\</script\>"}  
    ↓  
\[WAF\]  
    ← (Vede binary WebSocket frame)  
    ← (Cannot inspect payload \- XSS passa inosservato)  
\[Backend\]  
    ← (Processa message, stores in DB)  
    ← (Stored XSS vulnerability)

Il WAF è **strutturalmente cieco** ai frame WebSocket post-upgrade.

### **6.4 Implicazione Architetturale**

Non esiste soluzione infrastructure-level. La sicurezza deve essere implementata nel codice applicativo:

* Backend deve validare/sanitize ogni WebSocket frame payload  
* Non può delegare a WAF/Gateway

Questo viola il principio di separation of concerns (infrastruttura gestisce security, application gestisce business logic).

---

## **7\. WEBSOCKET \+ AWS API GATEWAY: LOGGING TRUNCATION**

### **7.1 L'Assunzione Violata**

API Gateway assume **log entries sono bounded** (dimensione limitata ragionevole).

WebSocket frame può essere fino a **32 KB** (AWS limit), ma AWS CloudWatch Logs trunca a **1024 bytes**.

### **7.2 Il Blind Spot Forensico**

AWS API Gateway limitation documentata:

"API Gateway currently limits log events to 1024 bytes. Log events larger than 1024 bytes, such as request and response bodies, will be truncated."

\[Fonte: AWS API Gateway \- Important Notes \- https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html\]

Calcolo del problema:

WebSocket frame max size: 32 KB \= 32.768 bytes  
CloudWatch log entry: 1024 bytes  
Percentage logged: 1024 / 32768 \= 3.125%  
Percentage LOST: 96.875%

Il diagramma del blind spot:

\[WebSocket Frame\]  
  Size: 32 KB  
  Payload: {"action": "...", "data": "\<malicious payload 30KB\>"}  
    ↓  
\[API Gateway Logging\]  
  Log entry: {"action": "...", "data": "\<maliciou...  \[TRUNCATED\]  
    ↓  
\[CloudWatch Logs\]  
  Stored: First 1024 bytes only

### **7.3 Implicazione per Incident Response**

Post-breach investigation:

Security Team: "What payload did the attacker send?"  
CloudWatch Logs: {"message": "Hello, I am...  \[TRUNCATED\]  
Security Team: "96% del payload mancante, analisi impossibile"

Forensic analysis richiede **application-level logging** completo, non può affidarsi a API Gateway logs.

---

## **8\. WEBSOCKET \+ AWS API GATEWAY: PRIVATE NETWORK IMPOSSIBILE**

### **8.1 L'Assunzione Violata**

REST API può essere **private** (VPC endpoint only, no Internet exposure).

WebSocket API è **sempre public** (Internet-exposed).

### **8.2 Documentazione Esplicita della Limitazione**

AWS re:Post:

"WebSocket APIs in API Gateway are currently only offered with a **Regional endpoint type** and must be accessed over the internet, which means they **cannot be made private** like REST APIs."

\[Fonte: AWS re:Post \- WebSocket API Gateway Security \- https://repost.aws/questions/QUV184Gf\_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming\]

### **8.3 Implicazione Architetturale**

Scenario problematico:

Requirement: "Internal microservices comunicano via WebSocket, zero Internet exposure"

Architecture con REST API:  
\[Service A in VPC\] ← (VPC Endpoint \- Private) → \[Service B in VPC\] ✓

Architecture con WebSocket API:  
\[Service A in VPC\] → (Forced Internet exposure) → \[WebSocket API Gateway\] → \[Service B in VPC\] ✗

Servizi interni sono **forzati a esporre traffico su Internet** per usare WebSocket API Gateway.

### **8.4 Workaround Documentato**

Deploy ELB (Elastic Load Balancer) \+ ECS/EKS con WebSocket server custom, bypass API Gateway:

\[Service A\] → \[Internal ALB \- VPC only\] → \[ECS Task \- WebSocket Server\] → \[Service B\]

Trade-off:

* Lose: Managed service benefits (auto-scaling AWS-managed, integration Lambda)  
* Gain: Network isolation completo

---

## **9\. GRPC-WEB TRANSCODING: METADATA LOSS**

### **9.1 L'Assunzione Violata**

Browser non supporta gRPC nativo (HTTP/2 binary frames con protobuf). Soluzione: **gRPC-Web** (HTTP/1.1 text-based wrapper).

Envoy proxy (in Istio, standalone) fornisce transcoding automatico: converte gRPC-Web→gRPC binary.

Assunzione: transcoding è **lossless** (informazioni preservate).

Realtà: metadata e context possono essere persi.

### **9.2 Il Blind Spot Operativo**

Il flusso di transcoding:

\[Browser \- gRPC-Web Client\]  
    ↓ (HTTP/1.1 POST)  
    Content-Type: application/grpc-web+proto  
    Payload: Base64-encoded protobuf  
    ↓  
\[Envoy Sidecar \- gRPC-Web Filter\]  
    ↓ (Transcoding)  
    ↓ (Decode base64)  
    ↓ (Convert to gRPC binary HTTP/2)  
    ↓  
\[gRPC Server\]  
    ← (Receives native gRPC)

Il problema: **log mismatch**.

Gateway log mostra:

POST /UserService/GetUser HTTP/1.1  
Content-Type: application/grpc-web+proto

Backend log mostra:

gRPC Call: UserService.GetUser  
Protocol: HTTP/2

Security monitoring vede HTTP POST, backend processa gRPC. Correlazione tra log gateway e backend è difficile.

\[Fonte: VMware Blog \- gRPC-Web and Istio \- https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/\]

### **9.3 Implicazione di Sicurezza**

WAF ispeziona HTTP/1.1 request (gRPC-Web), vede base64-encoded payload. Può validare base64 format, ma **non può parsare protobuf** senza schema.

Backend riceve gRPC binary, deserializza protobuf. Se protobuf contiene exploit (deserialization attack), WAF non lo rileva perché non comprende semantic di protobuf.

\[WAF\]  
  Inspects: application/grpc-web+proto (base64 text)  
  Validates: "Base64 format OK ✓"  
    
\[Backend\]  
  Receives: gRPC protobuf binary  
  Deserializes: Malicious payload → RCE

Payload validation può essere **diversa** tra WAF (HTTP layer) e backend (gRPC layer), creando gap exploitabile.

---

## **10\. SSE \+ LOAD BALANCER: CONNECTION TIMEOUT SILENTE**

### **10.1 L'Assunzione Violata**

Load Balancer assume connessioni HTTP sono **short-lived** (secondi, minuti max). Timeout configurato (default 30-60 secondi) chiude connessioni idle.

SSE richiede **long-lived HTTP connection** (ore, giorni) per streaming eventi.

### **10.2 Il Blind Spot Operativo**

AWS Application Load Balancer: default idle timeout **60 secondi**.

Se SSE connection è inattiva per \>60s (nessun evento inviato), ALB chiude connessione.

Il diagramma del problema:

T=0: \[Client stabilisce SSE connection con JWT (expiry: 1h)\]  
    ↓  
\[Server streaming eventi\]  
T=30min: data: {"event": "update"}  
T=31min: data: {"event": "notification"}  
    ↓ (Eventi fermano \- nessun nuovo dato)  
T=32min: Connection idle  
    ...  
T=32min+60s: \[ALB chiude connection per idle timeout\]  
    ↓  
\[EventSource API auto-reconnect\]  
    ↓ (Tenta riconnessione con JWT)  
T=1h+1s: JWT scaduto  
    ↓ (Riconnessione fallisce \- 401 Unauthorized)  
\[Client perde eventi durante disconnect window\]

### **10.3 Workaround: Heartbeat Events**

Server invia **heartbeat** (comment line) ogni \<60s per mantenere connection alive:

data: {"event": "update"}

: heartbeat

data: {"event": "notification"}

: heartbeat

Comment lines (prefisso `:`) sono ignorate da `EventSource` API, ma mantengono connection attiva.

\[Fonte: Treblle \- How SSE and STDIO Can Ruin Your API Security \- https://treblle.com/blog/sse-stdio-api-security\]

Il blind spot: Load Balancer **non distingue** heartbeat da traffico reale. Heartbeat consuma:

* Bandwidth (piccolo ma continuo)  
* Connection slots (ogni client una connessione persistente)  
* Server resources (generazione heartbeat periodica)

---

## **SINTESI PARTE 2: TASSONOMIA DEI BLIND SPOTS**

### **Pattern Ricorrenti di Failure**

Analizzando le dieci interazioni problematiche, emergono **cinque pattern di failure ricorrenti**:

**Pattern 1 \- State Mismatch**: Architettura assume stateless, protocollo richiede stateful.

* Esempi: WebSocket \+ API Gateway, SSE \+ Load Balancer  
* Root cause: Infrastructure progettata per request/response, non persistent connections

**Pattern 2 \- Protocol Translation Loss**: Transcoding introduce metadata loss o semantic mismatch.

* Esempi: gRPC-Web → gRPC, Istio protocol downgrade HTTP/2 → HTTP/1.1  
* Root cause: Informazioni perse in conversione tra protocolli

**Pattern 3 \- Payload Opacity**: Infrastructure non può ispezionare payload binario/cifrato.

* Esempi: gRPC protobuf, WebSocket frames post-upgrade  
* Root cause: WAF/IDS blind su formati non-text

**Pattern 4 \- Semantic Routing Failure**: Infrastructure route su metadata HTTP, protocollo route su payload semantic.

* Esempi: GraphQL batching, single endpoint multi-operation  
* Root cause: Gateway non comprende semantic applicativo

**Pattern 5 \- Resource Accounting Mismatch**: Infrastructure misura richieste HTTP, protocollo esegue N operazioni per richiesta.

* Esempi: GraphQL batching, gRPC streaming, WebSocket frames  
* Root cause: Unità di misura disallineate tra layer

### **Matrice Blind Spot per Architettura-Protocollo**

| Protocollo | Architettura | Blind Spot Primario | Causa Tecnica | Mitigazione |
| ----- | ----- | ----- | ----- | ----- |
| gRPC | Service Mesh Sidecar | Memory exhaustion | Envoy bufferizza stream infiniti | Ambient Mode / memory limits |
| gRPC | Istio Gateway | Protocol downgrade | Fallback HTTP/1.1 non loggato | Annotation esplicite |
| GraphQL | API Gateway | Batching rate limit bypass | 1 HTTP request \= N query | Query complexity analysis |
| GraphQL | API Gateway | Introspection leakage | Field suggestion via errors | Disable field hints (difficile) |
| WebSocket | API Gateway | Rate limiting post-handshake | Frame non contati come HTTP | Application-level limiter |
| WebSocket | API Gateway | WAF bypass | Frame non ispezionabili | Application-level validation |
| WebSocket | AWS API Gateway | Private network impossible | Sempre regional endpoint | Workaround: ELB \+ ECS |
| WebSocket | API Gateway | Logging truncation | 1024 bytes max log | Application-level logging |
| gRPC-Web | Envoy Transcoding | Metadata loss | Log HTTP, processa gRPC | End-to-end logging correlation |
| SSE | Load Balancer | Connection timeout | Idle timeout chiude long-lived | Heartbeat events |

---

## **IMPLICAZIONI PER IL FRAMEWORK DI TESTING**

### **Principi di Design Emergenti**

L'analisi delle patologie rivela che un framework di security testing efficace deve:

**Principio 1 \- Testare Interazioni, Non Componenti Isolati**

Non testare "GraphQL" separatamente da "API Gateway". Testare "GraphQL attraverso API Gateway con rate limiting configurato", verificando enforcement effettivo di batching limits.

**Principio 2 \- Non Assumere Configuration \= Enforcement**

Introspection disabilitata ≠ schema segreto (field suggestion bypass) Rate limiting configurato ≠ protezione (WebSocket/GraphQL bypass) WAF enabled ≠ payload inspection (WebSocket frame opachi)

Serve verification runtime, non solo configuration audit.

**Principio 3 \- Protocol-Aware Tool Selection**

Tool tradizionali (Burp, ZAP) coprono REST adequately. GraphQL richiede: `graphql-cop`, `clairvoyance`, query complexity calculator gRPC richiede: `grpcurl`, protobuf decoder, reflection probe WebSocket richiede: client stateful, Origin validation tester, frame fuzzer SSE richiede: long-duration connection manager, heartbeat detector

**Principio 4 \- Multi-Layer Validation**

Un singolo layer non basta:

* Gateway layer: authentication, rate limiting base  
* Service Mesh layer: mTLS, network policy  
* Application layer: authorization field-level, input validation

Framework deve testare policy enforcement a tutti i layer, identificare gap dove layer assume altro layer gestisce security (ma non lo fa).

### **Tool Gaps Identificati**

Scanner HTTP generici (Nikto, Dirb, OWASP ZAP baseline) **non coprono**:

* WebSocket frame analysis post-handshake  
* gRPC protobuf decoding senza `.proto` file  
* GraphQL query complexity calculation  
* SSE long-duration connection testing con token expiry  
* Protocol downgrade detection (HTTP/2 → HTTP/1.1)

Framework richiede orchestrazione di tool specializzati:

* `grpcurl`, `ghz` per gRPC  
* `graphql-cop`, `clairvoyance` per GraphQL  
* `wscat`, `wsdump.py` per WebSocket  
* Custom EventSource client per SSE  
* `tcpdump` \+ analysis per protocol inspection

---

## **CONCLUSIONI FASE 1.C**

L'analisi delle interazioni architettura-protocollo ha rivelato che la complessità non emerge dai componenti singoli, ma dalle loro combinazioni. Un API Gateway sicuro \+ GraphQL sicuro non garantiscono sistema sicuro se il gateway conta HTTP requests mentre GraphQL esegue batch queries. Un Service Mesh con mTLS \+ gRPC cifrato non garantiscono protezione se memory exhaustion causa crash del sidecar.

I blind spot identificati non sono bug implementation-specific, ma **proprietà emergenti** dell'impedance mismatch tra design architetturali. WebSocket è intrinsecamente stateful, API Gateway è intrinsecamente stateless-oriented. Questa incompatibilità fondamentale genera blind spot strutturali (rate limiting bypass, WAF bypass, logging truncation) che non sono risolvibili via semplice configuration.

La distinzione tra fisiologia (come dovrebbero funzionare le integrazioni) e patologia (dove falliscono) evidenzia che best practice architetturali hanno **limitazioni intrinseche**. Configurazioni standard non eliminano blind spot, solo li mitigano parzialmente. Security testing deve quindi:

1. Riconoscere quale combinazione architettura-protocollo è deployata  
2. Identificare blind spot specifici di quella combinazione  
3. Testare enforcement effettivo, non configuration dichiarata  
4. Usare tool protocol-specific, non scanner generici

Questa comprensione profonda delle interazioni fornisce la base necessaria per progettare un framework di security assessment che opera efficacemente in ambienti cloud-native reali, dove la superficie di attacco è definita non dai componenti singoli, ma dalle loro interazioni complesse.

---

## **BIBLIOGRAFIA TECNICA**

### **gRPC \+ Kubernetes/Service Mesh**

* Datadog \- gRPC at Datadog: https://www.datadoghq.com/blog/grpc-at-datadog/  
* AWS Prescriptive Guidance \- gRPC on Amazon EKS with ALB: https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html  
* Kubernetes Ingress-Nginx \- gRPC Example: https://kubernetes.github.io/ingress-nginx/examples/grpc/  
* Medium \- Don't Load Balance gRPC Using Kubernetes Service: https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f  
* Istio \- gRPC Proxyless Service Mesh: https://istio.io/latest/blog/2021/proxyless-grpc/  
* GitHub \- Istio Discussion \#53877: https://github.com/istio/istio/discussions/53877  
* Red Hat \- gRPC Protocol Listener on Service Mesh: https://access.redhat.com/solutions/6246351  
* VMware Blog \- gRPC-Web and Istio: https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/

### **GraphQL \+ API Gateway**

* Escape Tech \- How to Secure GraphQL APIs: https://escape.tech/blog/how-to-secure-graphql-apis/  
* Apollo GraphQL \- Introduction to Apollo Federation: https://www.apollographql.com/docs/federation  
* Contentful \- Understanding Federated GraphQL: https://www.contentful.com/blog/understanding-federated-graphql/  
* GraphQL API Gateway Guide \- Federation Pattern: https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation  
* Cyber Chief \- Mastering GraphQL Introspection: https://www.cyberchief.ai/2024/11/graphql-security.html

### **WebSocket \+ API Gateway**

* AWS API Gateway \- Protect WebSocket APIs: https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html  
* AWS API Gateway \- Important Notes: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html  
* AWS re:Post \- WebSocket API Gateway Security: https://repost.aws/questions/QUV184Gf\_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming  
* Microsoft Learn \- Import WebSocket API to Azure API Management: https://learn.microsoft.com/en-us/azure/api-management/websocket-api  
* Microsoft Learn \- WebSocket Support in Azure Application Gateway: https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket  
* Modus Create \- Building WebSocket Server with AWS API Gateway: https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway  
* Medium \- AWS API Gateway Deep Dive (WebSocket API): https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1

### **Server-Sent Events**

* Treblle \- How SSE and STDIO Can Ruin Your API Security: https://treblle.com/blog/sse-stdio-api-security

### **Serverless & General**

* Serverless Architecture Patterns: https://americanchase.com/serverless-architecture-patterns/  
* Lumigo \- AWS Lambda Architecture: https://lumigo.io/learn/aws-lambda-architecture/  
* Azure Architecture Center \- API Gateways: https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway  
* Kong Gateway Documentation: https://developer.konghq.com/gateway/

## BIBLIOGRAFIA TECNICA

### gRPC \+ Kubernetes

- Datadog \- gRPC at Datadog: [https://www.datadoghq.com/blog/grpc-at-datadog/](https://www.datadoghq.com/blog/grpc-at-datadog/)  
- AWS Prescriptive Guidance \- gRPC on Amazon EKS with ALB: [https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-a-grpc-based-application-on-an-amazon-eks-cluster-and-access-it-with-an-application-load-balancer.html)  
- Kubernetes Ingress-Nginx \- gRPC Example: [https://kubernetes.github.io/ingress-nginx/examples/grpc/](https://kubernetes.github.io/ingress-nginx/examples/grpc/)  
- Kubernetes Gateway API \- gRPC Routing: [https://gateway-api.sigs.k8s.io/guides/grpc-routing/](https://gateway-api.sigs.k8s.io/guides/grpc-routing/)  
- Medium \- Don't Load Balance gRPC Using Kubernetes Service: [https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f](https://medium.com/@lapwingcloud/dont-load-balance-grpc-or-http2-using-kubernetes-service-ae71be026d7f)  
- OneUptime \- gRPC Kubernetes Deployment: [https://oneuptime.com/blog/post/2026-01-08-grpc-kubernetes-deployment/view](https://oneuptime.com/blog/post/2026-01-08-grpc-kubernetes-deployment/view)

### gRPC \+ Service Mesh

- Istio \- gRPC Proxyless Service Mesh: [https://istio.io/latest/blog/2021/proxyless-grpc/](https://istio.io/latest/blog/2021/proxyless-grpc/)  
- GitHub \- Istio Discussion \#53877: [https://github.com/istio/istio/discussions/53877](https://github.com/istio/istio/discussions/53877)  
- Red Hat \- gRPC Protocol Listener on Service Mesh: [https://access.redhat.com/solutions/6246351](https://access.redhat.com/solutions/6246351)  
- VMware Blog \- gRPC-Web and Istio: [https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/](https://blogs.vmware.com/networkvirtualization/2019/04/grpc-web-and-istio.html/)

### GraphQL \+ API Gateway

- Escape Tech \- How to Secure GraphQL APIs: [https://escape.tech/blog/how-to-secure-graphql-apis/](https://escape.tech/blog/how-to-secure-graphql-apis/)  
- Apollo GraphQL \- Introduction to Apollo Federation: [https://www.apollographql.com/docs/federation](https://www.apollographql.com/docs/federation)  
- GraphQL.org \- GraphQL Federation: [https://graphql.org/learn/federation/](https://graphql.org/learn/federation/)  
- Contentful \- Understanding Federated GraphQL: [https://www.contentful.com/blog/understanding-federated-graphql/](https://www.contentful.com/blog/understanding-federated-graphql/)  
- GraphQL API Gateway Guide \- Federation Pattern: [https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation](https://graphql-api-gateway.com/graphql-api-gateway-patterns/graphql-federation)  
- Cyber Chief \- Mastering GraphQL Introspection: [https://www.cyberchief.ai/2024/11/graphql-security.html](https://www.cyberchief.ai/2024/11/graphql-security.html)

### WebSocket \+ API Gateway

- AWS API Gateway \- Protect WebSocket APIs: [https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/websocket-api-protect.html)  
- AWS API Gateway \- Important Notes: [https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html)  
- AWS API Gateway \- Deploy WebSocket APIs: [https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-websocket-deployment.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-set-up-websocket-deployment.html)  
- AWS re:Post \- WebSocket API Gateway Security: [https://repost.aws/questions/QUV184Gf\_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming](https://repost.aws/questions/QUV184Gf_kSHqrFNWOJswD0g/websocket-api-gateway-security-or-alternatives-for-streaming)  
- Microsoft Learn \- Expose WebSocket Server to Application Gateway: [https://learn.microsoft.com/en-us/azure/application-gateway/ingress-controller-expose-websocket-server](https://learn.microsoft.com/en-us/azure/application-gateway/ingress-controller-expose-websocket-server)  
- Microsoft Learn \- WebSocket Support in Azure Application Gateway: [https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket](https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-websocket)  
- Microsoft Learn \- Import WebSocket API to Azure API Management: [https://learn.microsoft.com/en-us/azure/api-management/websocket-api](https://learn.microsoft.com/en-us/azure/api-management/websocket-api)  
- Modus Create \- Building WebSocket Server with AWS API Gateway: [https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway](https://www.moduscreate.com/blog/building-a-websocket-server-using-aws-api-gateway)  
- Medium \- AWS API Gateway Deep Dive (WebSocket API): [https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1](https://medium.com/@joudwawad/aws-api-gateway-deep-dive-websocket-api-a00558fa40e1)

### Server-Sent Events

- Treblle \- How SSE and STDIO Can Ruin Your API Security: [https://treblle.com/blog/sse-stdio-api-security](https://treblle.com/blog/sse-stdio-api-security)

### Serverless Architectures

- Serverless Architecture Patterns: [https://americanchase.com/serverless-architecture-patterns/](https://americanchase.com/serverless-architecture-patterns/)  
- Lumigo \- AWS Lambda Architecture: [https://lumigo.io/learn/aws-lambda-architecture/](https://lumigo.io/learn/aws-lambda-architecture/)  
- AWS Documentation \- Amazon API Gateway: [https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html](https://docs.aws.amazon.com/apigateway/latest/developerguide/welcome.html)

### General Resources

- Azure Architecture Center \- API Gateways: [https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway](https://learn.microsoft.com/en-us/azure/architecture/microservices/design/gateway)  
- Kong Gateway Documentation: [https://developer.konghq.com/gateway/](https://developer.konghq.com/gateway/)

---

**FINE FASE 1.C \- MATRICE DI INTERAZIONE ARCHITETTURA-PROTOCOLLO**

---

**FINE CAPITOLO 1 \- STATO DELL'ARTE: ARCHITETTURE, PROTOCOLLI E INTERAZIONI**

Il capitolo ha fornito una base tecnica completa per comprendere il panorama moderno delle API in ambiente cloud-native, analizzando separatamente le architetture (il contenitore), i protocolli (il contenuto), e le loro interazioni (dove emerge la complessità reale). Questa comprensione stratificata è fondamentale per progettare un framework di security assessment efficace, che sarà oggetto delle fasi successive della tesi.

