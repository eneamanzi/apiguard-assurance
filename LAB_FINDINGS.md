# What the labs' findings are

The full assessments of 2026-11-05 on the three labs, each lab reset first, read finding by finding: is it a
weakness of the **application** behind the gateway, a consequence of **how the lab is set up** (its gateway
configuration, its network, the resources we added for the tests), or a gap in the **OpenAPI specification**
that is not a vulnerability. Each test page holds the detail of what was observed (section 12); this page puts
the three labs side by side and says where each result comes from.

| Lab | Run | Result |
|---|---|---|
| Forgejo + Kong | `apiguard-20261105-232318-038433` | 12 PASS, 11 FAIL, 1 INCONCLUSIVE, 7 SKIP, 0 ERROR, 91 findings |
| crAPI + Kong | `apiguard-20261105-231941-766602` | 9 PASS, 16 FAIL, 2 INCONCLUSIVE, 4 SKIP, 0 ERROR, 25 findings |
| Forgejo + APISIX | `apiguard-20261105-221301-780706` | 13 PASS, 10 FAIL, 1 INCONCLUSIVE, 7 SKIP, 0 ERROR, 90 findings |

The reports are in `outputs/forgejo/`, `outputs/crapi/` and `outputs/forgejo-apisix/` (not tracked by git; a new run
of the same configuration rewrites them).

## Summary

| Lab | Application | Lab setup | Specification | Findings |
|---|---|---|---|---|
| Forgejo + Kong | 6 | 7 | 78 | 91 |
| crAPI + Kong | 15 | 10 | 0 | 25 |
| Forgejo + APISIX | 6 | 6 | 78 | 90 |

- **No finding is a false positive of the tool**: each one is a behaviour the target really has, with its record in
  `evidence.json`.
- **"Lab setup" findings are true for that deployment.** They show that the tool sees what the gateway leaves open;
  a gateway configured otherwise would not have them. They say nothing about Forgejo or crAPI.
- **The 78 "specification" findings are not vulnerabilities.** Forgejo's specification declares one security
  requirement for the whole document and marks no operation public. Test 1.1 therefore reports, at TENTATIVE, every
  operation served without a credential, and all 78 are genuinely public. The result carries a note saying the
  document does not declare security per operation.
- **Some PASS results come from the lab setup as well** (marked below): the timeouts, health checks, signing policy
  and TLS configuration are ours, so those PASS say the lab's gateway is configured well, not that the product is.

## crAPI + Kong

crAPI is vulnerable by design; the challenges it declares are in
[the compatibility page](docs/03-reference/06-compatibility.md#crapi--kong).

**In short:**

| | Application | Lab setup | Specification | Total |
|---|---|---|---|---|
| FAIL tests | 9 (1.1, 1.2, 1.3, 1.7, 2.1, 2.2, 7.1, 7.3, ext.3.1), and 0.1 in part | 6 (0.2, 0.4, 1.5, 4.1, 4.4, 5.1), and 0.1 in part | 0 | 16 |
| Findings | 15 | 10 | 0 | 25 |
| PASS tests | 3 (2.5, 6.1, ext.0.1) | 5 (3.3, 4.2, 4.3, 6.2, ext.1.5) | - | 9, with 6.4 from both |
| INCONCLUSIVE tests | 2 (2.4; 7.2, which also meets a limit of the tool) | 0 | - | 2 |

SKIP: 4 (what crAPI does not have, or a test input not configured).

### FAIL

| Test | Finding | Source | Why |
|---|---|---|---|
| 0.1 | Undeclared method known: `PUT /workshop/api/shop/orders` (FIRM) | Application | crAPI handles a `PUT` there (it answers `401 "JWT Token required!"`, where an unknown path gets the router's 404); the specification does not declare it |
| 0.1 | Gateway route without documented paths: `hmac-audit-route` (CERTAIN) | Lab setup | the route `/hmac-audit-probe-not-a-real-path` was added to the lab's Kong for test 3.3 |
| 0.2 | Answered without a route: `/workshop-<random>`, `/community-<random>` (FIRM, 2) | Lab setup | the lab's Kong routes are the prefixes `/workshop` and `/community`, which Kong matches as strings: `/workshop-x` reaches the backend |
| 0.4 | Backend answers without the gateway: `172.23.0.8:8000`, `172.23.0.6:8080`, `172.23.0.7:8087` (1 CERTAIN, 2 FIRM) | Lab setup | the tool runs on the Docker host, which reaches the containers' network: the backends are not isolated from that vantage point |
| 1.1 | Served without a credential: `GET /workshop/api/shop/orders/1`, `GET /workshop/api/shop/return_qr_code` (FIRM, 2) | Application | both declare their own security requirement and answer `200` without a credential (crAPI challenge 14) |
| 1.2 | Invalid token accepted: `alg: none` (CERTAIN) | Application | crAPI accepts an unsigned JWT (challenge 15) |
| 1.3 | The credential's lifetime is long (TENTATIVE) | Application | crAPI's JWT lives 7 days |
| 1.5 | API endpoint redirects plain HTTP to HTTPS (CERTAIN) | Lab setup | the lab's Kong answers plain HTTP with a `301` to HTTPS (`https_redirect_status_code: 301`); on an API path ASVS v5.0.0-4.1.2 asks for no answer at all |
| 1.7 | The login says whether the account exists; it takes longer for one that exists; failed attempts are not limited (1 CERTAIN, 2 FIRM) | Application | `Invalid Credentials` against `Given Email is not registered!`, 94 ms against 5 ms, 101 attempts without a limit. The last could also be closed at the gateway, which in the lab adds none |
| 2.1 | Ordinary user reached a privileged function: `GET /workshop/api/management/users/all` (FIRM) | Application | crAPI's management plane serves user_a (BFLA) |
| 2.2 | User reached another user's object: `GET /workshop/api/shop/orders/{order_id}` (CERTAIN) | Application | user_b reads user_a's order (BOLA), while the modify is refused |
| 4.1 | No rate limit on `/workshop/api/mechanic/` (FIRM) | Lab setup | the lab's Kong has no rate-limiting plugin; the endpoint is also crAPI challenge 6 |
| 4.4 | Oversized body not rejected: `/workshop/api/shop/orders` (FIRM) | Lab setup | the lab's Kong has no body-size limit; this run concluded, others end INCONCLUSIVE by a race (test page) |
| 5.1 | No gateway plugin ships the request logs to a separate system (FIRM) | Lab setup | the lab's Kong writes its access log to the container's output only |
| 7.1 | No anti-automation control on `POST /identity/api/auth/forget-password` (CERTAIN) | Application | the challenge's own endpoint (challenge 3) |
| 7.3 | Race condition: `POST /workshop/api/shop/apply_coupon` accepted 15 times (FIRM) | Application | 15 simultaneous applications of a once-only coupon all accepted |
| ext.3.1 | Server error on a generated input: `GET /community/api/v2/community/posts/recent`, `GET /workshop/api/shop/orders/{order_id}`, `GET /workshop/api/mechanic/receive_report` (FIRM, 3) | Application | a generated input makes crAPI answer `500`; the inputs are random, so each run finds a subset (1 to 3 of these on 2026-11-05) |

### INCONCLUSIVE

| Test | Source | Why |
|---|---|---|
| 2.4 | Application | crAPI's identity service refuses every path before routing it, so whether an older version enforces the same policy cannot be seen (`REFUSED_BEFORE_ROUTING`) |
| 7.2 | Application, and a limit of the tool | crAPI calls the first cloud-metadata URL synchronously and hangs until the gateway answers `504`; the test stops there to keep the backend in service. An accepted URL would not be judged anyway: confirming the outbound call needs a listener the tool does not have |

### PASS

| Test | Source | Basis |
|---|---|---|
| 2.5 | Application | the order shows the card number masked; the injected fields are not shown (`partial`) |
| 3.3 | Lab setup | the lab's `hmac-auth` plugin uses SHA-256 and a 300 s window |
| 4.2 | Lab setup | the lab sets 5 / 30 / 30 s timeouts on every service |
| 4.3 | Lab setup | the lab configures passive health checks on the upstreams |
| 6.1 | Application | no stack trace, debug field or leaky header |
| 6.2 | Lab setup | the lab's Kong sets `X-Content-Type-Options` and `X-Frame-Options` on every service; no arbitrary origin is granted CORS |
| 6.4 | Application and lab setup | the six default configuration paths expose nothing; the gateway configuration holds no credential |
| ext.0.1 | Application | no undocumented path among the lists (`partial`: the identity service refuses unknown paths, so the search is blind there) |
| ext.1.5 | Lab setup | the TLS listener is the lab's gateway with its certificate (`partial`: certificate revocation cannot be checked with the lab's private CA) |

### SKIP

0.3 (crAPI marks no operation deprecated), 1.4 (crAPI's JWT has no revocation), 1.6 (no session cookie), 7.4 (no
webhook receiver configured).

**The lab's own defect, corrected on 2026-11-05.** A first run that evening reported 6.2 FAIL on crAPI: nosniff and
framing protection absent on the community service's answers. The cause was the lab's Kong, which set the two
headers with `response-transformer` `replace` only; in Kong `replace` rewrites a header the backend already sent
(`kong/plugins/response-transformer/header_transformer.lua`, Kong 3.9.3), and that service sends neither. The two
Kong labs now set them with `add` as well, and the run above is the one after the correction.

## Forgejo + Kong

**In short:**

| | Application | Lab setup | Specification | Total |
|---|---|---|---|---|
| FAIL tests | 3 (0.3, 1.7, ext.0.1) | 7 (0.1, 0.2, 0.4, 1.5, 4.1, 4.4, 5.1) | 1 (1.1) | 11 |
| Findings | 6 | 7 | 78 | 91 |
| PASS tests | 6 (1.4, 2.1, 2.2, 2.5, 6.1, ext.3.1) | 4 (3.3, 4.2, 4.3, ext.1.5) | - | 12, with 6.2 and 6.4 from both |
| INCONCLUSIVE tests | 0 | 0 | - | 1 (7.2: a limit of the tool) |

SKIP: 7 (what Forgejo does not have, or a test input not configured for this lab).

### FAIL

| Test | Finding | Source | Why |
|---|---|---|---|
| 0.1 | Gateway route without documented paths: `hmac-audit-route` (CERTAIN) | Lab setup | the route added for test 3.3 |
| 0.2 | Answered without a route: `/api-<random>` (FIRM) | Lab setup | the lab's Kong route is the prefix `/api`, matched as a string: Forgejo answers `/api-x` with its own `Not found.` |
| 0.3 | Deprecated operation still served: `GET /api/v1/repos/{owner}/{repo}/times/{user}` (FIRM) | Application | Forgejo's specification marks it deprecated, and it answers `200` with neither `Deprecation` nor `Sunset` |
| 0.4 | Backend answers without the gateway: `172.22.0.3:3000` (CERTAIN) | Lab setup | the tool runs on the Docker host, which reaches Forgejo's container directly |
| 1.1 | Served without a credential, 78 operations (TENTATIVE) | Specification | public operations (`/version`, `/licenses`, `/orgs`, `/repos/search`, a public repository's reads, ...) under a specification that declares security for the whole document; list below |
| 1.5 | API endpoint redirects plain HTTP to HTTPS (CERTAIN) | Lab setup | the lab's Kong `301` |
| 1.7 | The login says whether the account exists; it takes longer for one that exists; failed attempts are not limited (1 CERTAIN, 2 FIRM) | Application | `user's password is invalid` against `user does not exist`, about 400 ms against 3 ms (the password hash is computed only for an existing account), 101 attempts without a limit, which the lab's gateway does not add either |
| 4.1 | No rate limit on `/api/v1/orgs` (FIRM) | Lab setup | no rate-limiting plugin in the lab's Kong |
| 4.4 | Oversized body not rejected: `/api/v1/orgs` (FIRM) | Lab setup | no body-size limit in the lab's Kong |
| 5.1 | No gateway plugin ships the request logs to a separate system (FIRM) | Lab setup | access log to the container's output only |
| ext.0.1 | Undocumented path answers: `GET /api/healthz`, `GET /api/swagger` (FIRM, 2) | Application | Forgejo's health endpoint and Swagger page, outside the specification's `basePath /api/v1`; probably harmless, which is why they are FIRM |

**The 78 operations of test 1.1** (all `GET`, all public in Forgejo): `/api/v1/gitignore/templates`,
`/label/templates`, `/licenses`, `/licenses/MIT`, `/orgs`, `/orgs/test-org` and its `activities/feeds`, `labels`,
`public_members`, `repos`, `/packages/user-a`, `/repos/issues/search`, `/repos/search`, `/settings/api`,
`/settings/attachment`, `/settings/repository`, `/settings/ui`, `/signing-key.gpg`, `/topics/search`,
`/users/search`, `/users/user-a` and its `activities/feeds`, `heatmap`, `repos`, `/version`, and 52 reads of the
public repository `user-a/test-repo` (`actions/runs`, `actions/tasks`, `activities/feeds`, `archive/main.tar.gz`,
`branches`, `branches/main`, `commits`, `commits/main/status`, `commits/main/statuses`, `compare/main...main`,
`contents`, `contents/README.md`, `forks`, `git/commits/main`, `git/commits/main.diff`, `git/refs`,
`git/trees/main`, `issue_config`, `issue_config/validate`, `issue_templates`, `issues`, `issues/1` and its
`assets`, `blocks`, `comments`, `dependencies`, `labels`, `reactions`, `subscriptions`, `timeline`,
`issues/comments`, `issues/comments/1` and its `assets`, `reactions`, `issues/pinned`, `labels`, `languages`,
`media/README.md`, `milestones`, `new_pin_allowed`, `pulls`, `pulls/pinned`, `raw/README.md`, `releases`,
`releases/1/assets`, `signing-key.gpg`, `stargazers`, `statuses/main`, `subscribers`, `tags`, `tags/v0.1.0`,
`topics`, and the repository itself).

### INCONCLUSIVE

| Test | Source | Why |
|---|---|---|
| 7.2 | A limit of the tool | 15 payloads rejected (non-HTTP schemes, malformed URLs), 58 accepted as webhook URLs: whether Forgejo then calls them cannot be seen without a listener the tool does not have (`OUTBOUND_NOT_CONFIRMED`) |

### PASS

| Test | Source | Basis |
|---|---|---|
| 1.4 | Application | a deleted API token is refused at once |
| 2.1 | Application | the admin endpoints refuse user_a (`partial`: parametric admin paths whose resource does not exist, and the destructive ones, are not verified) |
| 2.2 | Application | user_b is refused user_a's private repository: its own read, 35 sub-resource reads, the modify and the delete |
| 2.5 | Application | no sensitive field; the injected ownership fields are not kept |
| 3.3 | Lab setup | the lab's `hmac-auth` plugin, SHA-256 and a 300 s window |
| 4.2 | Lab setup | 5 / 30 / 30 s timeouts on both services |
| 4.3 | Lab setup | a passive health check on the upstream |
| 6.1 | Application | no debug field or leaky header (`partial`: the malformed body provoked no error, so whether an error leaks a stack trace was not seen, `ERROR_NOT_PROVOKED`) |
| 6.2 | Application and lab setup | Forgejo itself sends `X-Content-Type-Options: nosniff` and `X-Frame-Options: SAMEORIGIN` (read on the backend directly), and the lab's Kong sets them too (`DENY`); no arbitrary origin is granted CORS |
| 6.4 | Application and lab setup | the 11 configured debug paths expose nothing; the gateway configuration holds no credential |
| ext.1.5 | Lab setup | the lab's TLS listener (`partial`: certificate revocation cannot be checked with the lab's private CA) |
| ext.3.1 | Application | no generated read made Forgejo answer `500` (`partial`: many operations refused every generated input) |

### SKIP

1.2 and 1.3 (Forgejo's API token is opaque, not a JWT), 1.6 (no session cookie), 2.4 (no second API version), 7.1,
7.3, 7.4 (no sensitive flow, once-only operation or webhook receiver configured for this lab).

## Forgejo + APISIX

**In short:**

| | Application | Lab setup | Specification | Total |
|---|---|---|---|---|
| FAIL tests | 3 (0.3, 1.7, ext.0.1) | 6 (0.1, 0.4, 1.5, 4.1, 4.4, 5.1) | 1 (1.1) | 10 |
| Findings | 6 | 6 | 78 | 90 |
| PASS tests | 6 (1.4, 2.1, 2.2, 2.5, 6.1, ext.3.1) | 5 (0.2, 3.3, 4.2, 4.3, ext.1.5) | - | 13, with 6.2 and 6.4 from both |
| INCONCLUSIVE tests | 0 | 0 | - | 1 (7.2: a limit of the tool) |

SKIP: 7, as on Forgejo + Kong.

The same application as Forgejo + Kong, so the **application** and **specification** findings are the same (1.7,
0.3, ext.0.1, and the 78 of 1.1), and so are the INCONCLUSIVE (7.2) and the SKIP. What changes is the gateway:

| Test | Result | Source | Why |
|---|---|---|---|
| 0.1 | FAIL, `hmac-audit-route` | Lab setup | the same route, added for test 3.3 |
| 0.2 | **PASS** | Lab setup | APISIX matches `/api/*` segment by segment: every neighbour of a route gets APISIX's own `404 Route Not Found` |
| 0.4 | FAIL, `172.21.0.4:3000` (CERTAIN) | Lab setup | the Docker host reaches the backend directly |
| 1.5 | FAIL, redirect to HTTPS | Lab setup | the lab's `redirect` plugin (`http_to_https`) |
| 4.1, 4.4, 5.1 | FAIL | Lab setup | no rate limit, no body-size limit, no log shipping configured on the lab's APISIX |
| 3.3, 4.2, 4.3, ext.1.5 | PASS | Lab setup | the lab's signing policy, timeouts (5 / 30 / 30 s), health check and TLS listener |
| 6.2 | PASS | Application and lab setup | Forgejo sends the two headers itself, and the lab's `response-rewrite` sets them on every response |

## Reading these results elsewhere

On another deployment the **lab setup** rows are exactly what changes: a gateway with a rate limit, a body-size
limit, log shipping, no HTTP listener and a backend network the scanner cannot reach turns those FAIL into PASS, and
a gateway without timeouts or health checks turns those PASS into FAIL. The **application** rows follow the
application: they would be found on any gateway in front of it, except where a gateway control covers them (a rate
limit at the gateway would also stop 1.7's unlimited attempts).
