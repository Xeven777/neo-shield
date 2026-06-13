# NeoShield — Product Specification & Implementation Plan

> **Purpose:** Build a practical security intelligence platform for developers and small teams. NeoShield combines repository and domain security checks, endpoint monitoring, lightweight network visibility, a unified findings/incident engine, and a small read-only AWS integration.
>
> **Architecture decisions:** Next.js is the web application and owns authentication. Python is a separate backend/worker service for scanning and security integrations. They are separate applications and may live in separate Git repositories; this is **not a monorepo**. Both can run as separate containers in one Docker Compose deployment on one cloud VM. PostgreSQL is managed by Neon; do not run a local PostgreSQL container. Drizzle owns the application schema/migrations. Python accesses the same Neon database using a Python PostgreSQL client, without a second migration system.
>
> **Instruction to the coding agent:** Treat this document as the source of truth. Inspect the existing repositories before changing anything. Do not silently replace the agreed architecture. Implement one phase at a time and report decisions before making large structural changes.

---

## 1. Product Overview

### Product
**NeoShield — Unified Security Intelligence Platform**

### Problem
Small development teams often have security information scattered across GitHub, dependency scanners, domain checks, endpoint tools, network utilities and cloud consoles. They need one understandable place to see what is exposed, what is risky, what needs fixing and whether remediation has happened.

### Product goal
Give a developer or small team one dashboard to:
- Connect multiple projects and GitHub repositories.
- Identify vulnerable dependencies and accidentally committed secrets.
- Check domains for TLS/SSL, DNS, HTTP and security-header misconfigurations.
- Monitor Windows/Linux endpoints through Wazuh.
- Discover devices and exposed services on explicitly authorized networks.
- Review selected security configuration checks for an AWS account.
- Consolidate findings, calculate explainable risk scores, correlate related events, track incidents and remediation, and optionally use AI to explain findings.

### Target users
- Individual developers managing multiple applications.
- Small software teams and agencies.
- Students and lab users demonstrating practical security engineering.

### Product principles
1. **Evidence before opinions:** Every finding comes from a scanner, integration or deterministic rule and retains evidence.
2. **One normalized model:** All scanners produce a common finding format.
3. **AI is an assistant, not the detection engine:** AI explains verified findings and suggests remediation. It must not invent findings, silently change severity or be required for the platform to work.
4. **Safe by default:** Only scan resources the user owns or is authorized to assess. Use read-only cloud permissions. Do not execute repository code.
5. **Free-tier friendly:** Heavy scanning runs in the Python service on the chosen host or lab machine. The hosted app stores metadata and displays results.
6. **Intelligence before AWS:** Build scoring, correlation, incidents and remediation before adding AWS as another finding source.
7. **Separate services, not a monorepo:** Web and Python applications have independent codebases, dependencies, builds and release lifecycles.

---

## 2. Scope and Priorities

| Module | Priority | Purpose |
|---|---|---|
| Application / Repository Security | P0 | GitHub repositories, dependencies, secrets and container/config scans |
| Domain Security | P0 | TLS, DNS, redirects, security headers and expiry |
| Endpoint Monitoring | P1 | Windows/Linux events and endpoint findings through Wazuh |
| Network Intelligence | P1 | Authorized network discovery and exposed-service inventory |
| Security Intelligence | P1 / Phase 3 | Unified findings, health score, correlation, incidents, remediation and AI explanations |
| AWS Security | P2 / Phase 4 | Small read-only AWS configuration checks |

### Out of scope initially
- Full enterprise SIEM replacement or 24/7 managed monitoring.
- Automated exploitation or intrusive penetration testing.
- Autonomous remediation or changing firewall/IAM settings.
- Kubernetes, multi-cloud orchestration or GCP integration.
- Building a custom endpoint agent; use Wazuh agents.
- Custom ML model training.
- Paid scanning APIs or paid threat-intelligence feeds.
- Redis, Kafka, a separate message broker or a local PostgreSQL container.

---

## 3. Feature Specifications

### 3.1 Workspace and Project Management

Users can create workspaces and group assets into projects.

**Project fields**
- Name, description, environment (`development`, `staging`, `production`, `lab`).
- Optional business criticality (`low`, `medium`, `high`).
- Created/updated timestamps.

**Assets attached to projects**
- GitHub repository.
- Domain or subdomain.
- Endpoint (Wazuh agent / host).
- Network / authorized CIDR range.
- AWS account connection (Phase 4).

Users can add, edit, disable and remove assets. Removing an asset must not silently delete historical findings or incidents.

### 3.2 Authentication and Authorization

Use **Better Auth in the Next.js application**. Do not implement authentication/session management independently in Python.

**Required sign-in methods**
- Email OTP.
- Email magic link.
- Google OAuth sign-in.

**Requirements**
- Use Better Auth's supported plugins/providers for the above methods.
- Configure a real email delivery provider for OTP and magic-link delivery; keep provider credentials in server environment variables.
- Configure Google OAuth client credentials in the Next.js server environment.
- Store Better Auth user/session/account/verification data in Neon PostgreSQL using the Better Auth Drizzle adapter.
- Use secure, HTTP-only cookies and production-appropriate cookie settings.
- Enforce workspace membership and role-based authorization in Next.js APIs and server-side data access.
- Python does not accept browser session cookies as its authentication mechanism. It authenticates worker/service requests using a separate revocable, scoped worker token.
- Never expose Better Auth secrets, OAuth client secrets, email credentials or database credentials to the browser.

### 3.3 GitHub Repository Security

**Connection**
- Prefer a GitHub App with minimal read-only permissions for repository metadata and contents.
- Support selected repositories only; avoid organization-wide access unless needed.
- Store installation/repository identifiers, not long-lived plaintext credentials.
- Use short-lived installation tokens when a scan is requested. Never expose tokens to the browser or logs.

**Scans**
- Dependency vulnerability scan using **OSV-Scanner** against supported lockfiles/manifests.
- Secret detection using **Gitleaks**.
- Filesystem and configuration scan using **Trivy** (including Dockerfile/config checks where supported).

**Required outputs**
- Tool and tool version.
- Repository, branch/commit SHA, scan time and scan status.
- Finding title, rule/CVE ID, severity, package/file reference, affected version and fixed version where available.
- Safe evidence only. For secret findings, store file path, rule and redacted fingerprint/snippet; **never store the full secret value**.

**Safety**
- Do not run install scripts, build scripts, tests, binaries or other code from scanned repositories.
- Do not build untrusted Docker images initially.
- Use isolated temporary directories, timeouts, file-size limits and cleanup.
- Treat repository contents, filenames and scanner output as untrusted input.

### 3.4 Domain Security Checks

Users add domains they own or are authorized to test.

Initial checks:
1. Resolve A, AAAA, CNAME, MX and TXT records where relevant.
2. Retrieve TLS certificate issuer, subject, validity dates, hostname match and days until expiry.
3. Check HTTP-to-HTTPS redirection.
4. Inspect CSP, HSTS, X-Content-Type-Options, Referrer-Policy and frame protection (`X-Frame-Options` or CSP `frame-ancestors`).
5. Check basic HTTP response status and server metadata without aggressive fingerprinting.
6. Optionally check a small defined list of common ports using Nmap after explicit authorization.

**Safety**
- Validate and normalize domains.
- Resolve DNS and reject private, loopback, link-local, multicast and reserved destinations for public-domain scans.
- Re-check redirect destinations and DNS results to reduce SSRF and DNS-rebinding risk.
- Apply strict timeouts, response-size limits and request limits.
- Do not crawl websites or submit forms initially.
- Port scanning is opt-in, limited to authorized targets and a conservative port list. Never run exploit scripts or aggressive scans.

### 3.5 Endpoint Security — Wazuh Integration

Use Wazuh rather than creating a custom endpoint agent.

**Demonstration setup**
- Wazuh manager/indexer/dashboard in a local or hosted lab environment.
- At least one Linux endpoint; add Windows if resources permit.
- Wazuh agents collect endpoint telemetry and security events.

**NeoShield integration**
- Python service reads relevant Wazuh alerts through the manager or supported indexer API.
- Normalize selected alerts into NeoShield findings/events.
- Map Wazuh agent ID, hostname, OS and status to NeoShield assets.

**Initial use cases**
- Repeated failed authentication attempts.
- File integrity monitoring changes.
- Malware/suspicious-file alerts produced by configured Wazuh rules.
- Endpoint vulnerability inventory/alerts where available.
- Agent disconnected or unhealthy.

Do not expose Wazuh management or indexer ports publicly. Keep Wazuh credentials in the Python service environment or local secret store.

### 3.6 Network Intelligence

Use **Nmap** initially. Zeek is an optional extension and must not block the MVP.

**Initial features**
- Discover hosts on an explicitly authorized local network.
- Record IP, MAC where available, hostname and discovered services/ports.
- Identify selected exposed services and changes between scans.
- Create findings for clearly risky configurations, such as unexpected remote-management ports exposed on a lab host.

**Safety**
- Require the user to confirm authorization and enter the exact CIDR range.
- Restrict default discovery to private/local networks and a maximum range such as `/24`.
- Use conservative discovery and service-detection options; no exploit scripts, brute force or denial-of-service checks.
- Show exact target range and scan options before starting.
- Record scan scope and timestamp for auditability.

### 3.7 Unified Security Intelligence — Phase 3, Before AWS

This central layer consumes findings from repository, domain, endpoint and network modules. AWS findings use the same interface in Phase 4.

**A. Normalized findings**
Every provider maps results into the same finding structure. See Data Model.

**B. Project and workspace security health**
- Deterministic, explainable project and workspace scores based only on open findings.
- Show breakdown by severity, asset type and exposure.
- Show trends when historical scans exist.
- Never present the score as formal compliance certification.

Suggested initial model (tune with test data):
- Base risk points: Critical 25, High 15, Medium 8, Low 3, Informational 0.
- Apply documented multipliers for internet exposure and asset criticality; cap total risk at 100.
- `health_score = 100 - min(100, total_open_risk_points)`.
- Deduplicate recurring instances of the same rule on the same asset so repeated scans do not inflate risk.
- Record score algorithm version.

**C. Finding lifecycle**
Statuses: `open`, `acknowledged`, `in_progress`, `resolved`, `accepted_risk`, `false_positive`.

A finding includes:
- First seen, last seen and occurrence count.
- Source integration and scanner rule.
- Severity, confidence and optional CVSS score.
- Affected asset and project.
- Description, evidence, references and remediation guidance.
- Optional owner/assignee.
- Status, notes and status-change history.

When a completed scan no longer reports a finding, mark it resolved only if the relevant asset/rule was actually checked. Failed/incomplete scans must not resolve old findings.

**D. Incident correlation**
Group related findings/events using explicit deterministic rules. Initial examples:
- Repeated endpoint login failures plus network context involving the same source/target.
- Internet-exposed SSH/RDP plus repeated authentication failures on that endpoint.
- A repository secret finding associated with a production project/domain, only when the relationship is explicitly configured.
- Multiple high-risk findings affecting the same asset within a configured time window.

Each incident shows why findings were grouped, related findings/assets, timeline, evidence, severity and status (`new`, `investigating`, `contained`, `resolved`, `closed`).

Do not claim correlated signals prove an attack. Use “related activity” or “potential incident” and show the correlation rule/evidence.

**E. Remediation tracking**
- Suggested remediation steps per finding.
- User can mark work as planned, in progress, fixed or verified.
- Keep who/when/what history.
- A later successful scan can verify that a finding is no longer present.
- No automatic changes to repositories, DNS, endpoints or cloud configuration initially.

**F. AI-assisted explanations**
- Optional “Explain with AI” action for a finding or incident.
- Send only minimum necessary, redacted context: title, rule/CVE, package/version, affected file path, non-sensitive evidence and known remediation references.
- Never send raw secrets, tokens, private keys, credentials, full environment files or unnecessary source code.
- Output: plain-language explanation, likely impact, contextual relevance, suggested remediation and verification steps.
- Clearly label AI-generated content and link it to source findings.
- AI must not determine authoritative severity, close findings or take actions.
- Use a provider adapter; Gemini or another API can be configured. AI is optional and the platform works without an API key.
- Review provider data-use terms before sending real customer data. Free-tier quotas and terms can change.

### 3.8 AWS Security — Phase 4, Lightweight

Add AWS after Phase 3. Use Boto3 from the Python service.

**Read-only checks**
1. IAM: list users/roles and inspect attached/inline policies for broad permissions such as `Action: "*"` and `Resource: "*"`. Flag as a review item, not automatically exploitable.
2. S3: inspect bucket public-access block settings and bucket policy/public-access indicators where permissions allow.
3. EC2 security groups: flag ingress allowing SSH (`22`) or RDP (`3389`) from `0.0.0.0/0` or `::/0`; show other unrestricted ingress separately.
4. CloudTrail: retrieve recent management events through Event History/lookup APIs and identify selected high-signal changes, such as security-group, bucket-policy or IAM-policy changes.

**AWS requirements**
- Document a minimal read-only IAM policy limited to required APIs.
- Support local AWS profile/credential-chain selection for development and demo.
- Do not ask users to paste access keys into the browser.
- Do not persist AWS secret keys in NeoShield. Python reads credentials from its configured credential chain/profile.
- Do not create resources, change permissions, modify buckets, alter security groups, enable paid services or perform remediation.
- Display account ID and regions being checked; require confirmation of account access and scan scope.
- No GCP integration initially.

---

## 4. User Experience and Main Screens

### Navigation
1. **Overview** — health score, open findings by severity, recent incidents, scan activity and asset summary.
2. **Projects** — project list, project detail and associated assets.
3. **Assets** — repositories, domains, endpoints, network ranges and AWS account.
4. **Findings** — filter by project, asset, severity, source, status and date.
5. **Incidents** — correlated incidents, timeline, evidence and investigation notes.
6. **Scans** — scan history, status, duration and safe logs/summaries.
7. **Integrations** — GitHub, Python worker, Wazuh and AWS connection status.
8. **Reports** — project security summary and exportable report.
9. **Settings** — workspace, users, API tokens and preferences.

### Overview content
- Workspace health score with score explanation.
- Total assets by type.
- Open findings by severity.
- Top projects/assets needing attention.
- Active incidents.
- Latest completed/failed scans.
- Recent remediation activity.

### UX requirements
- Every metric links to underlying records.
- Distinguish `no findings` from `not scanned` and `scan failed`.
- Show last scan time and data freshness.
- Useful empty states explaining how to connect the first asset.
- Readable, compact enterprise-style UI; avoid decorative charts without useful data.
- Desktop-first responsive layout is acceptable initially.

---

## 5. Technical Architecture

### 5.1 Agreed architecture

- **Web application:** Next.js App Router, TypeScript. Owns UI, Better Auth and product-facing APIs.
- **Python service:** FastAPI plus background worker/scanner orchestration. Owns security scanning integrations and processing.
- **Separate codebases:** Web and Python are separate repositories/applications, not a JavaScript/Python monorepo. They have independent dependency management, builds and release lifecycles.
- **Containers:** Separate Docker images/containers for Next.js and Python. A single Docker Compose deployment can run both on one cloud VM. They can also be deployed independently later.
- **Database:** One managed Neon PostgreSQL database shared by the two services. Do not run a local PostgreSQL container or introduce a second database for the initial version.
- **ORM/schema ownership:** Drizzle ORM in the Next.js codebase owns schema definitions and migrations, including Better Auth tables. Python uses `psycopg` or SQLAlchemy Core for database access. Python must not introduce Alembic or another migration owner.
- **Package managers:** `pnpm` for the Next.js app; `uv` for Python dependency and environment management. Do not use npm unless a specific deployment tool requires it.
- **Job queue:** PostgreSQL-backed job table using row locking/leases. No Redis/Kafka initially.

### 5.2 Deployment topology

```text
                         ONE CLOUD VM (initial deployment)
┌──────────────────────────────────────────────────────────────────┐
│                         Docker Compose                           │
│                                                                  │
│  ┌──────────────────────────┐    ┌────────────────────────────┐  │
│  │ web container            │    │ python container           │  │
│  │ Next.js                  │◄──►│ FastAPI + background worker│  │
│  │ Better Auth              │    │ scanners + integrations    │  │
│  │ Drizzle                  │    │ psycopg / SQLAlchemy Core  │  │
│  └────────────┬─────────────┘    └──────────────┬─────────────┘  │
│               │                                 │                │
└───────────────┼─────────────────────────────────┼────────────────┘
                │                                 │
                └──────────────┬──────────────────┘
                               ▼
                    ┌─────────────────────┐
                    │ Neon PostgreSQL     │
                    │ managed / external  │
                    │ auth + app + jobs   │
                    │ findings + incidents│
                    └─────────────────────┘
```

The initial deployment may expose the web service publicly and keep the Python service on the private Docker network. If Python needs an externally reachable API for worker callbacks, protect it with service authentication and a reverse proxy; do not expose scanner/admin interfaces.

The same two images may later be deployed to separate services or hosts. Both continue using the same Neon database and documented API/job contracts. Do not couple the architecture to one cloud vendor.

### 5.3 Next.js web application

- Next.js App Router, TypeScript, Tailwind CSS and shadcn/ui.
- `pnpm` for package management; commit the lockfile and pin the package manager version.
- Better Auth for email OTP, email magic link and Google sign-in.
- Drizzle ORM and Drizzle Kit for typed database access and migrations.
- Route Handlers for CRUD, auth integration, scan-job creation, worker/job APIs and result ingestion.
- Validate inputs with Zod.
- Perform workspace/project authorization server-side for every operation.
- Keep database credentials, Better Auth secret, Google OAuth secret, email-provider credentials and worker-token signing/secrets server-side only.

### 5.4 Python service

- Python 3.11+ (or compatible current version).
- FastAPI for internal/service APIs and health checks.
- Background worker process for polling/claiming jobs and running scans. The API and worker may run as separate processes from the same Python codebase/image if operationally useful; do not split into many microservices.
- `uv` for dependency management; commit `uv.lock`.
- Use `psycopg` or SQLAlchemy Core for PostgreSQL access. Avoid duplicating the full ORM model layer. Define only the tables/queries needed by the worker and keep the shared DB contract documented.
- Scanner adapters for GitHub, domain, Wazuh, network and AWS.
- Run external scanner binaries as subprocesses with strict timeouts, output limits, temporary directories and cleanup.
- Keep AWS credentials local to the Python service environment/credential chain.

### 5.5 Shared database and migrations

- Neon PostgreSQL is the only application database initially, for local development and deployed environments.
- No local PostgreSQL container. Developers use a Neon development branch/database or another isolated Neon branch for testing.
- Drizzle is the single schema/migration authority.
- Better Auth tables are created/managed through its Drizzle integration and generated schema/migrations as documented by Better Auth.
- Python uses parameterized SQL through `psycopg` or SQLAlchemy Core. It must not modify schema or run migrations.
- Use Neon pooled connection string for serverless/short-lived web connections where recommended; use an appropriate direct or pooled connection for the long-running Python worker. Keep connection counts low.
- Use separate Neon branches or databases for development and production. Never point local tests at production data.
- Use transactions and unique constraints for idempotent finding/job ingestion.

### 5.6 Service-to-service communication and job processing

Use PostgreSQL as the initial job queue; do not add Redis, Kafka or an external queue service.

**Preferred flow**
1. User signs in through Better Auth in Next.js.
2. User requests a scan. Next.js authorizes the user and creates a `ScanJob` in Neon.
3. Python worker polls/claims an eligible job from Neon using a transaction and `FOR UPDATE SKIP LOCKED`, or claims through an authenticated internal API if direct DB job claiming is later preferred.
4. Worker executes the scanner with timeout/resource limits.
5. Worker writes normalized findings and scan results to Neon using its restricted service database role, or submits results to a protected Next.js ingestion endpoint.
6. Next.js/UI reads scan state and findings from Neon.

Choose one result-ingestion path during Phase 0 and document it. Avoid writing the same result through both direct DB and HTTP paths. For a simple initial deployment, direct Python database writes are acceptable if the Python DB role is restricted to required tables/operations; Next.js remains responsible for user-facing authorization and mutations.

Job requirements: idempotency key, retry count, lease expiry, status (`queued`, `leased`, `running`, `completed`, `failed`, `cancelled`), start/end timestamps and safe error summary. Use transactions to avoid duplicate claims. Add heartbeat/lease renewal for longer scans.

### 5.7 Suggested API surface

Exact paths may be adjusted to repository conventions.

**Next.js product APIs**
- `GET/POST /api/v1/projects`
- `GET/PATCH/DELETE /api/v1/projects/:projectId`
- `GET/POST /api/v1/projects/:projectId/assets`
- `GET /api/v1/findings` and `GET/PATCH /api/v1/findings/:findingId`
- `GET /api/v1/incidents` and `GET/PATCH /api/v1/incidents/:incidentId`
- `GET /api/v1/scans` and `POST /api/v1/scans`
- `GET /api/v1/integrations`

**Python service endpoints**
- `GET /health`
- `POST /internal/worker/register` (or bootstrap token flow)
- `POST /internal/jobs/claim` if using HTTP job claiming
- `POST /internal/jobs/:jobId/heartbeat`
- `POST /internal/jobs/:jobId/complete` if using HTTP result ingestion

Internal endpoints must authenticate with a revocable, scoped worker/service token. Store only a hash of worker tokens where persisted. Support token rotation and last-seen/worker health status. Do not expose internal endpoints without authentication.

---

## 6. Initial Data Model

Use UUID primary keys and UTC timestamps. Refine names as needed, but preserve concepts.

| Entity | Purpose |
|---|---|
| `User` / Better Auth tables | Authentication identity and profile |
| `Session` / Better Auth tables | Auth sessions |
| `Account` / Better Auth tables | Google OAuth/provider account links |
| `Verification` / Better Auth tables | OTP/magic-link verification data |
| `Workspace` | User/team container and settings |
| `WorkspaceMember` | Membership and role; can be simplified for single-user MVP |
| `Project` | Workspace, name, description, environment, criticality |
| `Asset` | Project, type, display name, canonical identifier, config, enabled state |
| `Integration` | Provider, workspace/project, connection metadata, status |
| `Worker` | Workspace, token hash, version, hostname label, last seen, status |
| `ScanJob` | Asset, scan type, parameters, status, worker lease, retries and timestamps |
| `ScanRun` | Asset, scanner/version, target snapshot, status, start/completion and summary |
| `Finding` | Normalized issue, severity, source, rule/CVE, asset, status and first/last seen |
| `FindingEvidence` | Redacted evidence, file path, package/version, affected port, references, bounded JSON |
| `FindingStatusEvent` | Finding status changes, actor, timestamp and note |
| `Incident` | Title, severity, status, summary, correlation rule and lifecycle timestamps |
| `IncidentFinding` | Join between incident and findings, reason for association |
| `IncidentEvent` | Timeline item, notes and state transitions |
| `Remediation` | Finding/incident, recommendation, status, verification reference and timestamps |
| `AuditLog` | Important user/integration/scan actions |

### Normalized finding contract

```ts
type FindingInput = {
  source: "github" | "domain" | "wazuh" | "network" | "aws";
  sourceTool: string;
  sourceRuleId?: string;
  projectId: string;
  assetId: string;
  stableKey: string;
  title: string;
  description: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  confidence?: "low" | "medium" | "high";
  cveId?: string;
  cvssScore?: number;
  evidence: Record<string, unknown>; // redacted and size-limited
  remediation?: string;
  references?: string[];
  firstSeenAt: string;
  lastSeenAt: string;
};
```

The TypeScript contract is the canonical documented API/data contract. Python should validate equivalent fields with Pydantic. Never allow scanner-provided workspace/project/asset IDs to determine ownership; derive them from the claimed job and trusted server-side records.

---

## 7. Security and Reliability Requirements

- Enforce workspace-level authorization on every user-facing read/write; prevent insecure direct object references.
- Validate TypeScript API payloads with Zod and Python payloads with Pydantic.
- Hash worker tokens; scope tokens to one workspace and permitted actions; support revocation.
- Use least-privilege Neon database credentials for Python. Do not give the worker unnecessary auth-table write permissions.
- Keep Better Auth secret, OAuth credentials, email-provider credentials, database URLs and AI keys in environment variables/secrets.
- Never log access tokens, passwords, private keys, full secrets or raw environment files.
- Redact secrets from scanner output before database persistence.
- Apply rate limits and quotas to scan creation and ingestion endpoints.
- Add request IDs, structured logs, bounded payload sizes and scan timeouts.
- Use temporary directories with cleanup; do not execute repository contents.
- Restrict domain scanner redirects and resolved IPs to prevent SSRF.
- Require explicit authorization and conservative limits for network scans.
- Keep AWS credentials read-only and in the Python service's credential chain; no automated cloud changes.
- AI requests are opt-in and use redacted, minimal context.
- Do not expose Neon, Wazuh, Docker daemon or scanner/admin ports publicly.
- Use TLS for public traffic and secure internal service communication.

---

## 8. Deployment and Cost Constraints

**Target: ₹0 recurring infrastructure cost for a limited portfolio demo**, subject to free-tier quotas and provider terms. Do not promise unlimited scans or always-on workers.

| Component | Initial choice | Deployment |
|---|---|---|
| Web app | Next.js Docker image | Same cloud VM via Docker Compose initially |
| Python API/worker | FastAPI + worker Docker image | Same cloud VM via Docker Compose initially |
| Database | Neon PostgreSQL Free | Managed external database; no local DB container |
| Package manager | pnpm | Web codebase |
| Python environment | uv | Python codebase |
| Endpoint monitoring | Wazuh | Lab/local Docker environment or a suitably sized host |
| Scanning tools | Gitleaks, OSV-Scanner, Trivy, Nmap | Python container/host with required binaries |
| AI explanations | Optional Gemini/provider adapter | Python or server-side provider integration; quota-limited |
| AWS checks | Boto3 | Python service with read-only credentials |

Constraints:
- Use one Docker Compose file for the two application services in the initial single-VM deployment. Compose may also include a reverse proxy if required, but **must not include a PostgreSQL service**.
- Keep web and Python Dockerfiles independent.
- The Python worker needs adequate CPU/RAM and access to scanner binaries. Do not run heavy scans in Next.js request handlers.
- Wazuh can be resource-intensive; run it separately in a lab environment if the main host cannot comfortably support it.
- The Python service may be unavailable when the host is stopped; show worker last-seen status and pending jobs.
- Do not depend on paid queues, paid SIEM services, paid threat feeds or a permanently running cloud VM if a zero-cost demo is required.
- Do not store large raw PCAP files or full scanner databases in Neon. Store summarized/redacted evidence and bounded metadata.
- Use separate Neon development and production branches/databases. Free plans have storage/compute limits.
- A custom domain is optional and may cost money.
- AI is optional; provide a non-AI experience when no key/quota is available.

---

## 9. Phased Implementation Plan

The order is intentional: **Phase 3 is the intelligence layer; Phase 4 is AWS.**

### Phase 0 — Repository audit and foundation
- Inspect the existing web and Python repositories, package managers, conventions, auth, database, UI components and deployment setup.
- Confirm that the codebases remain separate; do not create a monorepo or combine dependency management.
- Set up Next.js with pnpm and Python with uv if not already present.
- Configure Neon connection for development; do not add local PostgreSQL.
- Add Drizzle schema/migrations and Better Auth integration.
- Implement email OTP, magic link and Google sign-in (email delivery and OAuth credentials documented as required environment variables).
- Create workspace/project CRUD and a consistent UI shell.
- Create Python service health endpoint, worker registration/token bootstrap and heartbeat.
- Add separate Dockerfiles and one Compose deployment that runs web and Python services; no DB container.

**Exit criteria:** User can sign in, create a workspace/project, start both services through Docker Compose, and see Python worker online/offline status. Neon is the only database.

### Phase 1 — Repository and domain security
- Implement GitHub connection and selected repository management.
- Implement Python scan jobs using Gitleaks, OSV-Scanner and Trivy filesystem/config scanning.
- Implement domain checks for DNS, TLS, redirects and security headers.
- Add scan history and normalized findings ingestion.
- Add findings list/detail and filters.

**Exit criteria:** A real authorized GitHub repository and domain can be scanned; findings appear in the hosted dashboard with evidence and scan provenance.

### Phase 2 — Endpoint and network monitoring
- Set up Wazuh in a lab and enroll at least one Linux endpoint; add Windows if resources permit.
- Implement Python Wazuh connector and alert normalization.
- Implement authorized Nmap discovery with exact scope confirmation.
- Add endpoint/network assets and scan/event history.

**Exit criteria:** Wazuh alerts and Nmap discovery results appear as NeoShield assets/findings. No Wazuh/Nmap management port is publicly exposed.

### Phase 3 — Security Intelligence (before AWS)
- Finalize common finding schema and stable deduplication keys.
- Implement finding lifecycle and status-change history.
- Implement deterministic project/workspace health scores with breakdown and algorithm version.
- Implement rule-based incident correlation using asset/IP/time relationships.
- Implement incident timelines, notes and status transitions.
- Implement remediation tracking and later-scan verification.
- Add optional AI explanations/remediation suggestions with redaction and provider adapter.
- Add project reports and score/finding trends.

**Exit criteria:** Findings from GitHub, domains, Wazuh and Nmap flow through one intelligence layer; scores are explainable; correlated incidents show evidence; remediation can be tracked; AI is optional.

### Phase 4 — AWS Security (small scope)
- Document and test the minimal read-only IAM policy.
- Support local AWS profile/credential-chain selection.
- Implement IAM, S3 public-access, EC2 security-group and CloudTrail Event History checks.
- Normalize AWS checks into the existing finding model.
- Display AWS account/region assets and scan history.
- Add mocked Boto3 tests and optional controlled sandbox tests.

**Exit criteria:** User can scan an explicitly selected AWS account/region without storing credentials in the hosted app or changing cloud resources. AWS findings appear in the same dashboard, score and incident engine.

### Phase 5 — Hardening and portfolio demo
- Add integration/error states, retries and worker reconnection behavior.
- Add unit, integration and end-to-end tests for critical workflows.
- Add synthetic demo data clearly marked as synthetic; never mix it with real findings.
- Create architecture diagram, screenshots, setup guide and demo scenario.
- Add exportable report (CSV/JSON first; PDF optional).
- Review rate limits, SSRF restrictions, token handling, database permissions and authorization.

**Exit criteria:** A clean setup can be followed from README; reviewer can reproduce a repository scan, domain check, endpoint event, incident correlation and AWS read-only check.

---

## 10. Testing and Acceptance Criteria

### Automated tests
- Unit tests for normalization, deduplication, scoring and correlation rules.
- Next.js API tests for workspace authorization and Better Auth-protected routes.
- Python tests for worker authentication, job claiming, scanner adapters and database operations.
- Scanner adapter tests using fixture output from Gitleaks, OSV-Scanner, Trivy, Wazuh and Nmap.
- Domain scanner tests for invalid domains, redirects to private IPs, timeouts and malformed DNS/TLS responses.
- Job tests for duplicate delivery, expired leases, retries and failed scans.
- AWS tests using mocked Boto3 responses; real sandbox tests must be opt-in.
- Docker Compose smoke test verifying web/Python connectivity and Neon connectivity without a local DB container.

### Required end-to-end demo
1. Sign in using one configured Better Auth method.
2. Create a project and connect a test GitHub repository.
3. Scan it and produce at least one known test finding (dummy test secret only; never use a real credential).
4. Add an owned test domain and inspect TLS/DNS/security headers.
5. Send a controlled failed-login event to a Wazuh-monitored lab endpoint.
6. Run a permitted Nmap scan against a lab CIDR.
7. Show findings in the unified feed and demonstrate score calculation.
8. Trigger a deterministic correlation rule and open an incident with evidence.
9. Add a remediation note and show status history.
10. Optionally run an AI explanation on redacted finding data.
11. In Phase 4, connect a disposable/read-only AWS test account and show selected checks.

### Definition of done for every feature
- Real data path works end-to-end.
- Loading, empty, success and failure states exist.
- Input is validated and authorization enforced.
- Tests cover key logic and failure paths.
- Logs contain enough context to debug without leaking secrets.
- README/setup documentation is updated.

---

## 11. Implementation Rules for the Coding Agent

1. **Do not implement all phases in one pass.** Start with Phase 0, then complete one phase at a time.
2. Before coding, inspect both codebases and report what can be reused. Do not assume a blank project.
3. Keep web and Python as separate applications/repositories. Do not convert them into a monorepo.
4. Use pnpm for the Next.js codebase and uv for Python. Commit their lockfiles.
5. Better Auth is the only user authentication/session system. Python uses a separate scoped worker/service credential.
6. Drizzle is the only schema/migration authority. Python must not introduce a competing migration system.
7. Neon is the only application database initially. Do not add local PostgreSQL to Docker Compose.
8. Keep one Docker Compose deployment for the two independent app containers initially. Keep Dockerfiles separate and independently buildable.
9. Do not introduce Redis, Kafka, Kubernetes or additional microservices.
10. Use real scanner output and fixture-based tests. Do not fake findings to make the UI look populated.
11. Keep scanner integrations behind small adapters with documented input/output contracts.
12. Keep secrets in environment variables or local credential stores. Add `.env.example` files with names/descriptions, never real values.
13. Do not run untrusted repository code or aggressive network scans.
14. Do not expose local Wazuh, Neon credentials, Docker daemon or scanner/admin ports publicly.
15. Provide a short progress summary, changed files, commands to run, tests run and known limitations after each phase.
16. If free-tier limits or provider behavior are uncertain, verify current official documentation rather than hardcoding assumptions.
17. Keep the product usable without AI and without AWS integration.
18. Ask before changing agreed architectural decisions or introducing new infrastructure/dependencies with meaningful operational cost.

---

## 12. Suggested Repository Layout

Keep two independent repositories. The deployment directory may be a third small repository or a deployment folder on the host; it must not absorb the application source into a monorepo.

```text
neoshield-web/                       # Independent Git repository
├── app/
├── components/
├── lib/
│   ├── auth/                        # Better Auth configuration
│   ├── db/                          # Drizzle schema, client and migrations
│   ├── api/
│   └── security/
├── drizzle/
├── public/
├── Dockerfile
├── package.json
├── pnpm-lock.yaml
└── .env.example

neoshield-python/                    # Independent Git repository
├── neoshield/
│   ├── api/                         # FastAPI endpoints / health
│   ├── worker/                      # Job poller and execution
│   ├── jobs/
│   ├── scanners/
│   │   ├── github/
│   │   ├── domain/
│   │   ├── endpoint/
│   │   ├── network/
│   │   └── aws/                     # Phase 4
│   ├── normalization/
│   ├── db/                          # Python DB queries, no migrations
│   └── config/
├── tests/
├── Dockerfile
├── pyproject.toml
├── uv.lock
└── .env.example

neoshield-deploy/                    # Small deployment repo/folder
├── compose.yaml                     # web + python; NO postgres service
├── Caddyfile                        # Optional reverse proxy / TLS
└── .env.example                     # Deployment-only variables
```

Both application repositories can be cloned side-by-side on the deployment host and referenced by the deployment Compose file as separate build contexts. Keep secrets out of Git.

---

## 13. First Task to Execute

**Start with Phase 0 only.** Inspect the current web and Python repositories and report:
- Existing structure and reusable components.
- Whether the codebases are already separate.
- Current Node/package-manager and Python versions.
- Proposed Better Auth + Drizzle + Neon integration plan.
- Required environment variables for email OTP, magic link and Google OAuth.
- Docker Compose design for the two services with no local database.
- Worker authentication/heartbeat and job-queue approach.

Then implement the agreed Phase 0 foundation. Do not start scanners or later phases until Phase 0 is reviewed.

**Success condition:** A user can authenticate through Better Auth, create a project, run the Next.js and Python services as separate containers through one Docker Compose deployment, and see the Python worker's online/offline status. Both services use the same managed Neon PostgreSQL database, with Drizzle owning migrations and no local PostgreSQL container.
