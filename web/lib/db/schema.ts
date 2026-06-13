import {
  boolean,
  index,
  integer,
  jsonb,
  pgEnum,
  real,
  snakeCase,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core"

/**
 * Drizzle is the only schema/migration authority for NeoShield.
 * The Python worker reads/writes these tables but never migrates them.
 *
 * All physical identifiers are snake_case; the TypeScript keys stay camelCase
 * so the Better Auth Drizzle adapter can map its field names directly.
 */
const table = snakeCase.table

const timestamps = {
  createdAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
}

/* -------------------------------------------------------------------------- */
/* Better Auth                                                                */
/* -------------------------------------------------------------------------- */

export const user = table("user", {
  id: text().primaryKey(),
  name: text().notNull(),
  email: text().notNull().unique(),
  emailVerified: boolean().notNull().default(false),
  image: text(),
  ...timestamps,
})

export const session = table("session", {
  id: text().primaryKey(),
  expiresAt: timestamp({ withTimezone: true }).notNull(),
  token: text().notNull().unique(),
  ipAddress: text(),
  userAgent: text(),
  userId: text()
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  ...timestamps,
})

export const account = table("account", {
  id: text().primaryKey(),
  accountId: text().notNull(),
  providerId: text().notNull(),
  userId: text()
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
  accessToken: text(),
  refreshToken: text(),
  idToken: text(),
  accessTokenExpiresAt: timestamp({ withTimezone: true }),
  refreshTokenExpiresAt: timestamp({ withTimezone: true }),
  scope: text(),
  password: text(),
  ...timestamps,
})

export const verification = table("verification", {
  id: text().primaryKey(),
  identifier: text().notNull(),
  value: text().notNull(),
  expiresAt: timestamp({ withTimezone: true }).notNull(),
  ...timestamps,
})

/* -------------------------------------------------------------------------- */
/* Workspace and projects                                                     */
/* -------------------------------------------------------------------------- */

export const workspaceRole = pgEnum("workspace_role", [
  "owner",
  "admin",
  "member",
])

export const projectEnvironment = pgEnum("project_environment", [
  "development",
  "staging",
  "production",
  "lab",
])

export const projectCriticality = pgEnum("project_criticality", [
  "low",
  "medium",
  "high",
])

export const workspace = table("workspace", {
  id: uuid().primaryKey().defaultRandom(),
  name: text().notNull(),
  slug: text().notNull().unique(),
  ...timestamps,
})

export const workspaceMember = table(
  "workspace_member",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    userId: text()
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: workspaceRole().notNull().default("member"),
    createdAt: timestamps.createdAt,
  },
  (t) => [
    unique("workspace_member_workspace_id_user_id_key").on(
      t.workspaceId,
      t.userId
    ),
    index("workspace_member_user_id_idx").on(t.userId),
  ]
)

export const project = table(
  "project",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    name: text().notNull(),
    description: text(),
    environment: projectEnvironment().notNull().default("development"),
    criticality: projectCriticality().notNull().default("medium"),
    ...timestamps,
  },
  (t) => [
    index("project_workspace_id_idx").on(t.workspaceId),
    unique("project_workspace_id_name_key").on(t.workspaceId, t.name),
  ]
)

/* -------------------------------------------------------------------------- */
/* Assets, integrations and workers                                           */
/* -------------------------------------------------------------------------- */

export const assetType = pgEnum("asset_type", [
  "repository",
  "domain",
  "endpoint",
  "network",
  "aws_account",
])

export const asset = table(
  "asset",
  {
    id: uuid().primaryKey().defaultRandom(),
    projectId: uuid()
      .notNull()
      .references(() => project.id, { onDelete: "cascade" }),
    type: assetType().notNull(),
    displayName: text().notNull(),
    identifier: text().notNull(),
    config: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    enabled: boolean().notNull().default(true),
    ...timestamps,
  },
  (t) => [
    index("asset_project_id_idx").on(t.projectId),
    unique("asset_project_id_type_identifier_key").on(
      t.projectId,
      t.type,
      t.identifier
    ),
  ]
)

/**
 * Endpoint inventory for an `endpoint` asset. Wazuh is the only provider in
 * Phase 2, but `provider` is kept explicit so a second agent source can be
 * added without a new table.
 */
export type EndpointAgentStatus =
  | "active"
  | "disconnected"
  | "pending"
  | "never_connected"
  | "unknown"

export const endpointAgent = table(
  "endpoint_agent",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    provider: text().notNull().default("wazuh"),
    /** Agent id inside the provider (Wazuh agent id, e.g. "001"). */
    externalId: text().notNull(),
    name: text().notNull(),
    ipAddress: text(),
    osName: text(),
    osVersion: text(),
    osPlatform: text(),
    architecture: text(),
    agentVersion: text(),
    status: text().$type<EndpointAgentStatus>().notNull().default("unknown"),
    lastSeenAt: timestamp({ withTimezone: true }),
    config: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    ...timestamps,
  },
  (t) => [
    unique("endpoint_agent_asset_id_provider_external_id_key").on(
      t.assetId,
      t.provider,
      t.externalId
    ),
    index("endpoint_agent_workspace_id_idx").on(t.workspaceId),
    index("endpoint_agent_provider_external_id_idx").on(
      t.provider,
      t.externalId
    ),
  ]
)

export const integrationProvider = pgEnum("integration_provider", [
  "github",
  "wazuh",
  "aws",
  "worker",
])

export const integrationStatus = pgEnum("integration_status", [
  "pending",
  "connected",
  "disconnected",
  "error",
])

export const integration = table(
  "integration",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    projectId: uuid().references(() => project.id, { onDelete: "set null" }),
    provider: integrationProvider().notNull(),
    displayName: text().notNull(),
    status: integrationStatus().notNull().default("pending"),
    metadata: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    /** High-water mark for incremental pulls (Wazuh alert timestamp). */
    syncCursor: timestamp({ withTimezone: true }),
    lastSyncedAt: timestamp({ withTimezone: true }),
    /** Safe, already-redacted error summary from the worker. */
    lastError: text(),
    ...timestamps,
  },
  (t) => [index("integration_workspace_id_idx").on(t.workspaceId)]
)

export const workerStatus = pgEnum("worker_status", ["active", "revoked"])

export const worker = table(
  "worker",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    name: text().notNull(),
    /** SHA-256 hash of the worker token. The token itself is shown once. */
    tokenHash: text().notNull().unique(),
    /** Short non-secret prefix so tokens can be identified in the UI. */
    tokenPrefix: text().notNull(),
    scopes: jsonb().$type<string[]>().notNull().default([]),
    status: workerStatus().notNull().default("active"),
    version: text(),
    hostname: text(),
    lastSeenAt: timestamp({ withTimezone: true }),
    revokedAt: timestamp({ withTimezone: true }),
    ...timestamps,
  },
  (t) => [index("worker_workspace_id_idx").on(t.workspaceId)]
)

/* -------------------------------------------------------------------------- */
/* Job queue (PostgreSQL, no Redis)                                           */
/* -------------------------------------------------------------------------- */

export const scanType = pgEnum("scan_type", [
  "repository",
  "domain",
  "endpoint",
  "network",
  "aws",
])

export const scanJobStatus = pgEnum("scan_job_status", [
  "queued",
  "leased",
  "running",
  "completed",
  "failed",
  "cancelled",
])

export const scanJob = table(
  "scan_job",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    type: scanType().notNull(),
    status: scanJobStatus().notNull().default("queued"),
    idempotencyKey: text().notNull().unique(),
    parameters: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    attempts: integer().notNull().default(0),
    maxAttempts: integer().notNull().default(3),
    leasedByWorkerId: uuid().references(() => worker.id, {
      onDelete: "set null",
    }),
    leaseExpiresAt: timestamp({ withTimezone: true }),
    availableAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    startedAt: timestamp({ withTimezone: true }),
    completedAt: timestamp({ withTimezone: true }),
    errorSummary: text(),
    createdByUserId: text().references(() => user.id, { onDelete: "set null" }),
    ...timestamps,
  },
  (t) => [
    index("scan_job_claim_idx").on(t.status, t.availableAt),
    index("scan_job_workspace_id_idx").on(t.workspaceId),
    index("scan_job_asset_id_idx").on(t.assetId),
  ]
)

/* -------------------------------------------------------------------------- */
/* GitHub App integration                                                     */
/* -------------------------------------------------------------------------- */

/**
 * One GitHub App installation per workspace in Phase 1. Installation tokens are
 * minted on demand and never persisted.
 */
export const githubInstallation = table(
  "github_installation",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    installationId: text().notNull(),
    accountLogin: text().notNull(),
    accountType: text().notNull(),
    installedByUserId: text().references(() => user.id, {
      onDelete: "set null",
    }),
    ...timestamps,
  },
  (t) => [
    unique("github_installation_workspace_id_key").on(t.workspaceId),
    unique("github_installation_installation_id_key").on(t.installationId),
  ]
)

export const githubRepository = table(
  "github_repository",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    installationId: text().notNull(),
    githubId: text().notNull(),
    owner: text().notNull(),
    name: text().notNull(),
    fullName: text().notNull(),
    defaultBranch: text().notNull(),
    private: boolean().notNull().default(false),
    projectId: uuid().references(() => project.id, { onDelete: "set null" }),
    assetId: uuid().references(() => asset.id, { onDelete: "set null" }),
    selected: boolean().notNull().default(false),
    ...timestamps,
  },
  (t) => [
    unique("github_repository_workspace_id_github_id_key").on(
      t.workspaceId,
      t.githubId
    ),
    index("github_repository_workspace_id_idx").on(t.workspaceId),
  ]
)

/* -------------------------------------------------------------------------- */
/* Scan runs                                                                  */
/* -------------------------------------------------------------------------- */

export const scanRunStatus = pgEnum("scan_run_status", [
  "running",
  "completed",
  "partial",
  "failed",
])

export type ScanToolResult = {
  name: string
  version: string | null
  status: "ok" | "missing" | "error"
  findingCount: number
  error?: string
  durationMs?: number
}

export const scanRun = table(
  "scan_run",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    projectId: uuid()
      .notNull()
      .references(() => project.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    scanJobId: uuid().references(() => scanJob.id, { onDelete: "set null" }),
    scanner: text().notNull().default("repository"),
    status: scanRunStatus().notNull().default("running"),
    targetSnapshot: jsonb()
      .$type<Record<string, unknown>>()
      .notNull()
      .default({}),
    tools: jsonb().$type<ScanToolResult[]>().notNull().default([]),
    findingCount: integer().notNull().default(0),
    startedAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp({ withTimezone: true }),
    errorSummary: text(),
    createdAt: timestamps.createdAt,
  },
  (t) => [
    index("scan_run_workspace_id_idx").on(t.workspaceId),
    index("scan_run_asset_id_started_at_idx").on(t.assetId, t.startedAt),
  ]
)

/* -------------------------------------------------------------------------- */
/* Network discovery inventory                                                */
/* -------------------------------------------------------------------------- */

export type NetworkObservationStatus = "active" | "missing"

export const networkHost = table(
  "network_host",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    address: text().notNull(),
    hostname: text(),
    macAddress: text(),
    vendor: text(),
    status: text().$type<NetworkObservationStatus>().notNull().default("active"),
    firstSeenAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    lastScanRunId: uuid().references(() => scanRun.id, {
      onDelete: "set null",
    }),
    ...timestamps,
  },
  (t) => [
    unique("network_host_asset_id_address_key").on(t.assetId, t.address),
    index("network_host_workspace_id_idx").on(t.workspaceId),
    index("network_host_asset_id_status_idx").on(t.assetId, t.status),
  ]
)

export const networkService = table(
  "network_service",
  {
    id: uuid().primaryKey().defaultRandom(),
    hostId: uuid()
      .notNull()
      .references(() => networkHost.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    port: integer().notNull(),
    protocol: text().notNull().default("tcp"),
    serviceName: text(),
    product: text(),
    version: text(),
    extraInfo: text(),
    cpe: text(),
    status: text().$type<NetworkObservationStatus>().notNull().default("active"),
    firstSeenAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    lastScanRunId: uuid().references(() => scanRun.id, {
      onDelete: "set null",
    }),
    ...timestamps,
  },
  (t) => [
    unique("network_service_host_id_port_protocol_key").on(
      t.hostId,
      t.port,
      t.protocol
    ),
    index("network_service_asset_id_idx").on(t.assetId),
    index("network_service_status_idx").on(t.status),
  ]
)

/* -------------------------------------------------------------------------- */
/* Findings                                                                   */
/* -------------------------------------------------------------------------- */

export const findingSource = pgEnum("finding_source", [
  "github",
  "domain",
  "wazuh",
  "network",
  "aws",
])

export const findingSeverity = pgEnum("finding_severity", [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
])

export const findingConfidence = pgEnum("finding_confidence", [
  "low",
  "medium",
  "high",
])

export const findingStatus = pgEnum("finding_status", [
  "open",
  "acknowledged",
  "in_progress",
  "resolved",
  "accepted_risk",
  "false_positive",
])

export const finding = table(
  "finding",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    projectId: uuid()
      .notNull()
      .references(() => project.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    source: findingSource().notNull(),
    sourceTool: text().notNull(),
    sourceRuleId: text(),
    /** Deterministic dedupe key scoped to the asset. */
    stableKey: text().notNull(),
    title: text().notNull(),
    description: text().notNull(),
    category: text().notNull(),
    severity: findingSeverity().notNull(),
    confidence: findingConfidence(),
    cveId: text(),
    cvssScore: real(),
    remediation: text(),
    references: jsonb().$type<string[]>().notNull().default([]),
    status: findingStatus().notNull().default("open"),
    firstSeenAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp({ withTimezone: true }).notNull().defaultNow(),
    resolvedAt: timestamp({ withTimezone: true }),
    occurrenceCount: integer().notNull().default(1),
    /** Consecutive successful scans where the finding was absent. */
    missedScanCount: integer().notNull().default(0),
    ...timestamps,
  },
  (t) => [
    unique("finding_asset_id_stable_key_key").on(t.assetId, t.stableKey),
    index("finding_workspace_id_status_idx").on(t.workspaceId, t.status),
    index("finding_workspace_id_severity_idx").on(t.workspaceId, t.severity),
    index("finding_project_id_idx").on(t.projectId),
    index("finding_last_seen_at_idx").on(t.lastSeenAt),
  ]
)

export const findingEvidence = table(
  "finding_evidence",
  {
    id: uuid().primaryKey().defaultRandom(),
    findingId: uuid()
      .notNull()
      .references(() => finding.id, { onDelete: "cascade" }),
    scanRunId: uuid().references(() => scanRun.id, { onDelete: "set null" }),
    filePath: text(),
    packageName: text(),
    packageVersion: text(),
    fixedVersion: text(),
    evidence: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamps.createdAt,
  },
  (t) => [unique("finding_evidence_finding_id_key").on(t.findingId)]
)

export const findingStatusEvent = table(
  "finding_status_event",
  {
    id: uuid().primaryKey().defaultRandom(),
    findingId: uuid()
      .notNull()
      .references(() => finding.id, { onDelete: "cascade" }),
    fromStatus: findingStatus(),
    toStatus: findingStatus().notNull(),
    actorUserId: text().references(() => user.id, { onDelete: "set null" }),
    note: text(),
    createdAt: timestamps.createdAt,
  },
  (t) => [index("finding_status_event_finding_id_idx").on(t.findingId)]
)

/* -------------------------------------------------------------------------- */
/* Security events (endpoint telemetry, not every alert is a finding)         */
/* -------------------------------------------------------------------------- */

export const securityEvent = table(
  "security_event",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid()
      .notNull()
      .references(() => workspace.id, { onDelete: "cascade" }),
    projectId: uuid()
      .notNull()
      .references(() => project.id, { onDelete: "cascade" }),
    assetId: uuid()
      .notNull()
      .references(() => asset.id, { onDelete: "cascade" }),
    findingId: uuid().references(() => finding.id, { onDelete: "set null" }),
    source: findingSource().notNull(),
    sourceTool: text().notNull(),
    /** Provider document id (Wazuh alert id); dedupes repeated polls. */
    externalId: text().notNull(),
    eventTime: timestamp({ withTimezone: true }).notNull(),
    ruleId: text(),
    ruleLevel: integer(),
    severity: findingSeverity().notNull(),
    category: text().notNull(),
    title: text().notNull(),
    description: text().notNull(),
    agentId: text(),
    agentName: text(),
    sourceIp: text(),
    evidence: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamps.createdAt,
  },
  (t) => [
    unique("security_event_workspace_id_source_tool_external_id_key").on(
      t.workspaceId,
      t.sourceTool,
      t.externalId
    ),
    index("security_event_workspace_id_event_time_idx").on(
      t.workspaceId,
      t.eventTime
    ),
    index("security_event_asset_id_event_time_idx").on(
      t.assetId,
      t.eventTime
    ),
    index("security_event_workspace_id_severity_idx").on(
      t.workspaceId,
      t.severity
    ),
  ]
)

/* -------------------------------------------------------------------------- */
/* Audit log                                                                  */
/* -------------------------------------------------------------------------- */

export const auditLog = table(
  "audit_log",
  {
    id: uuid().primaryKey().defaultRandom(),
    workspaceId: uuid().references(() => workspace.id, { onDelete: "cascade" }),
    actorUserId: text().references(() => user.id, { onDelete: "set null" }),
    action: text().notNull(),
    targetType: text(),
    targetId: text(),
    metadata: jsonb().$type<Record<string, unknown>>().notNull().default({}),
    createdAt: timestamps.createdAt,
  },
  (t) => [index("audit_log_workspace_id_idx").on(t.workspaceId)]
)

export type Workspace = typeof workspace.$inferSelect
export type WorkspaceMember = typeof workspaceMember.$inferSelect
export type Project = typeof project.$inferSelect
export type Asset = typeof asset.$inferSelect
export type Worker = typeof worker.$inferSelect
export type ScanJob = typeof scanJob.$inferSelect
export type WorkspaceRole = (typeof workspaceRole.enumValues)[number]
export type AssetType = (typeof assetType.enumValues)[number]
export type FindingRow = typeof finding.$inferSelect
export type FindingSeverity = (typeof findingSeverity.enumValues)[number]
export type FindingStatus = (typeof findingStatus.enumValues)[number]
export type FindingSource = (typeof findingSource.enumValues)[number]
export type ScanRun = typeof scanRun.$inferSelect
export type ScanJobStatus = (typeof scanJobStatus.enumValues)[number]
export type GithubRepository = typeof githubRepository.$inferSelect
export type GithubInstallation = typeof githubInstallation.$inferSelect
export type EndpointAgent = typeof endpointAgent.$inferSelect
export type Integration = typeof integration.$inferSelect
export type NetworkHost = typeof networkHost.$inferSelect
export type NetworkService = typeof networkService.$inferSelect
export type SecurityEvent = typeof securityEvent.$inferSelect
