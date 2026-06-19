import type {
  AssetType,
  FindingSeverity,
  ProjectEnvironment,
} from "../db/schema"

/**
 * Deterministic incident correlation (specification §3.7 D).
 *
 * Every rule works on explicit relationships (asset, IP, project, time window)
 * and returns the evidence that caused the grouping. The engine never claims an
 * attack took place: incidents are labelled as related activity / potential
 * incidents and always expose their rule and reason.
 */

export const CORRELATION_RULES = {
  endpointAuthFailures: "endpoint-auth-failures",
  exposedRemoteManagement: "exposed-remote-management",
  secretInProduction: "secret-in-production",
  assetHighRiskCluster: "asset-high-risk-cluster",
  sourceAuthBurst: "source-auth-burst",
} as const

export type CorrelationRule =
  (typeof CORRELATION_RULES)[keyof typeof CORRELATION_RULES]

export const RULE_DESCRIPTIONS: Record<CorrelationRule, string> = {
  [CORRELATION_RULES.endpointAuthFailures]:
    "Repeated authentication failures reported by Wazuh on one endpoint within 24 hours.",
  [CORRELATION_RULES.exposedRemoteManagement]:
    "An endpoint recorded repeated authentication failures and network discovery found SSH or RDP open on the same address.",
  [CORRELATION_RULES.secretInProduction]:
    "A secret finding exists in a production project that explicitly owns one or more domain assets.",
  [CORRELATION_RULES.assetHighRiskCluster]:
    "Three or more high or critical open findings were observed on the same asset within seven days.",
  [CORRELATION_RULES.sourceAuthBurst]:
    "Five or more authentication events from one source IP against one asset within 24 hours.",
}

export const AUTH_WINDOW_HOURS = 24
export const CLUSTER_WINDOW_HOURS = 7 * 24
export const AUTH_FINDING_THRESHOLD = 3
export const AUTH_EVENT_THRESHOLD = 5
export const AUTH_EVENT_HIGH_THRESHOLD = 20

const REMOTE_MANAGEMENT_PORTS = new Set([22, 3389])

export type CorrelationFinding = {
  id: string
  projectId: string
  projectName: string
  projectEnvironment: ProjectEnvironment
  assetId: string
  assetName: string
  assetType: AssetType
  source: string
  sourceTool: string
  stableKey: string
  title: string
  category: string
  severity: FindingSeverity
  occurrenceCount: number
  firstSeenAt: Date
  lastSeenAt: Date
  /** Bounded subset of `finding_evidence.evidence`. */
  evidence: Record<string, unknown>
}

export type CorrelationAsset = {
  id: string
  projectId: string
  projectName: string
  projectEnvironment: ProjectEnvironment
  type: AssetType
  displayName: string
  identifier: string
}

export type CorrelationEvent = {
  id: string
  projectId: string
  assetId: string
  assetName: string
  sourceIp: string | null
  category: string
  ruleId: string | null
  severity: FindingSeverity
  eventTime: Date
}

export type EndpointAddress = {
  assetId: string
  ipAddress: string
}

export type CorrelationCandidate = {
  rule: CorrelationRule
  key: string
  projectId: string
  title: string
  summary: string
  reason: string
  severity: FindingSeverity
  evidence: Record<string, unknown>
  findingIds: string[]
  /** Individual Wazuh events that contributed, linked to the timeline. */
  eventIds: string[]
  /** Per-finding explanation stored on `incident_finding.reason`. */
  findingReasons: Record<string, string>
}

const SEVERITY_RANK: Record<FindingSeverity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
}

export function maxSeverity(
  values: FindingSeverity[],
  floor: FindingSeverity = "informational"
): FindingSeverity {
  let result = floor
  for (const value of values) {
    if (SEVERITY_RANK[value] > SEVERITY_RANK[result]) result = value
  }
  return result
}

function withinWindow(date: Date, now: Date, hours: number) {
  const age = now.getTime() - date.getTime()
  return age >= 0 && age <= hours * 60 * 60 * 1000
}

function numericEvidence(value: unknown): number | null {
  if (typeof value === "number" && Number.isFinite(value)) return value
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value)
    return Number.isFinite(parsed) ? parsed : null
  }
  return null
}

function stringEvidence(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null
}

function uniqueSorted(values: string[]) {
  return [...new Set(values)].sort()
}

function groupedBy<T>(items: T[], keyOf: (item: T) => string) {
  const groups = new Map<string, T[]>()
  for (const item of items) {
    const key = keyOf(item)
    const group = groups.get(key)
    if (group) group.push(item)
    else groups.set(key, [item])
  }
  return groups
}

export type CorrelateInput = {
  findings: CorrelationFinding[]
  events: CorrelationEvent[]
  assets: CorrelationAsset[]
  endpointAddresses: EndpointAddress[]
  now: Date
}

/**
 * Runs every rule over one workspace snapshot and returns candidates keyed
 * deterministically by `(rule, key)`. Pure: same input → same output.
 */
export function correlate(input: CorrelateInput): CorrelationCandidate[] {
  const { findings, events, assets, endpointAddresses, now } = input
  const candidates: CorrelationCandidate[] = []

  const authFindings = findings.filter(
    (finding) =>
      finding.assetType === "endpoint" &&
      finding.category === "authentication" &&
      withinWindow(finding.lastSeenAt, now, AUTH_WINDOW_HOURS)
  )
  const authByAsset = groupedBy(authFindings, (finding) => finding.assetId)
  const authEvents = events.filter(
    (event) =>
      event.category === "authentication" &&
      event.sourceIp !== null &&
      withinWindow(event.eventTime, now, AUTH_WINDOW_HOURS)
  )

  // R1: repeated authentication failures on one endpoint.
  for (const [assetId, group] of authByAsset) {
    const totalOccurrences = group.reduce(
      (total, finding) => total + Math.max(finding.occurrenceCount, 1),
      0
    )
    if (totalOccurrences < AUTH_FINDING_THRESHOLD) continue

    const asset = group[0]
    const severity = maxSeverity(
      group.map((finding) => finding.severity),
      "medium"
    )

    candidates.push({
      rule: CORRELATION_RULES.endpointAuthFailures,
      key: assetId,
      projectId: asset.projectId,
      title: `Repeated authentication failures on ${asset.assetName}`,
      summary: `${totalOccurrences} failed authentication attempts were recorded on ${asset.assetName} in the last ${AUTH_WINDOW_HOURS} hours.`,
      reason: `Correlation rule "${CORRELATION_RULES.endpointAuthFailures}" grouped ${group.length} open authentication finding(s) on the same endpoint within ${AUTH_WINDOW_HOURS} hours. This shows repeated related activity, not that an account was compromised.`,
      severity,
      evidence: {
        rule: CORRELATION_RULES.endpointAuthFailures,
        windowHours: AUTH_WINDOW_HOURS,
        totalOccurrences,
        findings: group.map((finding) => ({
          stableKey: finding.stableKey,
          sourceTool: finding.sourceTool,
          occurrenceCount: finding.occurrenceCount,
        })),
      },
      findingIds: uniqueSorted(group.map((finding) => finding.id)),
      eventIds: uniqueSorted(
        authEvents
          .filter((event) => event.assetId === assetId)
          .map((event) => event.id)
      ),
      findingReasons: Object.fromEntries(
        group.map((finding) => [
          finding.id,
          `Authentication activity on this endpoint within the last ${AUTH_WINDOW_HOURS} hours.`,
        ])
      ),
    })
  }

  // R2: remote management exposed on the same endpoint address.
  const addressByAsset = new Map(
    endpointAddresses.map((entry) => [entry.assetId, entry.ipAddress])
  )
  const exposedServices = findings.filter(
    (finding) =>
      finding.category === "exposed_service" &&
      REMOTE_MANAGEMENT_PORTS.has(
        numericEvidence(finding.evidence.port) ?? -1
      ) &&
      withinWindow(finding.lastSeenAt, now, CLUSTER_WINDOW_HOURS)
  )

  for (const [assetId, authGroup] of authByAsset) {
    const ipAddress = addressByAsset.get(assetId)
    if (!ipAddress) continue

    const endpoint = authGroup[0]
    const totalAttempts = authGroup.reduce(
      (total, finding) => total + Math.max(finding.occurrenceCount, 1),
      0
    )
    if (totalAttempts < AUTH_FINDING_THRESHOLD) continue

    for (const exposed of exposedServices) {
      if (exposed.projectId !== endpoint.projectId) continue
      if (stringEvidence(exposed.evidence.address) !== ipAddress) continue

      const port = numericEvidence(exposed.evidence.port)
      if (port === null) continue

      candidates.push({
        rule: CORRELATION_RULES.exposedRemoteManagement,
        key: `${assetId}|${port}`,
        projectId: endpoint.projectId,
        title: `Remote management exposed with authentication failures on ${endpoint.assetName}`,
        summary: `Network discovery found port ${port} open on ${ipAddress}, and the endpoint at that address recorded ${totalAttempts} failed authentication attempts in the last ${AUTH_WINDOW_HOURS} hours.`,
        reason: `Correlation rule "${CORRELATION_RULES.exposedRemoteManagement}" matched the network service finding on ${ipAddress}:${port} with ${authGroup.length} authentication finding(s) on the endpoint that owns that address. The address relationship comes from the enrolled Wazuh agent; this is related activity, not proof of intrusion.`,
        severity: "high",
        evidence: {
          rule: CORRELATION_RULES.exposedRemoteManagement,
          ipAddress,
          port,
          totalAuthAttempts: totalAttempts,
          networkStableKey: exposed.stableKey,
          networkFindingId: exposed.id,
        },
        findingIds: uniqueSorted([
          ...authGroup.map((finding) => finding.id),
          exposed.id,
        ]),
        eventIds: uniqueSorted(
          authEvents
            .filter((event) => event.assetId === assetId)
            .map((event) => event.id)
        ),
        findingReasons: {
          ...Object.fromEntries(
            authGroup.map((finding) => [
              finding.id,
              `Authentication failures on the endpoint at ${ipAddress}, where port ${port} is exposed.`,
            ])
          ),
          [exposed.id]: `Port ${port} is open on ${ipAddress}, the address of the endpoint with repeated authentication failures.`,
        },
      })
    }
  }

  // R3: secret finding in a production project that explicitly owns a domain.
  const domainsByProject = groupedBy(
    assets.filter((asset) => asset.type === "domain"),
    (asset) => asset.projectId
  )
  const secretsByProject = groupedBy(
    findings.filter((finding) => finding.category === "secret"),
    (finding) => finding.projectId
  )

  for (const [projectId, group] of secretsByProject) {
    const domains = domainsByProject.get(projectId)
    if (!domains || domains.length === 0) continue

    const first = group[0]
    if (first.projectEnvironment !== "production") continue

    const domainNames = uniqueSorted(domains.map((domain) => domain.identifier))

    candidates.push({
      rule: CORRELATION_RULES.secretInProduction,
      key: projectId,
      projectId,
      title: `Secret findings in production project ${first.projectName}`,
      summary: `${group.length} open secret finding(s) exist in ${first.projectName}, which explicitly owns ${domainNames.length} domain asset(s).`,
      reason: `Correlation rule "${CORRELATION_RULES.secretInProduction}" requires both a secret finding and an explicitly attached domain in the same production project. Domains: ${domainNames.join(", ")}. The association is configured by you and does not prove the secret is live or exposed.`,
      severity: maxSeverity(
        group.map((finding) => finding.severity),
        "high"
      ),
      evidence: {
        rule: CORRELATION_RULES.secretInProduction,
        environment: first.projectEnvironment,
        domains: domainNames,
        secretFindingCount: group.length,
        stableKeys: group.map((finding) => finding.stableKey),
      },
      findingIds: uniqueSorted(group.map((finding) => finding.id)),
      eventIds: [],
      findingReasons: Object.fromEntries(
        group.map((finding) => [
          finding.id,
          "Secret finding in a production project that explicitly owns internet-facing domains.",
        ])
      ),
    })
  }

  // R4: multiple high/critical findings on one asset within a week.
  const highRisk = findings.filter(
    (finding) =>
      (finding.severity === "high" || finding.severity === "critical") &&
      withinWindow(finding.lastSeenAt, now, CLUSTER_WINDOW_HOURS)
  )
  const highRiskByAsset = groupedBy(highRisk, (finding) => finding.assetId)

  for (const [assetId, group] of highRiskByAsset) {
    if (group.length < 3) continue

    const asset = group[0]
    const hasCritical = group.some((finding) => finding.severity === "critical")

    candidates.push({
      rule: CORRELATION_RULES.assetHighRiskCluster,
      key: assetId,
      projectId: asset.projectId,
      title: `${group.length} high-risk findings on ${asset.assetName}`,
      summary: `${group.length} high or critical open findings affect ${asset.assetName} within the last ${CLUSTER_WINDOW_HOURS / 24} days.`,
      reason: `Correlation rule "${CORRELATION_RULES.assetHighRiskCluster}" grouped ${group.length} high/critical findings on the same asset within the ${CLUSTER_WINDOW_HOURS / 24}-day window. Multiple issues on one asset increase exposure but do not by themselves prove an attack.`,
      severity: hasCritical ? "critical" : "high",
      evidence: {
        rule: CORRELATION_RULES.assetHighRiskCluster,
        windowHours: CLUSTER_WINDOW_HOURS,
        findingCount: group.length,
        stableKeys: group.map((finding) => finding.stableKey),
      },
      findingIds: uniqueSorted(group.map((finding) => finding.id)),
      eventIds: [],
      findingReasons: Object.fromEntries(
        group.map((finding) => [
          finding.id,
          `High-risk finding on the same asset within the ${CLUSTER_WINDOW_HOURS / 24}-day window.`,
        ])
      ),
    })
  }

  // R5: authentication event burst from one source IP against one asset.
  const eventsBySource = groupedBy(
    authEvents,
    (event) => `${event.assetId}|${event.sourceIp}`
  )

  for (const [key, group] of eventsBySource) {
    if (group.length < AUTH_EVENT_THRESHOLD) continue

    const event = group[0]
    const sourceIp = event.sourceIp as string
    const relatedFindings = findings.filter(
      (finding) =>
        finding.assetId === event.assetId &&
        finding.category === "authentication" &&
        withinWindow(finding.lastSeenAt, now, AUTH_WINDOW_HOURS)
    )

    candidates.push({
      rule: CORRELATION_RULES.sourceAuthBurst,
      key,
      projectId: event.projectId,
      title: `Authentication attempts from ${sourceIp} against ${event.assetName}`,
      summary: `${group.length} authentication events from ${sourceIp} targeted ${event.assetName} within ${AUTH_WINDOW_HOURS} hours.`,
      reason: `Correlation rule "${CORRELATION_RULES.sourceAuthBurst}" grouped ${group.length} Wazuh authentication events from the same source IP against the same asset within ${AUTH_WINDOW_HOURS} hours. This is related activity; it does not prove the attempts succeeded.`,
      severity: group.length >= AUTH_EVENT_HIGH_THRESHOLD ? "high" : "medium",
      evidence: {
        rule: CORRELATION_RULES.sourceAuthBurst,
        windowHours: AUTH_WINDOW_HOURS,
        sourceIp,
        eventCount: group.length,
        wazuhRuleIds: uniqueSorted(
          group
            .map((entry) => entry.ruleId)
            .filter((ruleId): ruleId is string => Boolean(ruleId))
        ),
      },
      findingIds: uniqueSorted(relatedFindings.map((finding) => finding.id)),
      eventIds: uniqueSorted(group.map((entry) => entry.id)),
      findingReasons: Object.fromEntries(
        relatedFindings.map((finding) => [
          finding.id,
          `Authentication activity on this asset from source ${sourceIp} within ${AUTH_WINDOW_HOURS} hours.`,
        ])
      ),
    })
  }

  return candidates.sort(
    (a, b) => a.rule.localeCompare(b.rule) || a.key.localeCompare(b.key)
  )
}
