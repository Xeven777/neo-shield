import "server-only"

import {
  and,
  count,
  desc,
  eq,
  gte,
  ilike,
  inArray,
  isNotNull,
  notInArray,
  or,
} from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  endpointAgent,
  finding,
  findingEvidence,
  incident,
  incidentEvent,
  incidentFinding,
  incidentSecurityEvent,
  project,
  securityEvent,
  user,
  type Incident,
  type IncidentFinding,
  type IncidentStatus,
  type WorkspaceRole,
} from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { recordAudit } from "@/lib/services/audit"
import { OPEN_FINDING_STATUSES } from "@/lib/services/findings"
import {
  AUTH_WINDOW_HOURS,
  correlate,
  type CorrelationAsset,
  type CorrelationEvent,
  type CorrelationFinding,
} from "@/lib/intelligence/correlation"
import type { IncidentFilter } from "@/lib/validation/schemas"

export type IncidentListItem = {
  incident: Incident
  projectName: string
  findingCount: number
}

export type IncidentPage = {
  items: IncidentListItem[]
  total: number
  limit: number
  offset: number
}

export type IncidentFindingItem = {
  link: IncidentFinding
  finding: typeof finding.$inferSelect
  assetName: string
  assetType: string
}

export type IncidentEventItem = {
  event: typeof incidentEvent.$inferSelect
  actorName: string | null
}

export type IncidentDetail = IncidentListItem & {
  findings: IncidentFindingItem[]
  events: IncidentEventItem[]
  securityEvents: Array<{
    link: typeof incidentSecurityEvent.$inferSelect
    event: typeof securityEvent.$inferSelect
  }>
  ownerName: string | null
}

export type IncidentCounts = {
  total: number
  byStatus: Record<IncidentStatus, number>
  active: number
}

const ACTIVE_STATUSES: IncidentStatus[] = ["new", "investigating", "contained"]

function incidentConditions(workspaceId: string, filter: IncidentFilter) {
  const conditions = [eq(incident.workspaceId, workspaceId)]

  if (filter.status) conditions.push(eq(incident.status, filter.status))
  if (filter.severity) conditions.push(eq(incident.severity, filter.severity))
  if (filter.projectId)
    conditions.push(eq(incident.projectId, filter.projectId))

  if (filter.q) {
    const pattern = `%${filter.q}%`
    const search = or(
      ilike(incident.title, pattern),
      ilike(incident.reason, pattern),
      ilike(incident.correlationRule, pattern)
    )
    if (search) conditions.push(search)
  }

  return and(...conditions)
}

export async function listIncidents(
  workspaceId: string,
  filter: IncidentFilter,
  pagination: { limit: number; offset: number }
): Promise<IncidentPage> {
  const where = incidentConditions(workspaceId, filter)
  const db = getDb()

  const [rows, totals] = await Promise.all([
    db
      .select({
        incident,
        projectName: project.name,
        findingCount: count(incidentFinding.id),
      })
      .from(incident)
      .innerJoin(project, eq(project.id, incident.projectId))
      .leftJoin(incidentFinding, eq(incidentFinding.incidentId, incident.id))
      .where(where)
      .groupBy(incident.id, project.name)
      .orderBy(desc(incident.lastDetectedAt))
      .limit(pagination.limit)
      .offset(pagination.offset),
    db.select({ value: count() }).from(incident).where(where),
  ])

  return {
    items: rows,
    total: totals[0]?.value ?? 0,
    limit: pagination.limit,
    offset: pagination.offset,
  }
}

export async function getIncidentCounts(
  workspaceId: string
): Promise<IncidentCounts> {
  const rows = await getDb()
    .select({ status: incident.status, value: count() })
    .from(incident)
    .where(eq(incident.workspaceId, workspaceId))
    .groupBy(incident.status)

  const byStatus: Record<IncidentStatus, number> = {
    new: 0,
    investigating: 0,
    contained: 0,
    resolved: 0,
    closed: 0,
  }

  let total = 0
  for (const row of rows) {
    byStatus[row.status] = row.value
    total += row.value
  }

  return {
    total,
    byStatus,
    active: ACTIVE_STATUSES.reduce((sum, status) => sum + byStatus[status], 0),
  }
}

export async function getIncident(
  workspaceId: string,
  incidentId: string
): Promise<IncidentDetail | null> {
  const db = getDb()

  const [row] = await db
    .select({
      incident,
      projectName: project.name,
      ownerName: user.name,
    })
    .from(incident)
    .innerJoin(project, eq(project.id, incident.projectId))
    .leftJoin(user, eq(user.id, incident.ownerUserId))
    .where(
      and(eq(incident.workspaceId, workspaceId), eq(incident.id, incidentId))
    )
    .limit(1)

  if (!row) return null

  const [findingRows, eventRows, linkCount, securityEventRows] =
    await Promise.all([
      db
        .select({
          link: incidentFinding,
          finding,
          assetName: asset.displayName,
          assetType: asset.type,
        })
        .from(incidentFinding)
        .innerJoin(finding, eq(finding.id, incidentFinding.findingId))
        .innerJoin(asset, eq(asset.id, finding.assetId))
        .where(eq(incidentFinding.incidentId, incidentId))
        .orderBy(desc(finding.lastSeenAt)),
      db
        .select({ event: incidentEvent, actorName: user.name })
        .from(incidentEvent)
        .leftJoin(user, eq(user.id, incidentEvent.actorUserId))
        .where(eq(incidentEvent.incidentId, incidentId))
        .orderBy(desc(incidentEvent.createdAt)),
      db
        .select({ value: count() })
        .from(incidentFinding)
        .where(eq(incidentFinding.incidentId, incidentId)),
      db
        .select({ link: incidentSecurityEvent, event: securityEvent })
        .from(incidentSecurityEvent)
        .innerJoin(
          securityEvent,
          eq(securityEvent.id, incidentSecurityEvent.securityEventId)
        )
        .where(eq(incidentSecurityEvent.incidentId, incidentId))
        .orderBy(desc(securityEvent.eventTime)),
    ])

  return {
    ...row,
    ownerName: row.ownerName ?? null,
    findingCount: linkCount[0]?.value ?? 0,
    findings: findingRows,
    events: eventRows,
    securityEvents: securityEventRows,
  }
}

async function addEvent(input: {
  incidentId: string
  type:
    | "created"
    | "signal_changed"
    | "status_changed"
    | "note"
    | "auto_resolved"
    | "reopened"
  fromStatus?: IncidentStatus | null
  toStatus?: IncidentStatus | null
  actorUserId?: string | null
  note?: string | null
}) {
  await getDb()
    .insert(incidentEvent)
    .values({
      incidentId: input.incidentId,
      type: input.type,
      fromStatus: input.fromStatus ?? null,
      toStatus: input.toStatus ?? null,
      actorUserId: input.actorUserId ?? null,
      note: input.note ?? null,
    })
}

async function syncIncidentFindings(
  candidate: ReturnType<typeof correlate>[number],
  incidentId: string
): Promise<{ added: number; removed: number }> {
  const db = getDb()

  const existing = await db
    .select({ findingId: incidentFinding.findingId })
    .from(incidentFinding)
    .where(eq(incidentFinding.incidentId, incidentId))

  const currentIds = new Set(existing.map((row) => row.findingId))
  const desired = new Map(
    candidate.findingIds.map((findingId) => [
      findingId,
      candidate.findingReasons[findingId] ?? "Related finding.",
    ])
  )

  const toAdd = [...desired.entries()].filter(
    ([findingId]) => !currentIds.has(findingId)
  )
  const toRemove = [...currentIds].filter(
    (findingId) => !desired.has(findingId)
  )

  if (toAdd.length > 0) {
    await db
      .insert(incidentFinding)
      .values(
        toAdd.map(([findingId, reason]) => ({
          incidentId,
          findingId,
          reason,
        }))
      )
      .onConflictDoNothing()
  }

  if (toRemove.length > 0) {
    await db
      .delete(incidentFinding)
      .where(
        and(
          eq(incidentFinding.incidentId, incidentId),
          inArray(incidentFinding.findingId, toRemove)
        )
      )
  }

  return { added: toAdd.length, removed: toRemove.length }
}

async function syncIncidentEvents(
  candidate: ReturnType<typeof correlate>[number],
  incidentId: string
): Promise<{ added: number; removed: number }> {
  const db = getDb()

  const existing = await db
    .select({ securityEventId: incidentSecurityEvent.securityEventId })
    .from(incidentSecurityEvent)
    .where(eq(incidentSecurityEvent.incidentId, incidentId))

  const currentIds = new Set(existing.map((row) => row.securityEventId))
  const desired = new Set(candidate.eventIds)

  const toAdd = [...desired].filter((eventId) => !currentIds.has(eventId))
  const toRemove = [...currentIds].filter((eventId) => !desired.has(eventId))

  if (toAdd.length > 0) {
    await db
      .insert(incidentSecurityEvent)
      .values(
        toAdd.map((securityEventId) => ({
          incidentId,
          securityEventId,
          reason: `Security event matched correlation rule "${candidate.rule}".`,
        }))
      )
      .onConflictDoNothing()
  }

  if (toRemove.length > 0) {
    await db
      .delete(incidentSecurityEvent)
      .where(
        and(
          eq(incidentSecurityEvent.incidentId, incidentId),
          inArray(incidentSecurityEvent.securityEventId, toRemove)
        )
      )
  }

  return { added: toAdd.length, removed: toRemove.length }
}

async function loadCorrelationInput(workspaceId: string, now: Date) {
  const db = getDb()

  const eventFloor = new Date(
    now.getTime() - AUTH_WINDOW_HOURS * 60 * 60 * 1000
  )

  const [findingRows, assetRows, addressRows, eventRows] = await Promise.all([
    db
      .select({
        id: finding.id,
        projectId: finding.projectId,
        projectName: project.name,
        projectEnvironment: project.environment,
        assetId: finding.assetId,
        assetName: asset.displayName,
        assetType: asset.type,
        source: finding.source,
        sourceTool: finding.sourceTool,
        stableKey: finding.stableKey,
        title: finding.title,
        category: finding.category,
        severity: finding.severity,
        occurrenceCount: finding.occurrenceCount,
        firstSeenAt: finding.firstSeenAt,
        lastSeenAt: finding.lastSeenAt,
        evidence: findingEvidence.evidence,
      })
      .from(finding)
      .innerJoin(asset, eq(asset.id, finding.assetId))
      .innerJoin(project, eq(project.id, finding.projectId))
      .leftJoin(findingEvidence, eq(findingEvidence.findingId, finding.id))
      .where(
        and(
          eq(finding.workspaceId, workspaceId),
          inArray(finding.status, OPEN_FINDING_STATUSES)
        )
      ),
    db
      .select({
        id: asset.id,
        projectId: asset.projectId,
        projectName: project.name,
        projectEnvironment: project.environment,
        type: asset.type,
        displayName: asset.displayName,
        identifier: asset.identifier,
      })
      .from(asset)
      .innerJoin(project, eq(project.id, asset.projectId))
      .where(eq(project.workspaceId, workspaceId)),
    db
      .select({
        assetId: endpointAgent.assetId,
        ipAddress: endpointAgent.ipAddress,
      })
      .from(endpointAgent)
      .where(
        and(
          eq(endpointAgent.workspaceId, workspaceId),
          isNotNull(endpointAgent.ipAddress)
        )
      ),
    db
      .select({
        id: securityEvent.id,
        projectId: securityEvent.projectId,
        assetId: securityEvent.assetId,
        assetName: asset.displayName,
        sourceIp: securityEvent.sourceIp,
        category: securityEvent.category,
        ruleId: securityEvent.ruleId,
        severity: securityEvent.severity,
        eventTime: securityEvent.eventTime,
      })
      .from(securityEvent)
      .innerJoin(asset, eq(asset.id, securityEvent.assetId))
      .where(
        and(
          eq(securityEvent.workspaceId, workspaceId),
          gte(securityEvent.eventTime, eventFloor)
        )
      ),
  ])

  return {
    findings: findingRows.map<CorrelationFinding>((row) => ({
      ...row,
      evidence: row.evidence ?? {},
    })),
    assets: assetRows as CorrelationAsset[],
    endpointAddresses: addressRows.map((row) => ({
      assetId: row.assetId,
      ipAddress: row.ipAddress as string,
    })),
    events: eventRows as CorrelationEvent[],
  }
}

/**
 * Re-runs the deterministic rules and reconciles incidents: new signals create
 * incidents, changed signals update links, disappeared signals auto-resolve an
 * incident with a system timeline entry. User statuses are never overwritten
 * while signals still exist.
 */
export async function refreshIncidents(
  workspaceId: string
): Promise<{ created: number; updated: number; resolved: number }> {
  const db = getDb()
  const now = new Date()
  const input = await loadCorrelationInput(workspaceId, now)
  const candidates = correlate({ ...input, now })

  const existing = await db
    .select({
      id: incident.id,
      correlationRule: incident.correlationRule,
      correlationKey: incident.correlationKey,
      status: incident.status,
      severity: incident.severity,
      title: incident.title,
    })
    .from(incident)
    .where(eq(incident.workspaceId, workspaceId))

  const existingByKey = new Map(
    existing.map((row) => [`${row.correlationRule}|${row.correlationKey}`, row])
  )
  const candidateKeys = new Set<string>()
  let created = 0
  let updated = 0

  for (const candidate of candidates) {
    const identity = `${candidate.rule}|${candidate.key}`
    candidateKeys.add(identity)
    const previous = existingByKey.get(identity)

    let incidentId: string

    if (!previous) {
      const [inserted] = await db
        .insert(incident)
        .values({
          workspaceId,
          projectId: candidate.projectId,
          correlationRule: candidate.rule,
          correlationKey: candidate.key,
          title: candidate.title,
          summary: candidate.summary,
          reason: candidate.reason,
          severity: candidate.severity,
          evidence: candidate.evidence,
          firstDetectedAt: now,
          lastDetectedAt: now,
        })
        .onConflictDoUpdate({
          target: [
            incident.workspaceId,
            incident.correlationRule,
            incident.correlationKey,
          ],
          set: {
            projectId: candidate.projectId,
            title: candidate.title,
            summary: candidate.summary,
            reason: candidate.reason,
            severity: candidate.severity,
            evidence: candidate.evidence,
            lastDetectedAt: now,
            updatedAt: now,
          },
        })
        .returning({ id: incident.id })

      incidentId = inserted.id
      created += 1

      await addEvent({
        incidentId,
        type: "created",
        note: `Correlation rule "${candidate.rule}" grouped the first related findings. ${candidate.reason}`,
      })
    } else {
      incidentId = previous.id
      updated += 1

      await db
        .update(incident)
        .set({
          projectId: candidate.projectId,
          title: candidate.title,
          summary: candidate.summary,
          reason: candidate.reason,
          severity: candidate.severity,
          evidence: candidate.evidence,
          lastDetectedAt: now,
          updatedAt: now,
        })
        .where(eq(incident.id, incidentId))
    }

    const links = await syncIncidentFindings(candidate, incidentId)
    if (links.added > 0 || links.removed > 0) {
      await addEvent({
        incidentId,
        type: "signal_changed",
        note: `Related findings updated: ${links.added} added, ${links.removed} removed.`,
      })
    }
  }

  let resolved = 0

  for (const row of existing) {
    const identity = `${row.correlationRule}|${row.correlationKey}`
    if (candidateKeys.has(identity)) continue
    if (row.status === "resolved" || row.status === "closed") continue

    await db
      .update(incident)
      .set({
        status: "resolved",
        resolvedAt: now,
        updatedAt: now,
      })
      .where(eq(incident.id, row.id))

    await addEvent({
      incidentId: row.id,
      type: "auto_resolved",
      fromStatus: row.status,
      toStatus: "resolved",
      note: `No open findings currently match "${row.correlationRule}". The incident is closed automatically; history is kept.`,
    })

    resolved += 1
  }

  return { created, updated, resolved }
}

export async function updateIncidentStatus(input: {
  workspaceId: string
  incidentId: string
  actorUserId: string
  actorRole: WorkspaceRole
  status: IncidentStatus
  note?: string
}): Promise<Incident | null> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "Only workspace admins can change incident status."
    )
  }

  const db = getDb()

  const [existing] = await db
    .select()
    .from(incident)
    .where(
      and(
        eq(incident.workspaceId, input.workspaceId),
        eq(incident.id, input.incidentId)
      )
    )
    .limit(1)

  if (!existing) return null
  if (existing.status === input.status) return existing

  const closed = input.status === "resolved" || input.status === "closed"
  const now = new Date()

  const [updated] = await db
    .update(incident)
    .set({
      status: input.status,
      resolvedAt: closed ? now : null,
      updatedAt: now,
    })
    .where(eq(incident.id, existing.id))
    .returning()

  await addEvent({
    incidentId: existing.id,
    type: "status_changed",
    fromStatus: existing.status,
    toStatus: input.status,
    actorUserId: input.actorUserId,
    note: input.note ?? null,
  })

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "incident.status_changed",
    targetType: "incident",
    targetId: existing.id,
    metadata: { from: existing.status, to: input.status },
  })

  return updated
}

export async function addIncidentNote(input: {
  workspaceId: string
  incidentId: string
  actorUserId: string
  note: string
}): Promise<typeof incidentEvent.$inferSelect | null> {
  const db = getDb()

  const [existing] = await db
    .select({ id: incident.id })
    .from(incident)
    .where(
      and(
        eq(incident.workspaceId, input.workspaceId),
        eq(incident.id, input.incidentId)
      )
    )
    .limit(1)

  if (!existing) return null

  const [event] = await db
    .insert(incidentEvent)
    .values({
      incidentId: existing.id,
      type: "note",
      actorUserId: input.actorUserId,
      note: input.note,
    })
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "incident.note_added",
    targetType: "incident",
    targetId: existing.id,
  })

  return event
}

/** Incidents that still have signals; used by the overview and API. */
export async function listActiveIncidents(workspaceId: string, limit = 3) {
  return getDb()
    .select({
      incident,
      projectName: project.name,
      findingCount: count(incidentFinding.id),
    })
    .from(incident)
    .innerJoin(project, eq(project.id, incident.projectId))
    .leftJoin(incidentFinding, eq(incidentFinding.incidentId, incident.id))
    .where(
      and(
        eq(incident.workspaceId, workspaceId),
        notInArray(incident.status, ["resolved", "closed"])
      )
    )
    .groupBy(incident.id, project.name)
    .orderBy(desc(incident.lastDetectedAt))
    .limit(limit)
}
