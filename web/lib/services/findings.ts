import "server-only"

import { and, count, desc, eq, ilike, inArray, or } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  finding,
  findingEvidence,
  findingStatusEvent,
  project,
  scanRun,
  type FindingRow,
  type ScanRun,
  type FindingSeverity,
  type FindingStatus,
} from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { recordAudit } from "@/lib/services/audit"
import type { FindingFilter } from "@/lib/validation/schemas"
import type { WorkspaceRole } from "@/lib/db/schema"

export const OPEN_FINDING_STATUSES: FindingStatus[] = [
  "open",
  "acknowledged",
  "in_progress",
]

export type FindingListItem = {
  finding: FindingRow
  assetName: string
  assetType: string
  projectId: string
  projectName: string
}

export type FindingPage = {
  items: FindingListItem[]
  total: number
  limit: number
  offset: number
}

function filterConditions(workspaceId: string, filter: FindingFilter) {
  const conditions = [eq(finding.workspaceId, workspaceId)]

  if (filter.severity) conditions.push(eq(finding.severity, filter.severity))
  if (filter.status) conditions.push(eq(finding.status, filter.status))
  if (filter.source) conditions.push(eq(finding.source, filter.source))
  if (filter.projectId) conditions.push(eq(finding.projectId, filter.projectId))

  if (filter.q) {
    const pattern = `%${filter.q}%`
    const search = or(
      ilike(finding.title, pattern),
      ilike(finding.stableKey, pattern),
      ilike(finding.sourceRuleId, pattern)
    )
    if (search) conditions.push(search)
  }

  return and(...conditions)
}

export async function listFindings(
  workspaceId: string,
  filter: FindingFilter,
  pagination: { limit: number; offset: number }
): Promise<FindingPage> {
  const where = filterConditions(workspaceId, filter)
  const db = getDb()

  const [rows, totals] = await Promise.all([
    db
      .select({
        finding,
        assetName: asset.displayName,
        assetType: asset.type,
        projectId: project.id,
        projectName: project.name,
      })
      .from(finding)
      .innerJoin(asset, eq(asset.id, finding.assetId))
      .innerJoin(project, eq(project.id, finding.projectId))
      .where(where)
      .orderBy(desc(finding.lastSeenAt))
      .limit(pagination.limit)
      .offset(pagination.offset),
    db.select({ value: count() }).from(finding).where(where),
  ])

  return {
    items: rows,
    total: totals[0]?.value ?? 0,
    limit: pagination.limit,
    offset: pagination.offset,
  }
}

export type FindingCounts = {
  total: number
  bySeverity: Record<FindingSeverity, number>
}

export async function getFindingCounts(
  workspaceId: string
): Promise<FindingCounts> {
  const rows = await getDb()
    .select({ severity: finding.severity, value: count() })
    .from(finding)
    .where(
      and(
        eq(finding.workspaceId, workspaceId),
        inArray(finding.status, OPEN_FINDING_STATUSES)
      )
    )
    .groupBy(finding.severity)

  const bySeverity: Record<FindingSeverity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
  }

  let total = 0
  for (const row of rows) {
    bySeverity[row.severity] = row.value
    total += row.value
  }

  return { total, bySeverity }
}

export type FindingDetail = FindingListItem & {
  evidence: typeof findingEvidence.$inferSelect | null
  scanRun: ScanRun | null
  events: Array<typeof findingStatusEvent.$inferSelect>
}

export async function getFinding(
  workspaceId: string,
  findingId: string
): Promise<FindingDetail | null> {
  const db = getDb()

  const [row] = await db
    .select({
      finding,
      assetName: asset.displayName,
      assetType: asset.type,
      projectId: project.id,
      projectName: project.name,
    })
    .from(finding)
    .innerJoin(asset, eq(asset.id, finding.assetId))
    .innerJoin(project, eq(project.id, finding.projectId))
    .where(and(eq(finding.workspaceId, workspaceId), eq(finding.id, findingId)))
    .limit(1)

  if (!row) return null

  const [evidence] = await db
    .select()
    .from(findingEvidence)
    .where(eq(findingEvidence.findingId, findingId))
    .limit(1)

  const events = await db
    .select()
    .from(findingStatusEvent)
    .where(eq(findingStatusEvent.findingId, findingId))
    .orderBy(desc(findingStatusEvent.createdAt))
    .limit(20)

  let run: ScanRun | null = null
  if (evidence?.scanRunId) {
    const [row] = await db
      .select()
      .from(scanRun)
      .where(eq(scanRun.id, evidence.scanRunId))
      .limit(1)
    run = row ?? null
  }

  return { ...row, evidence: evidence ?? null, scanRun: run, events }
}

export async function updateFindingStatus(input: {
  workspaceId: string
  findingId: string
  actorUserId: string
  actorRole: WorkspaceRole
  status: FindingStatus
  note?: string
}): Promise<FindingRow | null> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "Only workspace admins can change finding status."
    )
  }

  const db = getDb()

  const [existing] = await db
    .select()
    .from(finding)
    .where(
      and(
        eq(finding.workspaceId, input.workspaceId),
        eq(finding.id, input.findingId)
      )
    )
    .limit(1)

  if (!existing) return null
  if (existing.status === input.status) return existing

  const resolved = input.status === "resolved"

  const [updated] = await db
    .update(finding)
    .set({
      status: input.status,
      resolvedAt: resolved ? new Date() : null,
      updatedAt: new Date(),
    })
    .where(eq(finding.id, existing.id))
    .returning()

  await db.insert(findingStatusEvent).values({
    findingId: existing.id,
    fromStatus: existing.status,
    toStatus: input.status,
    actorUserId: input.actorUserId,
    note: input.note ?? null,
  })

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "finding.status_changed",
    targetType: "finding",
    targetId: existing.id,
    metadata: { from: existing.status, to: input.status },
  })

  return updated
}
