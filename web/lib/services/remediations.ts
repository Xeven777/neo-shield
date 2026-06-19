import "server-only"

import { and, desc, eq, inArray } from "drizzle-orm"
import { alias } from "drizzle-orm/pg-core"

import { getDb } from "@/lib/db"
import {
  asset,
  finding,
  incidentFinding,
  remediation,
  remediationEvent,
  scanRun,
  user,
  workspaceMember,
  type Remediation,
  type RemediationStatus,
} from "@/lib/db/schema"
import { recordAudit } from "@/lib/services/audit"

export const OPEN_REMEDIATION_STATUSES: RemediationStatus[] = [
  "planned",
  "in_progress",
  "fixed",
]

const creator = alias(user, "remediation_creator")
const owner = alias(user, "remediation_owner")

export type RemediationEventItem = {
  event: typeof remediationEvent.$inferSelect
  actorName: string | null
}

export type RemediationItem = {
  remediation: Remediation
  findingTitle: string
  assetName: string
  creatorName: string | null
  ownerName: string | null
  verifiedRun: typeof scanRun.$inferSelect | null
  events: RemediationEventItem[]
}

type RemediationRow = {
  remediation: Remediation
  findingTitle: string
  assetName: string
  creatorName: string | null
  ownerName: string | null
}

async function attachDetails(
  rows: RemediationRow[]
): Promise<RemediationItem[]> {
  if (rows.length === 0) return []

  const db = getDb()
  const ids = rows.map((row) => row.remediation.id)
  const runIds = rows
    .map((row) => row.remediation.verifiedScanRunId)
    .filter((id): id is string => Boolean(id))

  const [eventRows, runs] = await Promise.all([
    db
      .select({ event: remediationEvent, actorName: user.name })
      .from(remediationEvent)
      .leftJoin(user, eq(user.id, remediationEvent.actorUserId))
      .where(inArray(remediationEvent.remediationId, ids))
      .orderBy(desc(remediationEvent.createdAt)),
    runIds.length > 0
      ? db.select().from(scanRun).where(inArray(scanRun.id, runIds))
      : Promise.resolve([]),
  ])

  const eventsByRemediation = new Map<string, RemediationEventItem[]>()
  for (const row of eventRows) {
    const group = eventsByRemediation.get(row.event.remediationId) ?? []
    group.push(row)
    eventsByRemediation.set(row.event.remediationId, group)
  }

  const runById = new Map(runs.map((run) => [run.id, run]))

  return rows.map((row) => ({
    ...row,
    verifiedRun: row.remediation.verifiedScanRunId
      ? (runById.get(row.remediation.verifiedScanRunId) ?? null)
      : null,
    events: eventsByRemediation.get(row.remediation.id) ?? [],
  }))
}

async function listRows(
  where: ReturnType<typeof and>
): Promise<RemediationRow[]> {
  return getDb()
    .select({
      remediation,
      findingTitle: finding.title,
      assetName: asset.displayName,
      creatorName: creator.name,
      ownerName: owner.name,
    })
    .from(remediation)
    .innerJoin(finding, eq(finding.id, remediation.findingId))
    .innerJoin(asset, eq(asset.id, finding.assetId))
    .leftJoin(creator, eq(creator.id, remediation.createdByUserId))
    .leftJoin(owner, eq(owner.id, remediation.ownerUserId))
    .where(where)
    .orderBy(desc(remediation.updatedAt))
}

export async function listFindingRemediations(
  workspaceId: string,
  findingId: string
): Promise<RemediationItem[]> {
  const rows = await listRows(
    and(
      eq(remediation.workspaceId, workspaceId),
      eq(remediation.findingId, findingId)
    )
  )
  return attachDetails(rows)
}

export async function listIncidentRemediations(
  workspaceId: string,
  incidentId: string
): Promise<RemediationItem[]> {
  const links = await getDb()
    .select({ findingId: incidentFinding.findingId })
    .from(incidentFinding)
    .where(eq(incidentFinding.incidentId, incidentId))

  if (links.length === 0) return []

  const rows = await listRows(
    and(
      eq(remediation.workspaceId, workspaceId),
      inArray(
        remediation.findingId,
        links.map((link) => link.findingId)
      )
    )
  )
  return attachDetails(rows)
}

export async function listProjectRemediations(
  workspaceId: string,
  projectId: string
): Promise<RemediationItem[]> {
  const findingRows = await getDb()
    .select({ id: finding.id })
    .from(finding)
    .where(
      and(eq(finding.workspaceId, workspaceId), eq(finding.projectId, projectId))
    )

  if (findingRows.length === 0) return []

  const rows = await listRows(
    and(
      eq(remediation.workspaceId, workspaceId),
      inArray(
        remediation.findingId,
        findingRows.map((row) => row.id)
      )
    )
  )
  return attachDetails(rows)
}

async function isWorkspaceMember(workspaceId: string, userId: string) {
  const [row] = await getDb()
    .select({ id: workspaceMember.id })
    .from(workspaceMember)
    .where(
      and(
        eq(workspaceMember.workspaceId, workspaceId),
        eq(workspaceMember.userId, userId)
      )
    )
    .limit(1)
  return row !== undefined
}

export async function createRemediation(input: {
  workspaceId: string
  actorUserId: string
  findingId: string
  recommendation: string
  ownerUserId: string | null
}): Promise<Remediation | null> {
  const db = getDb()

  const [target] = await db
    .select({ id: finding.id })
    .from(finding)
    .where(
      and(
        eq(finding.workspaceId, input.workspaceId),
        eq(finding.id, input.findingId)
      )
    )
    .limit(1)

  if (!target) return null

  if (
    input.ownerUserId &&
    !(await isWorkspaceMember(input.workspaceId, input.ownerUserId))
  ) {
    throw new Error("The selected owner is not a workspace member.")
  }

  const [created] = await db
    .insert(remediation)
    .values({
      workspaceId: input.workspaceId,
      findingId: input.findingId,
      recommendation: input.recommendation,
      ownerUserId: input.ownerUserId,
      createdByUserId: input.actorUserId,
      status: "planned",
    })
    .returning()

  await db.insert(remediationEvent).values({
    remediationId: created.id,
    fromStatus: null,
    toStatus: "planned",
    actorUserId: input.actorUserId,
    note: "Remediation planned.",
  })

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "remediation.created",
    targetType: "remediation",
    targetId: created.id,
    metadata: {
      findingId: input.findingId,
      ownerUserId: input.ownerUserId,
    },
  })

  return created
}

export async function updateRemediationStatus(input: {
  workspaceId: string
  remediationId: string
  actorUserId: string
  status: RemediationStatus
  note?: string
}): Promise<Remediation | null> {
  const db = getDb()

  const [existing] = await db
    .select()
    .from(remediation)
    .where(
      and(
        eq(remediation.workspaceId, input.workspaceId),
        eq(remediation.id, input.remediationId)
      )
    )
    .limit(1)

  if (!existing) return null
  if (existing.status === input.status) return existing

  const now = new Date()
  const [updated] = await db
    .update(remediation)
    .set({
      status: input.status,
      // Verification by a scan is written by the worker and keeps its run id.
      // A manual "verified" never invents a scan reference.
      verifiedScanRunId:
        input.status === "verified" ? existing.verifiedScanRunId : null,
      verifiedAt: input.status === "verified" ? now : null,
      updatedAt: now,
    })
    .where(eq(remediation.id, existing.id))
    .returning()

  await db.insert(remediationEvent).values({
    remediationId: existing.id,
    fromStatus: existing.status,
    toStatus: input.status,
    actorUserId: input.actorUserId,
    note: input.note ?? null,
  })

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "remediation.status_changed",
    targetType: "remediation",
    targetId: existing.id,
    metadata: { from: existing.status, to: input.status },
  })

  return updated
}

export async function countOpenRemediations(workspaceId: string) {
  const rows = await getDb()
    .select({ id: remediation.id })
    .from(remediation)
    .where(
      and(
        eq(remediation.workspaceId, workspaceId),
        inArray(remediation.status, OPEN_REMEDIATION_STATUSES)
      )
    )
  return rows.length
}
