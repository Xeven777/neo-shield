import "server-only"

import { and, count, desc, eq, ilike, or } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  project,
  securityEvent,
  type FindingSeverity,
  type SecurityEvent,
} from "@/lib/db/schema"
import type { EventFilter } from "@/lib/validation/schemas"

export type SecurityEventListItem = {
  event: SecurityEvent
  assetName: string
  assetType: string
  projectId: string
  projectName: string
}

export type SecurityEventPage = {
  items: SecurityEventListItem[]
  total: number
  limit: number
  offset: number
}

function eventConditions(workspaceId: string, filter: EventFilter) {
  const conditions = [eq(securityEvent.workspaceId, workspaceId)]

  if (filter.severity) {
    conditions.push(eq(securityEvent.severity, filter.severity))
  }
  if (filter.source) conditions.push(eq(securityEvent.source, filter.source))
  if (filter.projectId) {
    conditions.push(eq(securityEvent.projectId, filter.projectId))
  }

  if (filter.q) {
    const pattern = `%${filter.q}%`
    const search = or(
      ilike(securityEvent.title, pattern),
      ilike(securityEvent.description, pattern),
      ilike(securityEvent.agentName, pattern),
      ilike(securityEvent.sourceIp, pattern),
      ilike(securityEvent.ruleId, pattern)
    )
    if (search) conditions.push(search)
  }

  return and(...conditions)
}

export async function listSecurityEvents(
  workspaceId: string,
  filter: EventFilter,
  pagination: { limit: number; offset: number }
): Promise<SecurityEventPage> {
  const where = eventConditions(workspaceId, filter)
  const db = getDb()

  const [rows, totals] = await Promise.all([
    db
      .select({
        event: securityEvent,
        assetName: asset.displayName,
        assetType: asset.type,
        projectId: project.id,
        projectName: project.name,
      })
      .from(securityEvent)
      .innerJoin(asset, eq(asset.id, securityEvent.assetId))
      .innerJoin(project, eq(project.id, securityEvent.projectId))
      .where(where)
      .orderBy(desc(securityEvent.eventTime))
      .limit(pagination.limit)
      .offset(pagination.offset),
    db.select({ value: count() }).from(securityEvent).where(where),
  ])

  return {
    items: rows,
    total: totals[0]?.value ?? 0,
    limit: pagination.limit,
    offset: pagination.offset,
  }
}

export type EventSeverityCounts = {
  total: number
  bySeverity: Record<FindingSeverity, number>
}

export async function getEventSeverityCounts(
  workspaceId: string
): Promise<EventSeverityCounts> {
  const rows = await getDb()
    .select({ severity: securityEvent.severity, value: count() })
    .from(securityEvent)
    .where(eq(securityEvent.workspaceId, workspaceId))
    .groupBy(securityEvent.severity)

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
