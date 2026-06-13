import "server-only"

import { and, count, desc, eq, inArray, max } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  assetType,
  auditLog,
  project,
  scanJob,
  scanRun,
  type AssetType,
} from "@/lib/db/schema"
import { getFindingCounts, type FindingCounts } from "@/lib/services/findings"
import { isWorkerOnline, listWorkers } from "@/lib/services/workers"

export type OverviewWorker = {
  id: string
  name: string
  isOnline: boolean
  version: string | null
  hostname: string | null
  lastSeenAt: Date | null
}

export type WorkspaceOverview = {
  projectCount: number
  assetCounts: Record<AssetType, number>
  totalAssets: number
  findings: FindingCounts
  scanActivity: {
    active: number
    completed: number
    lastScanAt: Date | null
  }
  workers: OverviewWorker[]
  onlineWorkers: number
  recentActivity: {
    id: string
    action: string
    targetType: string | null
    targetId: string | null
    createdAt: Date
  }[]
}

export async function getWorkspaceOverview(
  workspaceId: string
): Promise<WorkspaceOverview> {
  const db = getDb()
  const findings = await getFindingCounts(workspaceId)

  const [
    projectRows,
    assetRows,
    activeScans,
    completedScans,
    lastScan,
    workers,
    activity,
  ] = await Promise.all([
    db
      .select({ value: count() })
      .from(project)
      .where(eq(project.workspaceId, workspaceId)),
    db
      .select({ type: asset.type, value: count() })
      .from(asset)
      .innerJoin(project, eq(project.id, asset.projectId))
      .where(eq(project.workspaceId, workspaceId))
      .groupBy(asset.type),
    db
      .select({ value: count() })
      .from(scanJob)
      .where(
        and(
          eq(scanJob.workspaceId, workspaceId),
          inArray(scanJob.status, ["queued", "leased", "running"])
        )
      ),
    db
      .select({ value: count() })
      .from(scanRun)
      .where(
        and(
          eq(scanRun.workspaceId, workspaceId),
          eq(scanRun.status, "completed")
        )
      ),
    db
      .select({ value: max(scanRun.startedAt) })
      .from(scanRun)
      .where(eq(scanRun.workspaceId, workspaceId)),
    listWorkers(workspaceId),
    listRecentActivity(workspaceId, 8),
  ])

  const assetCounts = Object.fromEntries(
    assetType.enumValues.map((type) => [type, 0])
  ) as Record<AssetType, number>

  for (const row of assetRows) {
    assetCounts[row.type] = row.value
  }

  return {
    projectCount: projectRows[0]?.value ?? 0,
    assetCounts,
    totalAssets: assetRows.reduce((total, row) => total + row.value, 0),
    findings,
    scanActivity: {
      active: activeScans[0]?.value ?? 0,
      completed: completedScans[0]?.value ?? 0,
      lastScanAt: lastScan[0]?.value ?? null,
    },
    workers: workers.map((worker) => ({
      id: worker.id,
      name: worker.name,
      isOnline: isWorkerOnline(worker),
      version: worker.version,
      hostname: worker.hostname,
      lastSeenAt: worker.lastSeenAt,
    })),
    onlineWorkers: workers.filter((worker) => isWorkerOnline(worker)).length,
    recentActivity: activity,
  }
}

export async function listRecentActivity(workspaceId: string, limit = 10) {
  return getDb()
    .select({
      id: auditLog.id,
      action: auditLog.action,
      targetType: auditLog.targetType,
      targetId: auditLog.targetId,
      createdAt: auditLog.createdAt,
    })
    .from(auditLog)
    .where(eq(auditLog.workspaceId, workspaceId))
    .orderBy(desc(auditLog.createdAt))
    .limit(limit)
}
