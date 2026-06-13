import "server-only"

import { and, count, desc, eq, inArray } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  project,
  scanJob,
  scanRun,
  type ScanJob,
  type ScanRun,
} from "@/lib/db/schema"
import {
  AuthorizationError,
  canManageWorkspace,
} from "@/lib/auth/session"
import { isGithubAppConfigured } from "@/lib/env"
import { recordAudit } from "@/lib/services/audit"
import type { WorkspaceRole } from "@/lib/db/schema"

const ACTIVE_SCAN_STATUSES = ["queued", "leased", "running"] as const
const MAX_ACTIVE_JOBS_PER_WORKSPACE = 25

export class ScanRequestError extends Error {
  code: "not_found" | "unsupported" | "disabled" | "integration_missing" | "queue_full"

  constructor(
    message: string,
    code: ScanRequestError["code"]
  ) {
    super(message)
    this.name = "ScanRequestError"
    this.code = code
  }
}

export async function getWorkspaceAsset(workspaceId: string, assetId: string) {
  const [row] = await getDb()
    .select({
      asset,
      projectId: project.id,
      projectName: project.name,
    })
    .from(asset)
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(and(eq(project.workspaceId, workspaceId), eq(asset.id, assetId)))
    .limit(1)

  return row ?? null
}

export async function queueRepositoryScan(input: {
  workspaceId: string
  assetId: string
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<{ jobId: string; reused: boolean }> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError("You do not have permission to queue scans.")
  }

  const target = await getWorkspaceAsset(input.workspaceId, input.assetId)
  if (!target) {
    throw new ScanRequestError("Asset not found in this workspace.", "not_found")
  }

  if (target.asset.type !== "repository") {
    throw new ScanRequestError(
      "Only repository assets can be scanned in Phase 1.",
      "unsupported"
    )
  }

  if (!target.asset.enabled) {
    throw new ScanRequestError("Enable the asset before scanning.", "disabled")
  }

  const config = target.asset.config as { fullName?: unknown }
  if (typeof config.fullName !== "string" || !config.fullName) {
    throw new ScanRequestError(
      "Asset is missing its GitHub repository metadata.",
      "integration_missing"
    )
  }

  if (!isGithubAppConfigured()) {
    throw new ScanRequestError(
      "GitHub App credentials are not configured on this deployment.",
      "integration_missing"
    )
  }

  const db = getDb()

  const [active] = await db
    .select({ id: scanJob.id })
    .from(scanJob)
    .where(
      and(
        eq(scanJob.assetId, input.assetId),
        inArray(scanJob.status, [...ACTIVE_SCAN_STATUSES])
      )
    )
    .limit(1)

  if (active) return { jobId: active.id, reused: true }

  const [activeCount] = await db
    .select({ value: count() })
    .from(scanJob)
    .where(
      and(
        eq(scanJob.workspaceId, input.workspaceId),
        inArray(scanJob.status, [...ACTIVE_SCAN_STATUSES])
      )
    )

  if ((activeCount?.value ?? 0) >= MAX_ACTIVE_JOBS_PER_WORKSPACE) {
    throw new ScanRequestError(
      "The scan queue is full for this workspace. Wait for running scans to finish.",
      "queue_full"
    )
  }

  // Time-bucketed idempotency: double clicks and retries within a minute cannot
  // enqueue duplicate work, while a new minute allows a fresh scan.
  const idempotencyKey = `repository:${input.assetId}:${Math.floor(
    Date.now() / 60_000
  )}`

  const [inserted] = await db
    .insert(scanJob)
    .values({
      workspaceId: input.workspaceId,
      assetId: input.assetId,
      type: "repository",
      idempotencyKey,
      parameters: { requestedAt: new Date().toISOString() },
      createdByUserId: input.actorUserId,
    })
    .onConflictDoNothing({ target: scanJob.idempotencyKey })
    .returning({ id: scanJob.id })

  if (!inserted) {
    const [existing] = await db
      .select({ id: scanJob.id })
      .from(scanJob)
      .where(eq(scanJob.idempotencyKey, idempotencyKey))
      .limit(1)

    if (!existing) {
      throw new Error("Could not enqueue the scan.")
    }

    return { jobId: existing.id, reused: true }
  }

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "scan.queued",
    targetType: "scan_job",
    targetId: inserted.id,
    metadata: { assetId: input.assetId, asset: target.asset.displayName },
  })

  return { jobId: inserted.id, reused: false }
}

export type ScanJobListItem = {
  job: ScanJob
  assetName: string
  projectId: string
  projectName: string
}

export async function listScanJobs(
  workspaceId: string,
  limit = 50
): Promise<ScanJobListItem[]> {
  return getDb()
    .select({
      job: scanJob,
      assetName: asset.displayName,
      projectId: project.id,
      projectName: project.name,
    })
    .from(scanJob)
    .innerJoin(asset, eq(asset.id, scanJob.assetId))
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(eq(project.workspaceId, workspaceId))
    .orderBy(desc(scanJob.createdAt))
    .limit(limit)
}

export async function listProjectScanJobs(
  projectId: string,
  limit = 100
): Promise<ScanJobListItem[]> {
  return getDb()
    .select({
      job: scanJob,
      assetName: asset.displayName,
      projectId: project.id,
      projectName: project.name,
    })
    .from(scanJob)
    .innerJoin(asset, eq(asset.id, scanJob.assetId))
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(eq(project.id, projectId))
    .orderBy(desc(scanJob.createdAt))
    .limit(limit)
}

/** Latest job per asset, used to render scan state on asset lists. */
export async function getLatestJobsByAsset(
  workspaceId: string
): Promise<Map<string, ScanJob>> {
  const rows = await getDb()
    .select({ job: scanJob })
    .from(scanJob)
    .innerJoin(asset, eq(asset.id, scanJob.assetId))
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(eq(project.workspaceId, workspaceId))
    .orderBy(desc(scanJob.createdAt))
    .limit(300)

  const latest = new Map<string, ScanJob>()
  for (const row of rows) {
    if (!latest.has(row.job.assetId)) latest.set(row.job.assetId, row.job)
  }

  return latest
}

export type ScanRunListItem = {
  run: ScanRun
  assetName: string
  projectName: string
}

export async function listScanRuns(
  workspaceId: string,
  limit = 25
): Promise<ScanRunListItem[]> {
  return getDb()
    .select({
      run: scanRun,
      assetName: asset.displayName,
      projectName: project.name,
    })
    .from(scanRun)
    .innerJoin(asset, eq(asset.id, scanRun.assetId))
    .innerJoin(project, eq(project.id, scanRun.projectId))
    .where(eq(scanRun.workspaceId, workspaceId))
    .orderBy(desc(scanRun.startedAt))
    .limit(limit)
}
