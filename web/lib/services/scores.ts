import "server-only"

import { and, desc, eq, inArray, isNull, max } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  finding,
  project,
  scanRun,
  scoreSnapshot,
  type AssetType,
  type FindingSeverity,
  type ProjectCriticality,
} from "@/lib/db/schema"
import {
  computeHealthScore,
  SCORED_STATUSES,
  SCORE_ALGORITHM_VERSION,
  type HealthScore,
  type ScoreBreakdown,
} from "@/lib/intelligence/score"

/** Keep at most one unchanged snapshot per day so trends stay readable. */
const SNAPSHOT_MAX_AGE_MS = 24 * 60 * 60 * 1000
const HISTORY_LIMIT = 12

export type ScoreHistoryPoint = {
  score: number
  computedAt: Date
  openFindingCount: number
}

export type HealthScoreView = HealthScore & {
  projectId: string | null
  /** False until at least one completed/partial scan run exists. */
  scanned: boolean
  lastScanAt: Date | null
  history: ScoreHistoryPoint[]
}

type ScoreRow = {
  severity: FindingSeverity
  status: (typeof SCORED_STATUSES)[number]
  assetType: AssetType
  criticality: ProjectCriticality
}

async function loadScoreInputs(
  workspaceId: string,
  projectId: string | null
): Promise<ScoreRow[]> {
  const conditions = [
    eq(finding.workspaceId, workspaceId),
    inArray(finding.status, SCORED_STATUSES),
  ]

  if (projectId) conditions.push(eq(finding.projectId, projectId))

  return getDb()
    .select({
      severity: finding.severity,
      status: finding.status,
      assetType: asset.type,
      criticality: project.criticality,
    })
    .from(finding)
    .innerJoin(asset, eq(asset.id, finding.assetId))
    .innerJoin(project, eq(project.id, finding.projectId))
    .where(and(...conditions))
}

async function latestCompletedScan(
  workspaceId: string,
  projectId: string | null
): Promise<Date | null> {
  const conditions = [
    eq(scanRun.workspaceId, workspaceId),
    inArray(scanRun.status, ["completed", "partial"]),
  ]

  if (projectId) conditions.push(eq(scanRun.projectId, projectId))

  const [row] = await getDb()
    .select({ value: max(scanRun.startedAt) })
    .from(scanRun)
    .where(and(...conditions))

  return row?.value ?? null
}

async function latestSnapshot(workspaceId: string, projectId: string | null) {
  const [row] = await getDb()
    .select()
    .from(scoreSnapshot)
    .where(
      and(
        eq(scoreSnapshot.workspaceId, workspaceId),
        projectId
          ? eq(scoreSnapshot.projectId, projectId)
          : isNull(scoreSnapshot.projectId)
      )
    )
    .orderBy(desc(scoreSnapshot.computedAt))
    .limit(1)

  return row ?? null
}

async function recordSnapshot(input: {
  workspaceId: string
  projectId: string | null
  score: HealthScore
}): Promise<void> {
  const previous = await latestSnapshot(input.workspaceId, input.projectId)
  const now = new Date()

  if (
    previous &&
    previous.score === input.score.score &&
    previous.openFindingCount === input.score.openFindingCount &&
    now.getTime() - previous.computedAt.getTime() < SNAPSHOT_MAX_AGE_MS
  ) {
    return
  }

  await getDb()
    .insert(scoreSnapshot)
    .values({
      workspaceId: input.workspaceId,
      projectId: input.projectId,
      scope: input.projectId ? "project" : "workspace",
      score: input.score.score,
      riskPoints: input.score.riskPoints,
      openFindingCount: input.score.openFindingCount,
      algorithmVersion: input.score.algorithmVersion,
      breakdown: input.score.breakdown as ScoreBreakdown,
      computedAt: now,
    })
}

async function scoreHistory(
  workspaceId: string,
  projectId: string | null
): Promise<ScoreHistoryPoint[]> {
  const rows = await getDb()
    .select({
      score: scoreSnapshot.score,
      computedAt: scoreSnapshot.computedAt,
      openFindingCount: scoreSnapshot.openFindingCount,
    })
    .from(scoreSnapshot)
    .where(
      and(
        eq(scoreSnapshot.workspaceId, workspaceId),
        projectId
          ? eq(scoreSnapshot.projectId, projectId)
          : isNull(scoreSnapshot.projectId)
      )
    )
    .orderBy(desc(scoreSnapshot.computedAt))
    .limit(HISTORY_LIMIT)

  return rows.reverse()
}

async function healthFor(
  workspaceId: string,
  projectId: string | null
): Promise<HealthScoreView> {
  const [rows, lastScanAt] = await Promise.all([
    loadScoreInputs(workspaceId, projectId),
    latestCompletedScan(workspaceId, projectId),
  ])

  const score = computeHealthScore(rows)
  const scanned = lastScanAt !== null

  if (scanned) {
    await recordSnapshot({ workspaceId, projectId, score })
  }

  return {
    ...score,
    projectId,
    scanned,
    lastScanAt,
    history: await scoreHistory(workspaceId, projectId),
  }
}

export function getWorkspaceHealth(workspaceId: string) {
  return healthFor(workspaceId, null)
}

export function getProjectHealth(workspaceId: string, projectId: string) {
  return healthFor(workspaceId, projectId)
}

/** Algorithm provenance for the UI/manual verification. */
export const scoreProvenance = {
  version: SCORE_ALGORITHM_VERSION,
  snapshotMaxAgeMinutes: SNAPSHOT_MAX_AGE_MS / 60_000,
} as const
