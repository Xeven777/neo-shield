import type {
  AssetType,
  FindingSeverity,
  FindingStatus,
  ProjectCriticality,
} from "../db/schema"

/**
 * Deterministic, explainable scoring. Nothing here reads the clock or a
 * database: callers pass open findings and get the same score every time.
 *
 * The algorithm version is stored with every snapshot so a historical score can
 * always be explained by the model that produced it.
 */
export const SCORE_ALGORITHM_VERSION = "score.v1"

export const BASE_RISK_POINTS: Record<FindingSeverity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  informational: 0,
}

/** Only these statuses contribute risk. Resolved/risk-accepted findings do not. */
export const SCORED_STATUSES: FindingStatus[] = [
  "open",
  "acknowledged",
  "in_progress",
]

export type Exposure = "internet" | "internal" | "source" | "cloud"

/**
 * Documented multipliers (specification §3.7 B). Exposure is derived from the
 * asset type: domains face the internet, endpoints and networks are assumed
 * internal, repositories are source code and AWS accounts are cloud scope.
 */
export const EXPOSURE_MULTIPLIERS: Record<Exposure, number> = {
  internet: 1.25,
  internal: 1,
  source: 0.85,
  cloud: 1.1,
}

export const CRITICALITY_MULTIPLIERS: Record<ProjectCriticality, number> = {
  high: 1.2,
  medium: 1,
  low: 0.85,
}

export function exposureForAssetType(type: AssetType): Exposure {
  switch (type) {
    case "domain":
      return "internet"
    case "repository":
      return "source"
    case "aws_account":
      return "cloud"
    default:
      return "internal"
  }
}

export type ScoreInput = {
  severity: FindingSeverity
  status: FindingStatus
  assetType: AssetType
  criticality: ProjectCriticality
}

export type ScoreBucket = {
  count: number
  points: number
}

export type ScoreBreakdown = {
  bySeverity: Record<FindingSeverity, ScoreBucket>
  byAssetType: Record<AssetType, ScoreBucket>
  byExposure: Record<Exposure, ScoreBucket>
}

export type HealthScore = {
  /** 0–100. `100 - min(100, riskPoints)`, rounded to an integer. */
  score: number
  riskPoints: number
  openFindingCount: number
  breakdown: ScoreBreakdown
  algorithmVersion: string
}

function round2(value: number) {
  return Math.round(value * 100) / 100
}

function emptyBucket(): ScoreBucket {
  return { count: 0, points: 0 }
}

function add(bucket: ScoreBucket, points: number) {
  bucket.count += 1
  bucket.points = round2(bucket.points + points)
}

/**
 * Recurring instances are already deduplicated upstream: `finding` has a unique
 * `(asset_id, stable_key)`, so one rule on one asset contributes once no matter
 * how many scans observed it.
 */
export function computeHealthScore(inputs: ScoreInput[]): HealthScore {
  const bySeverity = {
    critical: emptyBucket(),
    high: emptyBucket(),
    medium: emptyBucket(),
    low: emptyBucket(),
    informational: emptyBucket(),
  } satisfies Record<FindingSeverity, ScoreBucket>

  const byAssetType = {
    repository: emptyBucket(),
    domain: emptyBucket(),
    endpoint: emptyBucket(),
    network: emptyBucket(),
    aws_account: emptyBucket(),
  } satisfies Record<AssetType, ScoreBucket>

  const byExposure = {
    internet: emptyBucket(),
    internal: emptyBucket(),
    source: emptyBucket(),
    cloud: emptyBucket(),
  } satisfies Record<Exposure, ScoreBucket>

  let riskPoints = 0
  let openFindingCount = 0

  for (const input of inputs) {
    if (!SCORED_STATUSES.includes(input.status)) continue

    const exposure = exposureForAssetType(input.assetType)
    const points =
      BASE_RISK_POINTS[input.severity] *
      EXPOSURE_MULTIPLIERS[exposure] *
      CRITICALITY_MULTIPLIERS[input.criticality]

    riskPoints += points
    openFindingCount += 1

    add(bySeverity[input.severity], points)
    add(byAssetType[input.assetType], points)
    add(byExposure[exposure], points)
  }

  const cappedRisk = Math.min(100, riskPoints)

  return {
    score: Math.max(0, Math.round(100 - cappedRisk)),
    riskPoints: round2(riskPoints),
    openFindingCount,
    breakdown: { bySeverity, byAssetType, byExposure },
    algorithmVersion: SCORE_ALGORITHM_VERSION,
  }
}
