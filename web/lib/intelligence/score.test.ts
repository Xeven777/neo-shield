import { describe, expect, test } from "bun:test"

import {
  BASE_RISK_POINTS,
  CRITICALITY_MULTIPLIERS,
  EXPOSURE_MULTIPLIERS,
  SCORE_ALGORITHM_VERSION,
  computeHealthScore,
  exposureForAssetType,
  type ScoreInput,
} from "./score"

const base: ScoreInput = {
  severity: "medium",
  status: "open",
  assetType: "domain",
  criticality: "medium",
}

describe("computeHealthScore", () => {
  test("an empty workspace scores 100 with no risk", () => {
    const result = computeHealthScore([])
    expect(result.score).toBe(100)
    expect(result.riskPoints).toBe(0)
    expect(result.openFindingCount).toBe(0)
    expect(result.algorithmVersion).toBe(SCORE_ALGORITHM_VERSION)
  })

  test("informational findings count but add no risk", () => {
    const result = computeHealthScore([{ ...base, severity: "informational" }])
    expect(result.score).toBe(100)
    expect(result.riskPoints).toBe(0)
    expect(result.openFindingCount).toBe(1)
    expect(result.breakdown.bySeverity.informational.count).toBe(1)
  })

  test("applies severity, exposure and criticality multipliers", () => {
    const result = computeHealthScore([
      { ...base, severity: "critical", criticality: "high" },
    ])
    const expected =
      BASE_RISK_POINTS.critical *
      EXPOSURE_MULTIPLIERS.internet *
      CRITICALITY_MULTIPLIERS.high

    expect(result.riskPoints).toBe(expected)
    expect(result.score).toBe(Math.round(100 - expected))
    expect(result.breakdown.byExposure.internet.points).toBe(expected)
  })

  test("only open, acknowledged and in-progress findings count", () => {
    const result = computeHealthScore([
      { ...base, status: "open" },
      { ...base, status: "acknowledged" },
      { ...base, status: "in_progress" },
      { ...base, status: "resolved" },
      { ...base, status: "accepted_risk" },
      { ...base, status: "false_positive" },
    ])

    expect(result.openFindingCount).toBe(3)
    expect(result.riskPoints).toBe(
      BASE_RISK_POINTS.medium * EXPOSURE_MULTIPLIERS.internet * 3
    )
  })

  test("caps total risk at 100", () => {
    const result = computeHealthScore(
      Array.from({ length: 6 }, () => ({
        ...base,
        severity: "critical" as const,
        criticality: "high" as const,
      }))
    )

    expect(result.riskPoints).toBeGreaterThan(100)
    expect(result.score).toBe(0)
  })

  test("breakdowns add up to the total risk", () => {
    const result = computeHealthScore([
      { ...base, severity: "critical", assetType: "domain" },
      { ...base, severity: "high", assetType: "endpoint" },
      { ...base, severity: "low", assetType: "repository" },
    ])

    const severityTotal = Object.values(result.breakdown.bySeverity).reduce(
      (sum, bucket) => sum + bucket.points,
      0
    )
    const assetTotal = Object.values(result.breakdown.byAssetType).reduce(
      (sum, bucket) => sum + bucket.points,
      0
    )
    const exposureTotal = Object.values(result.breakdown.byExposure).reduce(
      (sum, bucket) => sum + bucket.points,
      0
    )

    expect(severityTotal).toBeCloseTo(result.riskPoints, 5)
    expect(assetTotal).toBeCloseTo(result.riskPoints, 5)
    expect(exposureTotal).toBeCloseTo(result.riskPoints, 5)
  })

  test("exposure is derived from asset type", () => {
    expect(exposureForAssetType("domain")).toBe("internet")
    expect(exposureForAssetType("repository")).toBe("source")
    expect(exposureForAssetType("endpoint")).toBe("internal")
    expect(exposureForAssetType("network")).toBe("internal")
    expect(exposureForAssetType("aws_account")).toBe("cloud")
  })
})
