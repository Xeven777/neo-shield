import { describe, expect, test } from "bun:test"

import {
  CORRELATION_RULES,
  correlate,
  type CorrelationAsset,
  type CorrelationEvent,
  type CorrelationFinding,
  type EndpointAddress,
} from "./correlation"

const now = new Date("2026-11-14T12:00:00.000Z")

function hoursAgo(hours: number) {
  return new Date(now.getTime() - hours * 60 * 60 * 1000)
}

function finding(
  overrides: Partial<CorrelationFinding> = {}
): CorrelationFinding {
  return {
    id: "f-default",
    projectId: "p1",
    projectName: "Production",
    projectEnvironment: "development",
    assetId: "a1",
    assetName: "endpoint-1",
    assetType: "endpoint",
    source: "wazuh",
    sourceTool: "wazuh",
    stableKey: "wazuh|authentication|a1|rule",
    title: "Failed authentication",
    category: "authentication",
    severity: "medium",
    occurrenceCount: 1,
    firstSeenAt: hoursAgo(2),
    lastSeenAt: hoursAgo(1),
    evidence: {},
    ...overrides,
  }
}

function asset(overrides: Partial<CorrelationAsset> = {}): CorrelationAsset {
  return {
    id: "domain-1",
    projectId: "p1",
    projectName: "Production",
    projectEnvironment: "production",
    type: "domain",
    displayName: "example.com",
    identifier: "example.com",
    ...overrides,
  }
}

function event(overrides: Partial<CorrelationEvent> = {}): CorrelationEvent {
  return {
    id: "e-default",
    projectId: "p1",
    assetId: "a1",
    assetName: "endpoint-1",
    sourceIp: "203.0.113.50",
    category: "authentication",
    ruleId: "5710",
    severity: "medium",
    eventTime: hoursAgo(1),
    ...overrides,
  }
}

function run(input: {
  findings?: CorrelationFinding[]
  events?: CorrelationEvent[]
  assets?: CorrelationAsset[]
  endpointAddresses?: EndpointAddress[]
}) {
  return correlate({
    findings: input.findings ?? [],
    events: input.events ?? [],
    assets: input.assets ?? [],
    endpointAddresses: input.endpointAddresses ?? [],
    now,
  })
}

function byRule(
  candidates: ReturnType<typeof run>,
  rule: (typeof CORRELATION_RULES)[keyof typeof CORRELATION_RULES]
) {
  return candidates.filter((candidate) => candidate.rule === rule)
}

describe("endpoint authentication failures rule", () => {
  test("groups three or more attempts on one endpoint", () => {
    const candidates = byRule(
      run({
        findings: [
          finding({ id: "f1", stableKey: "k1" }),
          finding({ id: "f2", stableKey: "k2" }),
          finding({ id: "f3", stableKey: "k3" }),
        ],
      }),
      CORRELATION_RULES.endpointAuthFailures
    )

    expect(candidates).toHaveLength(1)
    expect(candidates[0].key).toBe("a1")
    expect(candidates[0].findingIds).toEqual(["f1", "f2", "f3"])
    expect(candidates[0].evidence.totalOccurrences).toBe(3)
    expect(candidates[0].severity).toBe("medium")
  })

  test("ignores two attempts", () => {
    const candidates = byRule(
      run({
        findings: [
          finding({ id: "f1", stableKey: "k1" }),
          finding({ id: "f2", stableKey: "k2" }),
        ],
      }),
      CORRELATION_RULES.endpointAuthFailures
    )

    expect(candidates).toHaveLength(0)
  })

  test("ignores activity older than 24 hours", () => {
    const candidates = byRule(
      run({
        findings: [
          finding({ id: "f1", lastSeenAt: hoursAgo(25) }),
          finding({ id: "f2", lastSeenAt: hoursAgo(25) }),
          finding({ id: "f3", lastSeenAt: hoursAgo(25) }),
        ],
      }),
      CORRELATION_RULES.endpointAuthFailures
    )

    expect(candidates).toHaveLength(0)
  })
})

describe("exposed remote management rule", () => {
  test("matches SSH on the endpoint's address with authentication failures", () => {
    const exposed = finding({
      id: "n1",
      assetId: "network-1",
      assetName: "10.0.0.5",
      assetType: "network",
      source: "network",
      sourceTool: "nmap",
      stableKey: "network|port|10.0.0.5|22|tcp",
      title: "Exposed service: 22/tcp (ssh)",
      category: "exposed_service",
      severity: "medium",
      evidence: { address: "10.0.0.5", port: 22 },
    })

    const candidates = byRule(
      run({
        findings: [
          finding({ id: "f1", stableKey: "k1" }),
          finding({ id: "f2", stableKey: "k2" }),
          finding({ id: "f3", stableKey: "k3" }),
          exposed,
        ],
        endpointAddresses: [{ assetId: "a1", ipAddress: "10.0.0.5" }],
      }),
      CORRELATION_RULES.exposedRemoteManagement
    )

    expect(candidates).toHaveLength(1)
    expect(candidates[0].key).toBe("a1|22")
    expect(candidates[0].severity).toBe("high")
    expect(candidates[0].findingIds).toContain("n1")
    expect(candidates[0].evidence.ipAddress).toBe("10.0.0.5")
  })

  test("does not match a different address", () => {
    const exposed = finding({
      id: "n1",
      assetId: "network-1",
      assetType: "network",
      category: "exposed_service",
      severity: "medium",
      evidence: { address: "10.0.0.99", port: 22 },
    })

    const candidates = byRule(
      run({
        findings: [
          finding({ id: "f1" }),
          finding({ id: "f2" }),
          finding({ id: "f3" }),
          exposed,
        ],
        endpointAddresses: [{ assetId: "a1", ipAddress: "10.0.0.5" }],
      }),
      CORRELATION_RULES.exposedRemoteManagement
    )

    expect(candidates).toHaveLength(0)
  })
})

describe("secret in production rule", () => {
  const secret = finding({
    id: "s1",
    assetId: "repo-1",
    assetName: "app",
    assetType: "repository",
    source: "github",
    sourceTool: "gitleaks",
    category: "secret",
    severity: "high",
    projectEnvironment: "production",
  })

  test("groups a secret with an explicitly attached domain", () => {
    const candidates = byRule(
      run({ findings: [secret], assets: [asset()] }),
      CORRELATION_RULES.secretInProduction
    )

    expect(candidates).toHaveLength(1)
    expect(candidates[0].key).toBe("p1")
    expect(candidates[0].findingIds).toEqual(["s1"])
    expect(candidates[0].evidence.domains).toEqual(["example.com"])
  })

  test("does not fire outside production", () => {
    const candidates = byRule(
      run({
        findings: [{ ...secret, projectEnvironment: "staging" }],
        assets: [asset({ projectEnvironment: "staging" })],
      }),
      CORRELATION_RULES.secretInProduction
    )

    expect(candidates).toHaveLength(0)
  })

  test("does not fire without an attached domain", () => {
    const candidates = byRule(
      run({ findings: [secret], assets: [] }),
      CORRELATION_RULES.secretInProduction
    )

    expect(candidates).toHaveLength(0)
  })
})

describe("high-risk cluster rule", () => {
  test("groups three high findings on one asset", () => {
    const candidates = byRule(
      run({
        findings: [
          finding({ id: "h1", category: "dependency", severity: "high" }),
          finding({ id: "h2", category: "http", severity: "high" }),
          finding({ id: "h3", category: "tls", severity: "high" }),
        ],
      }),
      CORRELATION_RULES.assetHighRiskCluster
    )

    expect(candidates).toHaveLength(1)
    expect(candidates[0].key).toBe("a1")
    expect(candidates[0].severity).toBe("high")
  })

  test("escalates to critical when any finding is critical", () => {
    const candidates = byRule(
      run({
        findings: [
          finding({ id: "h1", category: "dependency", severity: "critical" }),
          finding({ id: "h2", category: "http", severity: "high" }),
          finding({ id: "h3", category: "tls", severity: "high" }),
        ],
      }),
      CORRELATION_RULES.assetHighRiskCluster
    )

    expect(candidates[0].severity).toBe("critical")
  })

  test("ignores medium findings and stale findings", () => {
    const fresh = [
      finding({ id: "m1", severity: "medium" }),
      finding({ id: "m2", severity: "medium" }),
      finding({ id: "m3", severity: "medium" }),
    ]
    expect(
      byRule(run({ findings: fresh }), CORRELATION_RULES.assetHighRiskCluster)
    ).toHaveLength(0)

    const stale = [
      finding({ id: "s1", severity: "high", lastSeenAt: hoursAgo(24 * 8) }),
      finding({ id: "s2", severity: "high", lastSeenAt: hoursAgo(24 * 8) }),
      finding({ id: "s3", severity: "high", lastSeenAt: hoursAgo(24 * 8) }),
    ]
    expect(
      byRule(run({ findings: stale }), CORRELATION_RULES.assetHighRiskCluster)
    ).toHaveLength(0)
  })
})

describe("source authentication burst rule", () => {
  test("groups five events from one source IP against one asset", () => {
    const events = Array.from({ length: 5 }, (_, index) =>
      event({ id: `e${index}` })
    )
    const candidates = byRule(
      run({ events }),
      CORRELATION_RULES.sourceAuthBurst
    )

    expect(candidates).toHaveLength(1)
    expect(candidates[0].key).toBe("a1|203.0.113.50")
    expect(candidates[0].evidence.eventCount).toBe(5)
    expect(candidates[0].severity).toBe("medium")
  })

  test("requires five events", () => {
    const events = Array.from({ length: 4 }, (_, index) =>
      event({ id: `e${index}` })
    )
    expect(
      byRule(run({ events }), CORRELATION_RULES.sourceAuthBurst)
    ).toHaveLength(0)
  })

  test("does not merge different source IPs", () => {
    const events = [
      ...Array.from({ length: 3 }, (_, index) =>
        event({ id: `a${index}`, sourceIp: "203.0.113.1" })
      ),
      ...Array.from({ length: 3 }, (_, index) =>
        event({ id: `b${index}`, sourceIp: "203.0.113.2" })
      ),
    ]

    expect(
      byRule(run({ events }), CORRELATION_RULES.sourceAuthBurst)
    ).toHaveLength(0)
  })
})

describe("determinism", () => {
  test("same input produces the same ordered candidates", () => {
    const input = {
      findings: [
        finding({ id: "f1" }),
        finding({ id: "f2" }),
        finding({ id: "f3" }),
      ],
      events: Array.from({ length: 5 }, (_, index) =>
        event({ id: `e${index}` })
      ),
    }

    const first = run(input)
    const second = run(input)
    expect(second).toEqual(first)

    const sorted = [...first].sort(
      (a, b) => a.rule.localeCompare(b.rule) || a.key.localeCompare(b.key)
    )
    expect(first).toEqual(sorted)
  })

  test("candidate evidence stays JSON-serializable", () => {
    const candidates = run({
      findings: [
        finding({ id: "f1" }),
        finding({ id: "f2" }),
        finding({ id: "f3" }),
      ],
    })

    expect(() => JSON.stringify(candidates)).not.toThrow()
  })
})
