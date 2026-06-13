import "server-only"

import { and, desc, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  endpointAgent,
  finding,
  networkHost,
  networkService,
  project,
  scanRun,
  securityEvent,
  type Asset,
  type EndpointAgent,
  type FindingRow,
  type NetworkHost,
  type NetworkService,
  type ScanRun,
  type SecurityEvent,
} from "@/lib/db/schema"
import { OPEN_FINDING_STATUSES } from "@/lib/services/findings"

export type EndpointAssetRow = {
  asset: Asset
  projectId: string
  projectName: string
  agent: EndpointAgent | null
}

export async function listEndpointAssets(
  workspaceId: string
): Promise<EndpointAssetRow[]> {
  const rows = await getDb()
    .select({
      asset,
      projectId: project.id,
      projectName: project.name,
      agent: endpointAgent,
    })
    .from(asset)
    .innerJoin(project, eq(project.id, asset.projectId))
    .leftJoin(
      endpointAgent,
      and(
        eq(endpointAgent.assetId, asset.id),
        eq(endpointAgent.provider, "wazuh")
      )
    )
    .where(
      and(eq(project.workspaceId, workspaceId), eq(asset.type, "endpoint"))
    )
    .orderBy(desc(asset.updatedAt))

  return rows
}

export type WorkspaceAssetRow = {
  asset: Asset
  projectId: string
  projectName: string
}

export async function getWorkspaceAssetRow(
  workspaceId: string,
  assetId: string
): Promise<WorkspaceAssetRow | null> {
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

export type AssetFindingRow = {
  finding: FindingRow
  assetName: string
  projectId: string
  projectName: string
}

export async function listAssetFindings(
  workspaceId: string,
  assetId: string,
  limit = 50
): Promise<AssetFindingRow[]> {
  return getDb()
    .select({
      finding,
      assetName: asset.displayName,
      projectId: project.id,
      projectName: project.name,
    })
    .from(finding)
    .innerJoin(asset, eq(asset.id, finding.assetId))
    .innerJoin(project, eq(project.id, finding.projectId))
    .where(and(eq(finding.workspaceId, workspaceId), eq(finding.assetId, assetId)))
    .orderBy(desc(finding.lastSeenAt))
    .limit(limit)
}

export async function listAssetScanRuns(
  workspaceId: string,
  assetId: string,
  limit = 10
): Promise<ScanRun[]> {
  return getDb()
    .select()
    .from(scanRun)
    .where(and(eq(scanRun.workspaceId, workspaceId), eq(scanRun.assetId, assetId)))
    .orderBy(desc(scanRun.startedAt))
    .limit(limit)
}

export async function listAssetEvents(
  workspaceId: string,
  assetId: string,
  limit = 25
): Promise<SecurityEvent[]> {
  return getDb()
    .select()
    .from(securityEvent)
    .where(
      and(
        eq(securityEvent.workspaceId, workspaceId),
        eq(securityEvent.assetId, assetId)
      )
    )
    .orderBy(desc(securityEvent.eventTime))
    .limit(limit)
}

export async function getEndpointAgent(
  assetId: string
): Promise<EndpointAgent | null> {
  const [row] = await getDb()
    .select()
    .from(endpointAgent)
    .where(
      and(eq(endpointAgent.assetId, assetId), eq(endpointAgent.provider, "wazuh"))
    )
    .limit(1)

  return row ?? null
}

export type NetworkHostWithServices = NetworkHost & {
  services: NetworkService[]
}

export async function listNetworkHosts(
  workspaceId: string,
  assetId: string
): Promise<NetworkHostWithServices[]> {
  const db = getDb()

  const [hosts, services] = await Promise.all([
    db
      .select()
      .from(networkHost)
      .where(
        and(
          eq(networkHost.workspaceId, workspaceId),
          eq(networkHost.assetId, assetId)
        )
      ),
    db
      .select()
      .from(networkService)
      .where(eq(networkService.assetId, assetId)),
  ])

  const byHost = new Map<string, NetworkService[]>()
  for (const service of services) {
    const list = byHost.get(service.hostId) ?? []
    list.push(service)
    byHost.set(service.hostId, list)
  }

  return hosts
    .map((host) => ({
      ...host,
      services: (byHost.get(host.id) ?? []).sort((a, b) => a.port - b.port),
    }))
    .sort((a, b) => compareAddresses(a.address, b.address))
}

function compareAddresses(left: string, right: string) {
  const parse = (value: string) =>
    value.split(".").map((part) => Number(part) || 0)
  const a = parse(left)
  const b = parse(right)

  for (let index = 0; index < 4; index += 1) {
    const difference = (a[index] ?? 0) - (b[index] ?? 0)
    if (difference !== 0) return difference
  }

  return left.localeCompare(right)
}

export type AssetDetail = {
  asset: Asset
  projectId: string
  projectName: string
  findings: AssetFindingRow[]
  runs: ScanRun[]
  openFindingCount: number
  agent: EndpointAgent | null
  events: SecurityEvent[]
  hosts: NetworkHostWithServices[]
  latestRun: ScanRun | null
  previousRun: ScanRun | null
}

export async function getAssetDetail(
  workspaceId: string,
  assetId: string
): Promise<AssetDetail | null> {
  const row = await getWorkspaceAssetRow(workspaceId, assetId)
  if (!row) return null

  const [findings, runs] = await Promise.all([
    listAssetFindings(workspaceId, assetId),
    listAssetScanRuns(workspaceId, assetId),
  ])

  const openFindingCount = findings.filter((item) =>
    OPEN_FINDING_STATUSES.includes(item.finding.status)
  ).length

  const isEndpoint = row.asset.type === "endpoint"
  const isNetwork = row.asset.type === "network"

  const [agent, events, hosts] = await Promise.all([
    isEndpoint ? getEndpointAgent(assetId) : Promise.resolve(null),
    isEndpoint ? listAssetEvents(workspaceId, assetId) : Promise.resolve([]),
    isNetwork ? listNetworkHosts(workspaceId, assetId) : Promise.resolve([]),
  ])

  return {
    ...row,
    findings,
    runs,
    openFindingCount,
    agent,
    events,
    hosts,
    latestRun: runs[0] ?? null,
    previousRun: runs[1] ?? null,
  }
}
