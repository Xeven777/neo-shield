import "server-only"

import { and, asc, count, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  networkHost,
  networkService,
  project,
  type Asset,
  type NetworkObservationStatus,
  type WorkspaceRole,
} from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { recordAudit } from "@/lib/services/audit"
import { getProject } from "@/lib/services/projects"
import { parseNetworkScope } from "@/lib/validation/network"
import {
  createNetworkSchema,
  type networkScanProfiles,
} from "@/lib/validation/schemas"

export type NetworkScanProfile = (typeof networkScanProfiles)[number]

export type NetworkAuthorization = {
  confirmedByUserId: string
  confirmedAt: string
  statement: string
  /** The exact normalized CIDR the user confirmed; the worker re-checks it. */
  scope: string
}

export type NetworkAssetConfig = {
  provider: "network"
  cidr: string
  scanProfile: NetworkScanProfile
  authorization: NetworkAuthorization
}

export type NetworkAssetRow = {
  asset: Asset
  projectId: string
  projectName: string
  hostCount: number
  activeHostCount: number
  activeServiceCount: number
}

export class NetworkRequestError extends Error {
  code: "not_found" | "invalid" | "scope" | "authorization"

  constructor(message: string, code: NetworkRequestError["code"]) {
    super(message)
    this.name = "NetworkRequestError"
    this.code = code
  }
}

export function networkAssetConfig(input: {
  cidr: string
  scanProfile: NetworkScanProfile
  confirmedByUserId: string
  confirmedAt: string
  statement: string
}): NetworkAssetConfig {
  return {
    provider: "network",
    cidr: input.cidr,
    scanProfile: input.scanProfile,
    authorization: {
      confirmedByUserId: input.confirmedByUserId,
      confirmedAt: input.confirmedAt,
      statement: input.statement,
      scope: input.cidr,
    },
  }
}

/**
 * Re-validates the stored authorization before a scan can be queued. The
 * worker applies the same checks again, so a tampered asset row still cannot
 * widen the scope or run without a confirmed owner.
 */
export function networkConfigIsScanReady(config: unknown): boolean {
  if (typeof config !== "object" || config === null) return false

  const candidate = config as Partial<NetworkAssetConfig>
  if (candidate.provider !== "network") return false
  if (typeof candidate.cidr !== "string") return false
  if (
    candidate.scanProfile !== "discovery" &&
    candidate.scanProfile !== "services"
  ) {
    return false
  }

  const authorization = candidate.authorization
  if (typeof authorization !== "object" || authorization === null) return false
  if (!authorization.confirmedByUserId || !authorization.confirmedAt) {
    return false
  }
  if (authorization.scope !== candidate.cidr) return false

  try {
    return parseNetworkScope(candidate.cidr).cidr === candidate.cidr
  } catch {
    return false
  }
}

export async function listNetworkAssets(
  workspaceId: string
): Promise<NetworkAssetRow[]> {
  const db = getDb()

  const [assets, hostTotals, activeHosts, activeServices] = await Promise.all([
    db
      .select({
        asset,
        projectId: project.id,
        projectName: project.name,
      })
      .from(asset)
      .innerJoin(project, eq(project.id, asset.projectId))
      .where(
        and(eq(project.workspaceId, workspaceId), eq(asset.type, "network"))
      )
      .orderBy(asc(asset.displayName)),
    db
      .select({ assetId: networkHost.assetId, value: count() })
      .from(networkHost)
      .where(eq(networkHost.workspaceId, workspaceId))
      .groupBy(networkHost.assetId),
    db
      .select({ assetId: networkHost.assetId, value: count() })
      .from(networkHost)
      .where(
        and(
          eq(networkHost.workspaceId, workspaceId),
          eq(networkHost.status, "active")
        )
      )
      .groupBy(networkHost.assetId),
    db
      .select({ assetId: networkService.assetId, value: count() })
      .from(networkService)
      .innerJoin(networkHost, eq(networkHost.id, networkService.hostId))
      .where(
        and(
          eq(networkHost.workspaceId, workspaceId),
          eq(networkService.status, "active")
        )
      )
      .groupBy(networkService.assetId),
  ])

  const hostTotalsByAsset = new Map(
    hostTotals.map((row) => [row.assetId, row.value])
  )
  const activeHostsByAsset = new Map(
    activeHosts.map((row) => [row.assetId, row.value])
  )
  const activeServicesByAsset = new Map(
    activeServices.map((row) => [row.assetId, row.value])
  )

  return assets.map((row) => ({
    ...row,
    hostCount: hostTotalsByAsset.get(row.asset.id) ?? 0,
    activeHostCount: activeHostsByAsset.get(row.asset.id) ?? 0,
    activeServiceCount: activeServicesByAsset.get(row.asset.id) ?? 0,
  }))
}

export async function getNetworkAsset(
  workspaceId: string,
  assetId: string
): Promise<NetworkAssetRow | null> {
  const rows = await listNetworkAssets(workspaceId)
  return rows.find((row) => row.asset.id === assetId) ?? null
}

export async function addNetworkAsset(input: {
  workspaceId: string
  projectId: string
  cidr: string
  scanProfile: NetworkScanProfile
  authorization: boolean
  confirmation: string
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<Asset> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "Only workspace admins can add authorized network ranges."
    )
  }

  const data = createNetworkSchema.parse({
    projectId: input.projectId,
    cidr: input.cidr,
    scanProfile: input.scanProfile,
    authorization: input.authorization,
    confirmation: input.confirmation,
  })

  const projectRow = await getProject(input.workspaceId, data.projectId)
  if (!projectRow) {
    throw new NetworkRequestError(
      "Project not found in this workspace.",
      "not_found"
    )
  }

  let scope: ReturnType<typeof parseNetworkScope>
  try {
    scope = parseNetworkScope(data.cidr)
  } catch (error) {
    throw new NetworkRequestError(
      error instanceof Error ? error.message : "Enter a valid CIDR range.",
      "scope"
    )
  }

  const now = new Date().toISOString()
  const statement = `I confirm I own or am explicitly authorized to scan ${scope.cidr} with NeoShield.`

  const [saved] = await getDb()
    .insert(asset)
    .values({
      projectId: projectRow.id,
      type: "network",
      displayName: scope.cidr,
      identifier: `network:${scope.cidr}`,
      config: networkAssetConfig({
        cidr: scope.cidr,
        scanProfile: data.scanProfile,
        confirmedByUserId: input.actorUserId,
        confirmedAt: now,
        statement,
      }),
    })
    .onConflictDoUpdate({
      target: [asset.projectId, asset.type, asset.identifier],
      set: {
        displayName: scope.cidr,
        config: networkAssetConfig({
          cidr: scope.cidr,
          scanProfile: data.scanProfile,
          confirmedByUserId: input.actorUserId,
          confirmedAt: now,
          statement,
        }),
        enabled: true,
        updatedAt: new Date(),
      },
    })
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "network.added",
    targetType: "asset",
    targetId: saved.id,
    metadata: {
      cidr: scope.cidr,
      profile: data.scanProfile,
      project: projectRow.name,
      authorized: true,
    },
  })

  return saved
}

export async function setNetworkAssetEnabled(input: {
  workspaceId: string
  assetId: string
  enabled: boolean
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<Asset> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "Only workspace admins can change authorized network ranges."
    )
  }

  const existing = await getNetworkAsset(input.workspaceId, input.assetId)
  if (!existing) {
    throw new NetworkRequestError(
      "Network asset not found in this workspace.",
      "not_found"
    )
  }

  const [updated] = await getDb()
    .update(asset)
    .set({ enabled: input.enabled, updatedAt: new Date() })
    .where(eq(asset.id, existing.asset.id))
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: input.enabled ? "network.enabled" : "network.disabled",
    targetType: "asset",
    targetId: existing.asset.id,
    metadata: { cidr: existing.asset.displayName },
  })

  return updated
}

export function networkStatusLabel(status: NetworkObservationStatus) {
  return status === "active" ? "active" : "missing"
}
