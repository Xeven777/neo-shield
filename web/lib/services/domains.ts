import "server-only"

import { and, asc, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import { asset, project, type Asset, type WorkspaceRole } from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { recordAudit } from "@/lib/services/audit"
import { getProject } from "@/lib/services/projects"
import { createDomainSchema } from "@/lib/validation/schemas"

export type DomainAsset = {
  asset: Asset
  projectId: string
  projectName: string
}

export class DomainRequestError extends Error {
  code: "not_found" | "invalid"

  constructor(message: string, code: DomainRequestError["code"]) {
    super(message)
    this.name = "DomainRequestError"
    this.code = code
  }
}

/**
 * Domain assets are plain `asset` rows: the worker needs no provider
 * credentials, only a hostname and the public-IP guard it applies itself.
 */
export function domainAssetConfig(domain: string) {
  return {
    provider: "domain",
    domain,
    url: `https://${domain}`,
  }
}

export async function listDomainAssets(
  workspaceId: string
): Promise<DomainAsset[]> {
  return getDb()
    .select({
      asset,
      projectId: project.id,
      projectName: project.name,
    })
    .from(asset)
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(and(eq(project.workspaceId, workspaceId), eq(asset.type, "domain")))
    .orderBy(asc(asset.displayName))
}

export async function getWorkspaceDomainAsset(
  workspaceId: string,
  assetId: string
): Promise<DomainAsset | null> {
  const [row] = await getDb()
    .select({
      asset,
      projectId: project.id,
      projectName: project.name,
    })
    .from(asset)
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(
      and(
        eq(project.workspaceId, workspaceId),
        eq(asset.id, assetId),
        eq(asset.type, "domain")
      )
    )
    .limit(1)

  return row ?? null
}

export async function addDomainAsset(input: {
  workspaceId: string
  projectId: string
  domain: string
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<Asset> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError("Only workspace admins can add domains.")
  }

  const data = createDomainSchema.parse({
    projectId: input.projectId,
    domain: input.domain,
  })

  const projectRow = await getProject(input.workspaceId, data.projectId)
  if (!projectRow) {
    throw new DomainRequestError("Project not found in this workspace.", "not_found")
  }

  const [linkedAsset] = await getDb()
    .insert(asset)
    .values({
      projectId: projectRow.id,
      type: "domain",
      displayName: data.domain,
      identifier: `domain:${data.domain}`,
      config: domainAssetConfig(data.domain),
    })
    .onConflictDoUpdate({
      target: [asset.projectId, asset.type, asset.identifier],
      set: {
        displayName: data.domain,
        config: domainAssetConfig(data.domain),
        enabled: true,
        updatedAt: new Date(),
      },
    })
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "domain.added",
    targetType: "asset",
    targetId: linkedAsset.id,
    metadata: { domain: data.domain, project: projectRow.name },
  })

  return linkedAsset
}

export async function setDomainAssetEnabled(input: {
  workspaceId: string
  assetId: string
  enabled: boolean
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<Asset> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError("Only workspace admins can change domains.")
  }

  const existing = await getWorkspaceDomainAsset(input.workspaceId, input.assetId)
  if (!existing) {
    throw new DomainRequestError("Domain not found in this workspace.", "not_found")
  }

  const [updated] = await getDb()
    .update(asset)
    .set({ enabled: input.enabled, updatedAt: new Date() })
    .where(eq(asset.id, existing.asset.id))
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: input.enabled ? "domain.enabled" : "domain.disabled",
    targetType: "asset",
    targetId: existing.asset.id,
    metadata: { domain: existing.asset.displayName },
  })

  return updated
}
