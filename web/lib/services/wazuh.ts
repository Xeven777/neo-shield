import "server-only"

import { and, asc, count, eq, gte, inArray, max } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  finding,
  integration,
  project,
  securityEvent,
  type Integration,
  type WorkspaceRole,
} from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { recordAudit } from "@/lib/services/audit"
import { getProject } from "@/lib/services/projects"
import { OPEN_FINDING_STATUSES } from "@/lib/services/findings"

export type WazuhOverview = {
  integration: Integration | null
  endpointCount: number
  events24h: number
  events7d: number
  openFindings: number
  lastEventAt: Date | null
}

export async function getWazuhIntegration(
  workspaceId: string
): Promise<Integration | null> {
  const [row] = await getDb()
    .select()
    .from(integration)
    .where(
      and(
        eq(integration.workspaceId, workspaceId),
        eq(integration.provider, "wazuh")
      )
    )
    .orderBy(asc(integration.createdAt))
    .limit(1)

  return row ?? null
}

export async function getWazuhOverview(
  workspaceId: string
): Promise<WazuhOverview> {
  const db = getDb()
  const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000)
  const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)

  const [current, endpoints, day, week, openFindings, lastEvent] =
    await Promise.all([
      getWazuhIntegration(workspaceId),
      db
        .select({ value: count() })
        .from(asset)
        .innerJoin(project, eq(project.id, asset.projectId))
        .where(
          and(
            eq(project.workspaceId, workspaceId),
            eq(asset.type, "endpoint")
          )
        ),
      db
        .select({ value: count() })
        .from(securityEvent)
        .where(
          and(
            eq(securityEvent.workspaceId, workspaceId),
            gte(securityEvent.eventTime, since24h)
          )
        ),
      db
        .select({ value: count() })
        .from(securityEvent)
        .where(
          and(
            eq(securityEvent.workspaceId, workspaceId),
            gte(securityEvent.eventTime, since7d)
          )
        ),
      db
        .select({ value: count() })
        .from(finding)
        .where(
          and(
            eq(finding.workspaceId, workspaceId),
            eq(finding.source, "wazuh"),
            inArray(finding.status, OPEN_FINDING_STATUSES)
          )
        ),
      db
        .select({ value: max(securityEvent.eventTime) })
        .from(securityEvent)
        .where(eq(securityEvent.workspaceId, workspaceId)),
    ])

  return {
    integration: current,
    endpointCount: endpoints[0]?.value ?? 0,
    events24h: day[0]?.value ?? 0,
    events7d: week[0]?.value ?? 0,
    openFindings: openFindings[0]?.value ?? 0,
    lastEventAt: lastEvent[0]?.value ?? null,
  }
}

export async function connectWazuh(input: {
  workspaceId: string
  projectId: string
  minLevel: number
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<Integration> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "Only workspace admins can configure endpoint monitoring."
    )
  }

  const projectRow = await getProject(input.workspaceId, input.projectId)
  if (!projectRow) {
    throw new AuthorizationError("Project not found in this workspace.")
  }

  const existing = await getWazuhIntegration(input.workspaceId)
  const metadata = {
    ...(existing?.metadata ?? {}),
    minLevel: input.minLevel,
    autoProvision: true,
    source: "wazuh-indexer",
  }

  const db = getDb()
  let saved: Integration

  if (existing) {
    const [updated] = await db
      .update(integration)
      .set({
        projectId: projectRow.id,
        displayName: "Wazuh endpoint monitoring",
        status: "pending",
        metadata,
        // Reconnecting starts a fresh initial window instead of replaying a
        // cursor from before the disconnect.
        syncCursor: existing.status === "disconnected" ? null : existing.syncCursor,
        lastError: null,
        updatedAt: new Date(),
      })
      .where(eq(integration.id, existing.id))
      .returning()
    saved = updated
  } else {
    const [created] = await db
      .insert(integration)
      .values({
        workspaceId: input.workspaceId,
        projectId: projectRow.id,
        provider: "wazuh",
        displayName: "Wazuh endpoint monitoring",
        status: "pending",
        metadata,
      })
      .returning()
    saved = created
  }

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "wazuh.connected",
    targetType: "integration",
    targetId: saved.id,
    metadata: {
      projectId: projectRow.id,
      project: projectRow.name,
      minLevel: input.minLevel,
    },
  })

  return saved
}

export async function disconnectWazuh(input: {
  workspaceId: string
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<boolean> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "Only workspace admins can configure endpoint monitoring."
    )
  }

  const existing = await getWazuhIntegration(input.workspaceId)
  if (!existing) return false

  await getDb()
    .update(integration)
    .set({
      status: "disconnected",
      lastError: null,
      updatedAt: new Date(),
    })
    .where(eq(integration.id, existing.id))

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "wazuh.disconnected",
    targetType: "integration",
    targetId: existing.id,
  })

  return true
}
