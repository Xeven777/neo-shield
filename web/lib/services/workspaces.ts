import "server-only"

import { asc, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  user,
  workspace,
  workspaceMember,
  type Workspace,
  type WorkspaceRole,
} from "@/lib/db/schema"
import { recordAudit } from "@/lib/services/audit"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { workspaceNameSchema } from "@/lib/validation/schemas"

function slugify(value: string) {
  const base = value
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)

  return base.length >= 2 ? base : "workspace"
}

export async function createWorkspaceForUser(userId: string, name: string) {
  const parsed = workspaceNameSchema.parse({ name })
  const db = getDb()

  // Random suffix keeps slugs unique without a retry loop.
  const slug = `${slugify(parsed.name)}-${crypto.randomUUID().slice(0, 6)}`

  const [created] = await db
    .insert(workspace)
    .values({ name: parsed.name, slug })
    .returning()

  try {
    await db
      .insert(workspaceMember)
      .values({ workspaceId: created.id, userId, role: "owner" })
  } catch (error) {
    // The Neon HTTP driver has no interactive transactions: clean up manually.
    await db.delete(workspace).where(eq(workspace.id, created.id))
    throw error
  }

  await recordAudit({
    workspaceId: created.id,
    actorUserId: userId,
    action: "workspace.created",
    targetType: "workspace",
    targetId: created.id,
    metadata: { name: created.name },
  })

  return created
}

export async function renameWorkspace(input: {
  workspaceId: string
  actorUserId: string
  actorRole: WorkspaceRole
  name: string
}): Promise<Workspace> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "You do not have permission to rename this workspace."
    )
  }

  const parsed = workspaceNameSchema.parse({ name })

  const [updated] = await getDb()
    .update(workspace)
    .set({ name: parsed.name, updatedAt: new Date() })
    .where(eq(workspace.id, input.workspaceId))
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "workspace.renamed",
    targetType: "workspace",
    targetId: input.workspaceId,
    metadata: { name: parsed.name },
  })

  return updated
}

export type WorkspaceMemberView = {
  id: string
  userId: string
  name: string
  email: string
  role: WorkspaceRole
  joinedAt: Date
}

export async function listWorkspaceMembers(
  workspaceId: string
): Promise<WorkspaceMemberView[]> {
  return getDb()
    .select({
      id: workspaceMember.id,
      userId: workspaceMember.userId,
      name: user.name,
      email: user.email,
      role: workspaceMember.role,
      joinedAt: workspaceMember.createdAt,
    })
    .from(workspaceMember)
    .innerJoin(user, eq(user.id, workspaceMember.userId))
    .where(eq(workspaceMember.workspaceId, workspaceId))
    .orderBy(asc(workspaceMember.createdAt))
}
