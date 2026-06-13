import "server-only"

import { cache } from "react"
import { headers } from "next/headers"
import { redirect } from "next/navigation"
import { eq } from "drizzle-orm"

import { getAuth } from "@/lib/auth/auth"
import { getDb } from "@/lib/db"
import {
  workspace,
  workspaceMember,
  type Workspace,
  type WorkspaceRole,
} from "@/lib/db/schema"

export type Session = NonNullable<Awaited<ReturnType<typeof getSession>>>

export async function getSession() {
  return getAuth().api.getSession({ headers: await headers() })
}

/** Use in pages and server actions: redirects unauthenticated users. */
export const requireSession = cache(async (): Promise<Session> => {
  const session = await getSession()
  if (!session) redirect("/sign-in")
  return session
})

export type ActiveWorkspace = {
  workspace: Workspace
  role: WorkspaceRole
  memberId: string
}

export type WorkspaceContext = ActiveWorkspace & { session: Session }

/**
 * Phase 0 is single-workspace: the user's oldest membership is the active
 * workspace. Multi-workspace switching can be added without changing the
 * authorization model.
 */
const loadActiveWorkspace = async (
  userId: string
): Promise<ActiveWorkspace | null> => {
  const [row] = await getDb()
    .select({
      workspace,
      role: workspaceMember.role,
      memberId: workspaceMember.id,
    })
    .from(workspaceMember)
    .innerJoin(workspace, eq(workspace.id, workspaceMember.workspaceId))
    .where(eq(workspaceMember.userId, userId))
    .orderBy(workspaceMember.createdAt)
    .limit(1)

  return row ?? null
}

export const getActiveWorkspace = cache(loadActiveWorkspace)

export const requireWorkspace = cache(
  async (): Promise<WorkspaceContext> => {
    const session = await requireSession()
    const active = await getActiveWorkspace(session.user.id)
    if (!active) redirect("/onboarding")
    return { session, ...active }
  }
)

const MANAGE_ROLES: WorkspaceRole[] = ["owner", "admin"]

export function canManageWorkspace(role: WorkspaceRole) {
  return MANAGE_ROLES.includes(role)
}

export class AuthorizationError extends Error {
  constructor(message = "You do not have permission for this action.") {
    super(message)
    this.name = "AuthorizationError"
  }
}
