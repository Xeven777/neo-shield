import { revalidatePath } from "next/cache"
import { NextResponse, type NextRequest } from "next/server"

import {
  canManageWorkspace,
  getActiveWorkspace,
  getSession,
} from "@/lib/auth/session"
import { verifyGithubState } from "@/lib/github/state"
import { connectGithubInstallation } from "@/lib/services/github"

export const dynamic = "force-dynamic"

export async function GET(request: NextRequest) {
  const url = request.nextUrl
  const redirectTo = (status: string) =>
    NextResponse.redirect(new URL(`/integrations?github=${status}`, url.origin))

  const state = verifyGithubState(url.searchParams.get("state"))
  if (!state) return redirectTo("invalid_state")

  const installationId = url.searchParams.get("installation_id")
  if (!installationId || !/^\d+$/.test(installationId)) {
    return redirectTo("missing_installation")
  }

  const session = await getSession()
  if (!session) return redirectTo("sign_in")

  const active = await getActiveWorkspace(session.user.id)
  if (
    !active ||
    active.workspace.id !== state.workspaceId ||
    session.user.id !== state.userId
  ) {
    return redirectTo("invalid_state")
  }

  if (!canManageWorkspace(active.role)) return redirectTo("forbidden")

  try {
    await connectGithubInstallation({
      workspaceId: active.workspace.id,
      userId: session.user.id,
      role: active.role,
      installationId,
    })
  } catch (error) {
    console.error("[github] installation callback failed", error)
    return redirectTo("error")
  }

  revalidatePath("/integrations")
  revalidatePath("/dashboard")
  return redirectTo("connected")
}
