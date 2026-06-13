import { NextResponse, type NextRequest } from "next/server"

import {
  getActiveWorkspace,
  getSession,
  canManageWorkspace,
} from "@/lib/auth/session"
import { isGithubAppConfigured } from "@/lib/env"
import { githubInstallUrl } from "@/lib/github/app"
import { signGithubState } from "@/lib/github/state"

export const dynamic = "force-dynamic"

export async function GET(request: NextRequest) {
  const redirectTo = (status: string) =>
    NextResponse.redirect(
      new URL(`/integrations?github=${status}`, request.nextUrl.origin)
    )

  const session = await getSession()
  if (!session) return redirectTo("sign_in")

  const active = await getActiveWorkspace(session.user.id)
  if (!active) return redirectTo("workspace_required")

  if (!canManageWorkspace(active.role)) return redirectTo("forbidden")
  if (!isGithubAppConfigured()) return redirectTo("not_configured")

  const state = signGithubState({
    workspaceId: active.workspace.id,
    userId: session.user.id,
  })

  try {
    return NextResponse.redirect(githubInstallUrl(state))
  } catch (error) {
    console.error("[github] could not build install url", error)
    return redirectTo("not_configured")
  }
}
