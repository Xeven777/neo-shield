import "server-only"

import { ZodError } from "zod"

import { getActiveWorkspace, getSession } from "@/lib/auth/session"
import type { WorkspaceRole } from "@/lib/db/schema"
import { ProjectNameTakenError } from "@/lib/services/projects"
import { ScanRequestError } from "@/lib/services/scans"

export type ApiContext = {
  userId: string
  workspaceId: string
  role: WorkspaceRole
}

export function json(data: unknown, init?: ResponseInit) {
  return Response.json(data, {
    ...init,
    headers: { "cache-control": "no-store", ...init?.headers },
  })
}

export function jsonError(
  status: number,
  code: string,
  message: string,
  details?: unknown
) {
  return json({ error: { code, message, details } }, { status })
}

/**
 * Every product API call resolves the session, the active workspace and the
 * caller's role server-side. Nothing about ownership is taken from the request
 * body or path.
 */
export async function withApiContext(
  handler: (context: ApiContext) => Promise<Response>
): Promise<Response> {
  try {
    const session = await getSession()
    if (!session) {
      return jsonError(401, "unauthorized", "Sign in is required.")
    }

    const active = await getActiveWorkspace(session.user.id)
    if (!active) {
      return jsonError(
        409,
        "workspace_required",
        "Create a workspace before using this API."
      )
    }

    return await handler({
      userId: session.user.id,
      workspaceId: active.workspace.id,
      role: active.role,
    })
  } catch (error) {
    if (error instanceof ZodError) {
      return jsonError(422, "invalid_input", "Invalid request body.", {
        fieldErrors: error.flatten().fieldErrors,
      })
    }

    if (error instanceof ProjectNameTakenError) {
      return jsonError(409, "name_taken", error.message)
    }

    if (error instanceof ScanRequestError) {
      const status = error.code === "not_found" ? 404 : 409
      return jsonError(status, error.code, error.message)
    }

    if (error instanceof Error && error.name === "AuthorizationError") {
      return jsonError(403, "forbidden", error.message)
    }

    console.error("[api] unhandled error", error)
    return jsonError(500, "internal_error", "Something went wrong.")
  }
}

export async function readJson(request: Request): Promise<unknown> {
  try {
    return await request.json()
  } catch {
    return undefined
  }
}

export function bearerToken(request: Request) {
  const header = request.headers.get("authorization")
  if (!header?.startsWith("Bearer ")) return null
  const token = header.slice("Bearer ".length).trim()
  return token.length > 0 ? token : null
}
