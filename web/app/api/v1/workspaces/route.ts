import { json, jsonError, readJson, withApiContext } from "@/lib/api/http"
import { getActiveWorkspace } from "@/lib/auth/session"
import {
  createWorkspaceForUser,
  listWorkspaceMembers,
} from "@/lib/services/workspaces"
import { workspaceNameSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

export async function GET() {
  return withApiContext(async ({ workspaceId, role }) => {
    const members = await listWorkspaceMembers(workspaceId)
    return json({ data: { id: workspaceId, role, members } })
  })
}

export async function POST(request: Request) {
  return withApiContext(async ({ userId }) => {
    const existing = await getActiveWorkspace(userId)
    if (existing) {
      return jsonError(
        409,
        "workspace_exists",
        "Phase 0 supports one workspace per user. Rename the existing workspace instead."
      )
    }

    const body = workspaceNameSchema.parse(await readJson(request))
    const created = await createWorkspaceForUser(userId, body.name)
    return json({ data: created }, { status: 201 })
  })
}
