import { json, jsonError, withApiContext } from "@/lib/api/http"
import { canManageWorkspace } from "@/lib/auth/session"
import { revokeWorker } from "@/lib/services/workers"

export const dynamic = "force-dynamic"

type Context = { params: Promise<{ workerId: string }> }

export async function DELETE(_request: Request, context: Context) {
  const { workerId } = await context.params

  return withApiContext(async ({ workspaceId, userId, role }) => {
    if (!canManageWorkspace(role)) {
      return jsonError(
        403,
        "forbidden",
        "Only workspace admins can revoke workers."
      )
    }

    const revoked = await revokeWorker({
      workspaceId,
      workerId,
      actorUserId: userId,
    })

    if (!revoked) {
      return jsonError(404, "not_found", "Worker not found.")
    }

    return json({ data: revoked })
  })
}
