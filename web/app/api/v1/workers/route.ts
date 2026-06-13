import { json, readJson, withApiContext } from "@/lib/api/http"
import { canManageWorkspace } from "@/lib/auth/session"
import { createWorker, listWorkers } from "@/lib/services/workers"
import { createWorkerSchema } from "@/lib/validation/schemas"
import { jsonError } from "@/lib/api/http"

export const dynamic = "force-dynamic"

export async function GET() {
  return withApiContext(async ({ workspaceId }) => {
    const workers = await listWorkers(workspaceId)
    return json({ data: workers })
  })
}

export async function POST(request: Request) {
  return withApiContext(async ({ workspaceId, userId, role }) => {
    if (!canManageWorkspace(role)) {
      return jsonError(403, "forbidden", "Only workspace admins can add workers.")
    }

    const body = createWorkerSchema.parse(await readJson(request))
    const created = await createWorker({
      workspaceId,
      actorUserId: userId,
      name: body.name,
    })

    // The plaintext token is returned exactly once and never stored.
    return json(
      {
        data: {
          worker: created.worker,
          token: created.token,
        },
      },
      { status: 201 }
    )
  })
}
