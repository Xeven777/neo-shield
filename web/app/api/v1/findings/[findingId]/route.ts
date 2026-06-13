import { json, jsonError, readJson, withApiContext } from "@/lib/api/http"
import { getFinding, updateFindingStatus } from "@/lib/services/findings"
import { findingStatusUpdateSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ findingId: string }> }
) {
  const { findingId } = await params

  return withApiContext(async ({ workspaceId }) => {
    const detail = await getFinding(workspaceId, findingId)
    if (!detail) {
      return jsonError(404, "not_found", "Finding not found.")
    }
    return json({ data: detail })
  })
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ findingId: string }> }
) {
  const { findingId } = await params

  return withApiContext(async ({ workspaceId, userId, role }) => {
    const body = findingStatusUpdateSchema.parse(await readJson(request))
    const updated = await updateFindingStatus({
      workspaceId,
      findingId,
      actorUserId: userId,
      actorRole: role,
      status: body.status,
      note: body.note,
    })

    if (!updated) {
      return jsonError(404, "not_found", "Finding not found.")
    }

    return json({ data: updated })
  })
}
