import { json, jsonError, readJson, withApiContext } from "@/lib/api/http"
import { getIncident, updateIncidentStatus } from "@/lib/services/incidents"
import { incidentStatusUpdateSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ incidentId: string }> }
) {
  const { incidentId } = await params

  return withApiContext(async ({ workspaceId }) => {
    const detail = await getIncident(workspaceId, incidentId)
    if (!detail) {
      return jsonError(404, "not_found", "Incident not found.")
    }
    return json({ data: detail })
  })
}

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ incidentId: string }> }
) {
  const { incidentId } = await params

  return withApiContext(async ({ workspaceId, userId, role }) => {
    const body = incidentStatusUpdateSchema.parse(await readJson(request))
    const updated = await updateIncidentStatus({
      workspaceId,
      incidentId,
      actorUserId: userId,
      actorRole: role,
      status: body.status,
      note: body.note,
    })

    if (!updated) {
      return jsonError(404, "not_found", "Incident not found.")
    }

    return json({ data: updated })
  })
}
