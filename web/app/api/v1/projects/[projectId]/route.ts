import { json, jsonError, readJson, withApiContext } from "@/lib/api/http"
import {
  deleteProject,
  getProject,
  listProjectAssets,
  updateProject,
} from "@/lib/services/projects"
import { updateProjectSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

type Context = { params: Promise<{ projectId: string }> }

export async function GET(_request: Request, context: Context) {
  const { projectId } = await context.params

  return withApiContext(async ({ workspaceId }) => {
    const project = await getProject(workspaceId, projectId)
    if (!project) {
      return jsonError(404, "not_found", "Project not found.")
    }

    const assets = await listProjectAssets(project.id)
    return json({ data: { ...project, assets } })
  })
}

export async function PATCH(request: Request, context: Context) {
  const { projectId } = await context.params

  return withApiContext(async ({ workspaceId, userId, role }) => {
    const body = updateProjectSchema.parse(await readJson(request))
    const updated = await updateProject({
      workspaceId,
      projectId,
      actorUserId: userId,
      actorRole: role,
      data: body,
    })

    if (!updated) {
      return jsonError(404, "not_found", "Project not found.")
    }

    return json({ data: updated })
  })
}

export async function DELETE(_request: Request, context: Context) {
  const { projectId } = await context.params

  return withApiContext(async ({ workspaceId, userId, role }) => {
    const deleted = await deleteProject({
      workspaceId,
      projectId,
      actorUserId: userId,
      actorRole: role,
    })

    if (!deleted) {
      return jsonError(404, "not_found", "Project not found.")
    }

    return new Response(null, { status: 204 })
  })
}
