import { json, readJson, withApiContext } from "@/lib/api/http"
import { createProject, listProjects } from "@/lib/services/projects"
import { createProjectSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

export async function GET() {
  return withApiContext(async ({ workspaceId }) => {
    const projects = await listProjects(workspaceId)
    return json({ data: projects })
  })
}

export async function POST(request: Request) {
  return withApiContext(async ({ workspaceId, userId, role }) => {
    const body = createProjectSchema.parse(await readJson(request))
    const project = await createProject({
      workspaceId,
      actorUserId: userId,
      actorRole: role,
      data: body,
    })
    return json({ data: project }, { status: 201 })
  })
}
