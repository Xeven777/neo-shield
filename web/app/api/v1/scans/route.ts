import { json, readJson, withApiContext } from "@/lib/api/http"
import { listScanJobs, listScanRuns, queueRepositoryScan } from "@/lib/services/scans"
import { queueScanSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

export async function GET() {
  return withApiContext(async ({ workspaceId }) => {
    const [jobs, runs] = await Promise.all([
      listScanJobs(workspaceId),
      listScanRuns(workspaceId),
    ])
    return json({ data: { jobs, runs } })
  })
}

export async function POST(request: Request) {
  return withApiContext(async ({ workspaceId, userId, role }) => {
    const body = queueScanSchema.parse(await readJson(request))
    const result = await queueRepositoryScan({
      workspaceId,
      assetId: body.assetId,
      actorUserId: userId,
      actorRole: role,
    })

    return json({ data: result }, { status: result.reused ? 200 : 201 })
  })
}
