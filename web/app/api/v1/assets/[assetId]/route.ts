import { json, jsonError, withApiContext } from "@/lib/api/http"
import { getAssetDetail } from "@/lib/services/endpoints"

export const dynamic = "force-dynamic"

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ assetId: string }> }
) {
  return withApiContext(async ({ workspaceId }) => {
    const { assetId } = await params
    const detail = await getAssetDetail(workspaceId, assetId)

    if (!detail) {
      return jsonError(404, "not_found", "Asset not found in this workspace.")
    }

    return json({ data: detail })
  })
}
