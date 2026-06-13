import type { NextRequest } from "next/server"

import { json, jsonError, withApiContext } from "@/lib/api/http"
import { listFindings } from "@/lib/services/findings"
import { findingFilterSchema } from "@/lib/validation/schemas"

export const dynamic = "force-dynamic"

function pagination(searchParams: URLSearchParams) {
  const limit = Number(searchParams.get("limit") ?? 25)
  const offset = Number(searchParams.get("offset") ?? 0)

  return {
    limit: Number.isFinite(limit) ? Math.min(Math.max(Math.trunc(limit), 1), 100) : 25,
    offset: Number.isFinite(offset) ? Math.max(Math.trunc(offset), 0) : 0,
  }
}

export async function GET(request: NextRequest) {
  return withApiContext(async ({ workspaceId }) => {
    const searchParams = request.nextUrl.searchParams
    const parsed = findingFilterSchema.safeParse({
      severity: searchParams.get("severity") ?? undefined,
      status: searchParams.get("status") ?? undefined,
      source: searchParams.get("source") ?? undefined,
      projectId: searchParams.get("projectId") ?? undefined,
      q: searchParams.get("q") ?? undefined,
    })

    if (!parsed.success) {
      return jsonError(422, "invalid_query", "Invalid finding filters.", {
        fieldErrors: parsed.error.flatten().fieldErrors,
      })
    }

    const page = await listFindings(
      workspaceId,
      parsed.data,
      pagination(searchParams)
    )

    return json({ data: page.items, meta: { total: page.total, limit: page.limit, offset: page.offset } })
  })
}
