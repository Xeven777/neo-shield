import { z } from "zod"

import { bearerToken, json, jsonError, readJson } from "@/lib/api/http"
import {
  recordWorkerHeartbeat,
  WORKER_HEARTBEAT_INTERVAL_SECONDS,
} from "@/lib/services/workers"

export const dynamic = "force-dynamic"

const heartbeatSchema = z.object({
  version: z.string().trim().max(40).optional(),
  hostname: z.string().trim().max(200).optional(),
})

export async function POST(request: Request) {
  const token = bearerToken(request)
  if (!token) {
    return jsonError(401, "unauthorized", "A worker bearer token is required.")
  }

  const parsed = heartbeatSchema.safeParse((await readJson(request)) ?? {})
  if (!parsed.success) {
    return jsonError(422, "invalid_input", "Invalid heartbeat payload.")
  }

  const worker = await recordWorkerHeartbeat({
    token,
    version: parsed.data.version,
    hostname: parsed.data.hostname,
  })

  if (!worker) {
    return jsonError(401, "invalid_token", "Worker token is invalid or revoked.")
  }

  return json({
    data: {
      workerId: worker.id,
      workspaceId: worker.workspaceId,
      name: worker.name,
      scopes: worker.scopes,
      heartbeatIntervalSeconds: WORKER_HEARTBEAT_INTERVAL_SECONDS,
    },
  })
}
