import { z } from "zod"

import { bearerToken, json, jsonError, readJson } from "@/lib/api/http"
import {
  registerWorker,
  verifyWorkerBootstrapToken,
  WORKER_HEARTBEAT_INTERVAL_SECONDS,
} from "@/lib/services/workers"

export const dynamic = "force-dynamic"

const registerSchema = z.object({
  workspaceId: z.uuid("workspaceId must be a UUID."),
  name: z.string().trim().min(1).max(80).default("neoshield-worker"),
  version: z.string().trim().max(40).optional(),
  hostname: z.string().trim().max(200).optional(),
})

/**
 * First-boot registration for the Python worker. Authenticated with the
 * deployment's WORKER_BOOTSTRAP_TOKEN, never with a browser session.
 */
export async function POST(request: Request) {
  const token = bearerToken(request)
  if (!token || !verifyWorkerBootstrapToken(token)) {
    return jsonError(401, "unauthorized", "Invalid worker bootstrap token.")
  }

  const parsed = registerSchema.safeParse(await readJson(request))
  if (!parsed.success) {
    return jsonError(422, "invalid_input", "Invalid registration payload.", {
      fieldErrors: parsed.error.flatten().fieldErrors,
    })
  }

  try {
    const created = await registerWorker(parsed.data)

    return json(
      {
        data: {
          workerId: created.worker.id,
          token: created.token,
          heartbeatIntervalSeconds: WORKER_HEARTBEAT_INTERVAL_SECONDS,
          heartbeatPath: "/api/internal/worker/heartbeat",
        },
      },
      { status: 201 }
    )
  } catch (error) {
    console.error("[worker-register] failed", error)
    return jsonError(
      409,
      "registration_failed",
      "Could not register the worker. Check that the workspace exists."
    )
  }
}
