import "server-only"

import { getDb } from "@/lib/db"
import { auditLog } from "@/lib/db/schema"

/**
 * Audit logging never throws: a failed audit write must not roll back a user
 * action, but it is reported so it can be investigated.
 */
export async function recordAudit(input: {
  workspaceId?: string | null
  actorUserId?: string | null
  action: string
  targetType?: string
  targetId?: string
  metadata?: Record<string, unknown>
}) {
  try {
    await getDb()
      .insert(auditLog)
      .values({
        workspaceId: input.workspaceId ?? null,
        actorUserId: input.actorUserId ?? null,
        action: input.action,
        targetType: input.targetType,
        targetId: input.targetId,
        metadata: input.metadata ?? {},
      })
  } catch (error) {
    console.error("[audit] failed to record action", input.action, error)
  }
}
