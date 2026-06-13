import "server-only"

import { createHash, randomBytes, timingSafeEqual } from "node:crypto"
import { and, desc, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import { worker, type Worker } from "@/lib/db/schema"
import { recordAudit } from "@/lib/services/audit"
import { serverEnv } from "@/lib/env"

export const WORKER_HEARTBEAT_INTERVAL_SECONDS = 30
export const WORKER_ONLINE_WINDOW_SECONDS = 90
export const WORKER_TOKEN_SCOPES = ["worker:heartbeat"] as const

export type WorkerView = Worker & { isOnline: boolean }

export function hashWorkerToken(token: string) {
  return createHash("sha256").update(token, "utf8").digest("hex")
}

function issueWorkerToken() {
  const token = `nsw_${randomBytes(32).toString("base64url")}`
  return {
    token,
    tokenHash: hashWorkerToken(token),
    tokenPrefix: token.slice(0, 12),
  }
}

export async function listWorkers(workspaceId: string): Promise<WorkerView[]> {
  const rows = await getDb()
    .select()
    .from(worker)
    .where(eq(worker.workspaceId, workspaceId))
    .orderBy(desc(worker.createdAt))

  return rows.map((row) => ({ ...row, isOnline: isWorkerOnline(row) }))
}

export function isWorkerOnline(
  row: Pick<Worker, "lastSeenAt" | "status">,
  now = Date.now()
) {
  if (row.status !== "active" || !row.lastSeenAt) return false
  return now - row.lastSeenAt.getTime() <= WORKER_ONLINE_WINDOW_SECONDS * 1000
}

/** Creates a worker and returns its plaintext token exactly once. */
export async function createWorker(input: {
  workspaceId: string
  actorUserId: string
  name: string
}) {
  const issued = issueWorkerToken()

  const [created] = await getDb()
    .insert(worker)
    .values({
      workspaceId: input.workspaceId,
      name: input.name,
      tokenHash: issued.tokenHash,
      tokenPrefix: issued.tokenPrefix,
      scopes: [...WORKER_TOKEN_SCOPES],
    })
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "worker.created",
    targetType: "worker",
    targetId: created.id,
    metadata: { name: created.name },
  })

  return { worker: created, token: issued.token }
}

export async function revokeWorker(input: {
  workspaceId: string
  workerId: string
  actorUserId: string
}) {
  const [updated] = await getDb()
    .update(worker)
    .set({ status: "revoked", revokedAt: new Date(), updatedAt: new Date() })
    .where(
      and(
        eq(worker.id, input.workerId),
        eq(worker.workspaceId, input.workspaceId)
      )
    )
    .returning()

  if (!updated) return null

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "worker.revoked",
    targetType: "worker",
    targetId: input.workerId,
  })

  return updated
}

export async function findActiveWorkerByToken(
  token: string
): Promise<Worker | null> {
  if (!token || token.length > 200) return null

  const [row] = await getDb()
    .select()
    .from(worker)
    .where(
      and(eq(worker.tokenHash, hashWorkerToken(token)), eq(worker.status, "active"))
    )
    .limit(1)

  return row ?? null
}

export async function recordWorkerHeartbeat(input: {
  token: string
  version?: string
  hostname?: string
}): Promise<Worker | null> {
  const current = await findActiveWorkerByToken(input.token)
  if (!current) return null

  const [updated] = await getDb()
    .update(worker)
    .set({
      lastSeenAt: new Date(),
      updatedAt: new Date(),
      version: input.version?.slice(0, 40) ?? current.version,
      hostname: input.hostname?.slice(0, 200) ?? current.hostname,
    })
    .where(eq(worker.id, current.id))
    .returning()

  return updated ?? null
}

/** Bootstrap registration using WORKER_BOOTSTRAP_TOKEN (never a browser token). */
export async function registerWorker(input: {
  workspaceId: string
  name: string
  version?: string
  hostname?: string
}) {
  const issued = issueWorkerToken()

  const [created] = await getDb()
    .insert(worker)
    .values({
      workspaceId: input.workspaceId,
      name: input.name.slice(0, 80),
      tokenHash: issued.tokenHash,
      tokenPrefix: issued.tokenPrefix,
      scopes: [...WORKER_TOKEN_SCOPES],
      version: input.version?.slice(0, 40),
      hostname: input.hostname?.slice(0, 200),
      lastSeenAt: new Date(),
    })
    .returning()

  await recordAudit({
    workspaceId: input.workspaceId,
    action: "worker.registered",
    targetType: "worker",
    targetId: created.id,
    metadata: { name: created.name },
  })

  return { worker: created, token: issued.token }
}

export function verifyWorkerBootstrapToken(provided: string) {
  const expected = serverEnv().WORKER_BOOTSTRAP_TOKEN
  if (!expected) return false

  const providedBuffer = Buffer.from(provided, "utf8")
  const expectedBuffer = Buffer.from(expected, "utf8")

  return (
    providedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(providedBuffer, expectedBuffer)
  )
}
