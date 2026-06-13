import "server-only"

import { createHmac, timingSafeEqual } from "node:crypto"

import { serverEnv } from "@/lib/env"

const STATE_TTL_MS = 10 * 60 * 1000

type GithubStatePayload = {
  workspaceId: string
  userId: string
  exp: number
}

function signature(body: string) {
  return createHmac("sha256", serverEnv().BETTER_AUTH_SECRET)
    .update(body)
    .digest("base64url")
}

export function signGithubState(payload: {
  workspaceId: string
  userId: string
}) {
  const body = Buffer.from(
    JSON.stringify({ ...payload, exp: Date.now() + STATE_TTL_MS })
  ).toString("base64url")

  return `${body}.${signature(body)}`
}

export function verifyGithubState(
  state: string | null | undefined
): GithubStatePayload | null {
  if (!state) return null

  const [body, providedSignature] = state.split(".")
  if (!body || !providedSignature) return null

  const expected = Buffer.from(signature(body), "utf8")
  const provided = Buffer.from(providedSignature, "utf8")

  if (expected.length !== provided.length) return null
  if (!timingSafeEqual(expected, provided)) return null

  try {
    const parsed = JSON.parse(
      Buffer.from(body, "base64url").toString("utf8")
    ) as Partial<GithubStatePayload>

    if (
      typeof parsed.workspaceId !== "string" ||
      typeof parsed.userId !== "string" ||
      typeof parsed.exp !== "number" ||
      parsed.exp < Date.now()
    ) {
      return null
    }

    return {
      workspaceId: parsed.workspaceId,
      userId: parsed.userId,
      exp: parsed.exp,
    }
  } catch {
    return null
  }
}
