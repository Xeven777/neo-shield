import "server-only"
import { z } from "zod"

/**
 * Server-only environment configuration.
 *
 * Validation is lazy so `next build` does not need runtime secrets; any request
 * that actually touches auth or the database fails fast with a clear message.
 */
const emptyToUndefined = (value: unknown) =>
  typeof value === "string" && value.trim() === "" ? undefined : value

const serverEnvSchema = z.object({
  DATABASE_URL: z.url({
    protocol: /^postgres(ql)?$/,
    error: "DATABASE_URL must be a Neon PostgreSQL connection string",
  }),
  BETTER_AUTH_SECRET: z
    .string()
    .min(32, "BETTER_AUTH_SECRET must be at least 32 characters"),
  BETTER_AUTH_URL: z.url().default("http://localhost:3000"),
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  RESEND_API_KEY: z.string().optional(),
  EMAIL_FROM: z.string().default("NeoShield <noreply@localhost>"),
  WORKER_BOOTSTRAP_TOKEN: z.string().min(24).optional(),
  AUTH_EMAIL_LOG_CODES: z.preprocess(emptyToUndefined, z.string().optional()),

  // GitHub App (Phase 1). Optional so the rest of the platform keeps working.
  GITHUB_APP_ID: z
    .string()
    .regex(/^\d+$/, "GITHUB_APP_ID must be numeric")
    .optional(),
  GITHUB_APP_SLUG: z.string().optional(),
  GITHUB_APP_PRIVATE_KEY: z.string().optional(),
  GITHUB_APP_CLIENT_ID: z.string().optional(),
  GITHUB_APP_CLIENT_SECRET: z.string().optional(),
})

export type ServerEnv = z.infer<typeof serverEnvSchema>

let cached: ServerEnv | undefined

export function serverEnv(): ServerEnv {
  if (cached) return cached

  const parsed = serverEnvSchema.safeParse({
    DATABASE_URL: process.env.DATABASE_URL,
    BETTER_AUTH_SECRET: process.env.BETTER_AUTH_SECRET,
    BETTER_AUTH_URL: process.env.BETTER_AUTH_URL,
    GOOGLE_CLIENT_ID: emptyToUndefined(process.env.GOOGLE_CLIENT_ID),
    GOOGLE_CLIENT_SECRET: emptyToUndefined(process.env.GOOGLE_CLIENT_SECRET),
    RESEND_API_KEY: emptyToUndefined(process.env.RESEND_API_KEY),
    EMAIL_FROM: emptyToUndefined(process.env.EMAIL_FROM),
    WORKER_BOOTSTRAP_TOKEN: emptyToUndefined(
      process.env.WORKER_BOOTSTRAP_TOKEN
    ),
    AUTH_EMAIL_LOG_CODES: process.env.AUTH_EMAIL_LOG_CODES,
    GITHUB_APP_ID: emptyToUndefined(process.env.GITHUB_APP_ID),
    GITHUB_APP_SLUG: emptyToUndefined(process.env.GITHUB_APP_SLUG),
    GITHUB_APP_PRIVATE_KEY: emptyToUndefined(
      process.env.GITHUB_APP_PRIVATE_KEY
    ),
    GITHUB_APP_CLIENT_ID: emptyToUndefined(process.env.GITHUB_APP_CLIENT_ID),
    GITHUB_APP_CLIENT_SECRET: emptyToUndefined(
      process.env.GITHUB_APP_CLIENT_SECRET
    ),
  })

  if (!parsed.success) {
    const details = parsed.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n")
    throw new Error(
      `Invalid server environment. Copy .env.example to .env.local and fill it in.\n${details}`
    )
  }

  cached = parsed.data
  return cached
}

/** Optional integrations that are allowed to be absent. */
export function isGoogleAuthEnabled() {
  return Boolean(
    process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET
  )
}

export function isGithubAuthEnabled() {
  return Boolean(
    process.env.GITHUB_APP_CLIENT_ID && process.env.GITHUB_APP_CLIENT_SECRET
  )
}

export function isGithubAppConfigured() {
  return Boolean(
    process.env.GITHUB_APP_ID &&
    process.env.GITHUB_APP_SLUG &&
    process.env.GITHUB_APP_PRIVATE_KEY
  )
}

export function shouldLogAuthCodes() {
  return (
    process.env.NODE_ENV !== "production" ||
    process.env.AUTH_EMAIL_LOG_CODES === "1"
  )
}
