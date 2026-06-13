import "server-only"

import { betterAuth } from "better-auth"
import { drizzleAdapter } from "better-auth/adapters/drizzle"
import { nextCookies } from "better-auth/next-js"
import { emailOTP } from "better-auth/plugins/email-otp"
import { magicLink } from "better-auth/plugins/magic-link"

import { getDb } from "@/lib/db"
import * as schema from "@/lib/db/schema"
import {
  magicLinkEmail,
  otpEmail,
  sendTransactionalEmail,
} from "@/lib/email/send"
import { isGithubAuthEnabled, isGoogleAuthEnabled, serverEnv } from "@/lib/env"

function createAuth() {
  const env = serverEnv()

  return betterAuth({
    appName: "NeoShield",
    baseURL: env.BETTER_AUTH_URL,
    secret: env.BETTER_AUTH_SECRET,
    trustedOrigins: [env.BETTER_AUTH_URL],
    database: drizzleAdapter(getDb(), {
      provider: "pg",
      schema,
      // Neon's HTTP driver has no interactive transactions; Better Auth then
      // executes multi-step operations sequentially.
      transaction: false,
    }),
    emailAndPassword: { enabled: false },
    socialProviders: {
      ...(isGoogleAuthEnabled()
        ? {
            google: {
              clientId: env.GOOGLE_CLIENT_ID as string,
              clientSecret: env.GOOGLE_CLIENT_SECRET as string,
            },
          }
        : {}),
      ...(isGithubAuthEnabled()
        ? {
            github: {
              clientId: env.GITHUB_APP_CLIENT_ID as string,
              clientSecret: env.GITHUB_APP_CLIENT_SECRET as string,
            },
          }
        : {}),
    },
    session: {
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
      cookieCache: { enabled: true, maxAge: 5 * 60 },
    },
    advanced: {
      // Better Auth already sets HttpOnly + SameSite=Lax cookies.
      useSecureCookies: process.env.NODE_ENV === "production",
    },
    plugins: [
      emailOTP({
        otpLength: 6,
        expiresIn: 10 * 60,
        allowedAttempts: 5,
        storeOTP: "hashed",
        rateLimit: { window: 60, max: 5 },
        async sendVerificationOTP({ email, otp, type }) {
          if (type !== "sign-in") return
          await sendTransactionalEmail({
            to: email,
            ...otpEmail(otp, 10),
            devSecret: `OTP ${otp}`,
          })
        },
      }),
      magicLink({
        expiresIn: 15 * 60,
        rateLimit: { window: 60, max: 5 },
        async sendMagicLink({ email, url }) {
          await sendTransactionalEmail({
            to: email,
            ...magicLinkEmail(url),
            devSecret: `magic link ${url}`,
          })
        },
      }),
      // Must be last: lets server actions persist auth cookies.
      nextCookies(),
    ],
  })
}

type Auth = ReturnType<typeof createAuth>

let instance: Auth | undefined

/** Auth is created lazily so `next build` never needs runtime secrets. */
export function getAuth(): Auth {
  instance ??= createAuth()
  return instance
}
