import Link from "next/link"
import { redirect } from "next/navigation"
import type { Metadata } from "next"
import { CheckCircleIcon, ShieldCheckIcon } from "@phosphor-icons/react/dist/ssr"

import { SignInForm } from "@/components/sign-in/sign-in-form"
import { getSession } from "@/lib/auth/session"
import { isGithubAuthEnabled, isGoogleAuthEnabled } from "@/lib/env"

export const dynamic = "force-dynamic"

export const metadata: Metadata = { title: "Sign in" }

const guarantees = [
  "Session cookies are HttpOnly, SameSite and Secure in production.",
  "Email codes are stored hashed and expire after 10 minutes.",
  "Magic links are single-use and expire after 15 minutes.",
  "Only your workspace data is ever queried, checked server-side.",
]

export default async function SignInPage() {
  const session = await getSession()
  if (session) redirect("/dashboard")

  return (
    <div className="grid min-h-svh lg:grid-cols-[1fr_1.05fr]">
      <div className="flex flex-col justify-between px-6 py-8 sm:px-10">
        <div className="flex items-center gap-2.5">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheckIcon weight="fill" className="size-5" />
          </span>
          <Link
            href="/"
            className="font-heading text-lg font-semibold tracking-tight"
          >
            NeoShield
          </Link>
        </div>

        <div className="mx-auto w-full max-w-sm py-10">
          <div className="mb-8">
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              Sign in to your workspace
            </h1>
            <p className="mt-2 text-sm text-muted-foreground">
              No password required. Use a one-time code, a magic link or a
              connected account.
            </p>
          </div>

          <SignInForm
            googleEnabled={isGoogleAuthEnabled()}
            githubEnabled={isGithubAuthEnabled()}
          />

          <p className="mt-8 text-xs leading-relaxed text-muted-foreground">
            By signing in you confirm that you only scan systems and
            repositories you own or are explicitly authorized to assess.
          </p>
        </div>

        <p className="font-mono text-[11px] text-muted-foreground">
          NeoShield · security intelligence platform
        </p>
      </div>

      <div className="relative hidden overflow-hidden border-l border-border bg-muted/30 lg:block">
        <div
          aria-hidden
          className="absolute inset-0 bg-[radial-gradient(ellipse_at_30%_20%,var(--primary)_0%,transparent_55%)] opacity-[0.07]"
        />
        <div
          aria-hidden
          className="absolute inset-0 bg-[linear-gradient(to_right,var(--border)_1px,transparent_1px),linear-gradient(to_bottom,var(--border)_1px,transparent_1px)] bg-[size:56px_56px] opacity-30"
        />
        <div className="relative flex h-full flex-col justify-center px-14">
          <p className="font-mono text-[11px] tracking-widest text-muted-foreground uppercase">
            Security foundation
          </p>
          <h2 className="mt-4 max-w-md font-heading text-3xl leading-tight font-semibold tracking-tight">
            Evidence-first access control, from the session cookie to the last
            query.
          </h2>
          <ul className="mt-8 space-y-3">
            {guarantees.map((item) => (
              <li key={item} className="flex max-w-md items-start gap-3 text-sm text-muted-foreground">
                <CheckCircleIcon
                  weight="fill"
                  className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                />
                {item}
              </li>
            ))}
          </ul>
          <div className="mt-10 rounded-xl border border-border bg-background/70 p-4 font-mono text-[11px] text-muted-foreground">
            <div className="flex justify-between gap-4">
              <span>auth</span>
              <span className="text-foreground">Better Auth · Drizzle</span>
            </div>
            <div className="mt-1.5 flex justify-between gap-4">
              <span>database</span>
              <span className="text-foreground">Neon PostgreSQL</span>
            </div>
            <div className="mt-1.5 flex justify-between gap-4">
              <span>worker</span>
              <span className="text-foreground">scoped revocable token</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
