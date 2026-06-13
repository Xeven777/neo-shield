import type { Metadata } from "next"
import { redirect } from "next/navigation"
import { ShieldCheckIcon } from "@phosphor-icons/react/dist/ssr"

import { WorkspaceOnboardingForm } from "@/components/onboarding-form"
import { getActiveWorkspace, requireSession } from "@/lib/auth/session"

export const dynamic = "force-dynamic"

export const metadata: Metadata = { title: "Create your workspace" }

export default async function OnboardingPage() {
  const session = await requireSession()

  const existing = await getActiveWorkspace(session.user.id)
  if (existing) redirect("/dashboard")

  return (
    <div className="mx-auto flex min-h-svh w-full max-w-lg flex-col justify-center px-6 py-12">
      <div className="mb-8 flex items-center gap-2.5">
        <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <ShieldCheckIcon weight="fill" className="size-5" />
        </span>
        <span className="font-heading text-lg font-semibold tracking-tight">
          NeoShield
        </span>
      </div>

      <h1 className="font-heading text-2xl font-semibold tracking-tight">
        Create your workspace
      </h1>
      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
        A workspace groups projects, assets, findings and worker tokens. Signed
        in as <span className="font-medium text-foreground">{session.user.email}</span>.
      </p>

      <div className="mt-8">
        <WorkspaceOnboardingForm />
      </div>

      <p className="mt-8 text-xs text-muted-foreground">
        Phase 0 keeps one workspace per user. You can rename it later in
        settings.
      </p>
    </div>
  )
}
