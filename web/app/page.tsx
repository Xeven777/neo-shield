import Link from "next/link"
import {
  ArrowRightIcon,
  BrowserIcon,
  CheckCircleIcon,
  CloudIcon,
  CodeIcon,
  DesktopIcon,
  GlobeHemisphereWestIcon,
  ShieldCheckIcon,
} from "@phosphor-icons/react/dist/ssr"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { getSession } from "@/lib/auth/session"

export const dynamic = "force-dynamic"

const capabilities = [
  {
    title: "Repository security",
    phase: "Phase 1",
    description:
      "OSV, Gitleaks and Trivy results normalized from the lockfile to the dashboard. No repository code is executed.",
    icon: CodeIcon,
  },
  {
    title: "Domain checks",
    phase: "Phase 1",
    description:
      "TLS expiry, DNS records, redirects and security headers, collected with SSRF-safe resolution.",
    icon: GlobeHemisphereWestIcon,
  },
  {
    title: "Endpoint monitoring",
    phase: "Phase 2",
    description:
      "Wazuh alerts for failed logins, file integrity changes and malware detections mapped to assets.",
    icon: DesktopIcon,
  },
  {
    title: "Network visibility",
    phase: "Phase 2",
    description:
      "Authorized Nmap discovery with explicit scope confirmation and change tracking between scans.",
    icon: BrowserIcon,
  },
  {
    title: "Cloud posture",
    phase: "Phase 4",
    description:
      "Read-only IAM, S3, security-group and CloudTrail checks. Credentials never leave the worker.",
    icon: CloudIcon,
  },
] as const

const pipeline = [
  { step: "01", title: "Collect", detail: "Scanners and integrations" },
  { step: "02", title: "Normalize", detail: "One finding contract" },
  { step: "03", title: "Score", detail: "Deterministic health" },
  { step: "04", title: "Correlate", detail: "Rule-based incidents" },
  { step: "05", title: "Remediate", detail: "Tracked verification" },
] as const

export default async function LandingPage() {
  // The public landing page must stay up even if auth/database is down.
  const session = await getSession().catch(() => null)

  return (
    <div className="relative min-h-svh overflow-hidden">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 -z-10 bg-[linear-gradient(to_right,var(--border)_1px,transparent_1px),linear-gradient(to_bottom,var(--border)_1px,transparent_1px)] [mask-image:radial-gradient(ellipse_at_top,black,transparent_72%)] bg-[size:64px_64px] opacity-40"
      />

      <header className="mx-auto flex w-full max-w-6xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2.5">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheckIcon weight="fill" className="size-5" />
          </span>
          <span className="font-heading text-lg font-semibold tracking-tight">
            NeoShield
          </span>
          <Badge variant="outline" className="ml-1 font-mono text-[10px]">
            phase 0
          </Badge>
        </div>
        <nav className="flex items-center gap-2">
          <Button variant="ghost" size="sm" render={<Link href="/sign-in" />}>
            Sign in
          </Button>
          <Button
            size="sm"
            render={<Link href={session ? "/dashboard" : "/sign-in"} />}
          >
            {session ? "Open dashboard" : "Get started"}
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
        </nav>
      </header>

      <main className="mx-auto w-full max-w-6xl px-6 pt-10 pb-24">
        <div className="grid gap-14 lg:grid-cols-[1.05fr_0.95fr] lg:items-center">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-border bg-muted/40 px-3 py-1 font-mono text-[11px] tracking-wide text-muted-foreground uppercase">
              <span className="size-1.5 rounded-full bg-emerald-500" />
              Unified security intelligence
            </div>
            <h1 className="font-heading text-4xl leading-[1.05] font-semibold tracking-tight text-balance sm:text-5xl lg:text-[3.4rem]">
              Know what is exposed.
              <br />
              <span className="text-primary">Prove what is fixed.</span>
            </h1>
            <p className="mt-6 max-w-xl text-base leading-relaxed text-muted-foreground">
              NeoShield turns repository, domain, endpoint and network signals
              into one normalized finding model with explainable scores,
              correlated incidents and a remediation trail your team can audit.
            </p>

            <div className="mt-8 flex flex-wrap items-center gap-3">
              <Button
                size="lg"
                render={
                  <Link href={session ? "/dashboard" : "/sign-in"} />
                }
              >
                {session ? "Open dashboard" : "Sign in to your workspace"}
                <ArrowRightIcon data-icon="inline-end" />
              </Button>
              <Button
                size="lg"
                variant="outline"
                render={<Link href="/sign-in" />}
              >
                Email code or Google
              </Button>
            </div>

            <ul className="mt-8 grid gap-2 text-sm text-muted-foreground sm:grid-cols-2">
              {[
                "Evidence before opinions",
                "Read-only cloud access",
                "No repository code executed",
                "AI optional, never authoritative",
              ].map((item) => (
                <li key={item} className="flex items-center gap-2">
                  <CheckCircleIcon
                    weight="fill"
                    className="size-4 text-emerald-600 dark:text-emerald-400"
                  />
                  {item}
                </li>
              ))}
            </ul>
          </div>

          <div className="relative">
            <div className="absolute -inset-6 -z-10 rounded-3xl bg-primary/5 blur-2xl" />
            <div className="rounded-xl border border-border bg-card/70 shadow-sm backdrop-blur">
              <div className="flex items-center justify-between border-b border-border px-5 py-3.5">
                <span className="font-mono text-[11px] tracking-wider text-muted-foreground uppercase">
                  Evidence pipeline
                </span>
                <span className="font-mono text-[11px] text-muted-foreground">
                  normalized · deterministic
                </span>
              </div>
              <ol className="divide-y divide-border">
                {pipeline.map((item) => (
                  <li
                    key={item.step}
                    className="flex items-center gap-4 px-5 py-4"
                  >
                    <span className="font-mono text-xs text-muted-foreground">
                      {item.step}
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="font-medium">{item.title}</p>
                      <p className="text-xs text-muted-foreground">
                        {item.detail}
                      </p>
                    </div>
                    <span className="font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
                      p0–p3
                    </span>
                  </li>
                ))}
              </ol>
              <div className="border-t border-border px-5 py-3.5 text-xs text-muted-foreground">
                Every finding keeps its tool, rule id, affected version and
                redacted evidence.
              </div>
            </div>
          </div>
        </div>

        <section className="mt-24">
          <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
            <div>
              <h2 className="font-heading text-xl font-semibold tracking-tight">
                One platform, five signal sources
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                Each module maps into the same finding, scoring and incident
                engine.
              </p>
            </div>
            <span className="font-mono text-[11px] tracking-wider text-muted-foreground uppercase">
              P0 critical · P2 optional
            </span>
          </div>

          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {capabilities.map((capability) => (
              <div
                key={capability.title}
                className="group rounded-xl border border-border bg-card p-5 transition-colors hover:border-primary/40"
              >
                <div className="mb-4 flex items-start justify-between">
                  <span className="flex size-9 items-center justify-center rounded-lg bg-muted text-foreground">
                    <capability.icon className="size-[18px]" />
                  </span>
                  <span className="font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
                    {capability.phase}
                  </span>
                </div>
                <h3 className="font-heading text-base font-medium">
                  {capability.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  {capability.description}
                </p>
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer className="border-t border-border">
        <div className="mx-auto flex w-full max-w-6xl flex-wrap items-center justify-between gap-2 px-6 py-6 font-mono text-[11px] text-muted-foreground">
          <span>NeoShield — security intelligence platform</span>
          <span>Neon PostgreSQL · Next.js · Python worker</span>
        </div>
      </footer>
    </div>
  )
}
