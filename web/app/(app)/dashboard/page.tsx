import type { Metadata } from "next"
import Link from "next/link"
import {
  ArrowUpRightIcon,
  CheckCircleIcon,
  CircleIcon,
  FolderSimpleIcon,
  PulseIcon,
  ShieldWarningIcon,
  SirenIcon,
  StackIcon,
} from "@phosphor-icons/react/dist/ssr"

import { PageHeader } from "@/components/page-header"
import { ProjectDialog } from "@/components/projects/project-dialog"
import { WorkerPill } from "@/components/worker-pill"
import { HealthScoreCard } from "@/components/intelligence/health-score-card"
import { IncidentStatusBadge } from "@/components/incidents/badges"
import { SeverityBadge } from "@/components/findings/badges"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyTitle,
} from "@/components/ui/empty"
import { requireWorkspace } from "@/lib/auth/session"
import { formatRelativeTime, pluralize, titleCase } from "@/lib/format"
import { getWorkspaceOverview } from "@/lib/services/overview"
import { getWorkspaceHealth } from "@/lib/services/scores"
import { listActiveIncidents, refreshIncidents } from "@/lib/services/incidents"

export const metadata: Metadata = { title: "Overview" }

const actionLabels: Record<string, string> = {
  "workspace.created": "Workspace created",
  "workspace.renamed": "Workspace renamed",
  "project.created": "Project created",
  "project.updated": "Project updated",
  "project.deleted": "Project deleted",
  "worker.created": "Worker token issued",
  "worker.registered": "Worker registered",
  "worker.revoked": "Worker revoked",
  "github.connected": "GitHub connected",
  "github.synced": "GitHub repositories synced",
  "github.repository_attached": "Repository attached to project",
  "github.repository_detached": "Repository detached from project",
  "github.disconnected": "GitHub disconnected",
  "domain.added": "Domain added",
  "wazuh.connected": "Wazuh ingestion enabled",
  "wazuh.disconnected": "Wazuh ingestion disabled",
  "network.added": "Authorized network range added",
  "network.enabled": "Network range enabled",
  "network.disabled": "Network range disabled",
  "scan.queued": "Scan queued",
  "finding.status_changed": "Finding status changed",
  "incident.status_changed": "Incident status changed",
  "incident.note_added": "Incident note added",
}

const assetLabels: Record<string, string> = {
  repository: "Repositories",
  domain: "Domains",
  endpoint: "Endpoints",
  network: "Networks",
  aws_account: "AWS accounts",
}

export default async function DashboardPage() {
  const { workspace, session } = await requireWorkspace()
  const [overview, health] = await Promise.all([
    getWorkspaceOverview(workspace.id),
    getWorkspaceHealth(workspace.id),
  ])

  await refreshIncidents(workspace.id)
  const activeIncidents = await listActiveIncidents(workspace.id, 3)

  const setupSteps = [
    {
      label: "Sign in through Better Auth",
      done: true,
      detail: session.user.email,
    },
    {
      label: "Create your first project",
      done: overview.projectCount > 0,
      detail: pluralize(overview.projectCount, "project"),
    },
    {
      label: "Issue a worker token and start the Python worker",
      done: overview.workers.length > 0,
      detail:
        overview.workers.length === 0
          ? "No worker tokens yet"
          : `${overview.onlineWorkers}/${overview.workers.length} online`,
    },
    {
      label: "Connect GitHub and run a repository scan",
      done: overview.scanActivity.completed > 0,
      detail:
        overview.scanActivity.completed === 0
          ? overview.scanActivity.active > 0
            ? `${overview.scanActivity.active} scan(s) queued`
            : "No completed scans yet"
          : `${overview.scanActivity.completed} completed scan(s)`,
    },
  ]

  return (
    <>
      <PageHeader
        title="Overview"
        description="Live facts from your workspace. Nothing here is inferred: unscanned surfaces are labelled as such."
        actions={<ProjectDialog mode="create" />}
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <HealthScoreCard health={health} />

        <Card size="sm">
          <CardHeader>
            <CardDescription>Open findings</CardDescription>
            <div className="flex items-baseline gap-2">
              <CardTitle className="font-mono text-3xl">
                {overview.findings.total}
              </CardTitle>
              <Badge variant="outline" className="font-mono text-[10px]">
                {overview.findings.bySeverity.critical} critical
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <Link
              href="/findings"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              {overview.scanActivity.completed === 0
                ? "No completed scans yet"
                : `${overview.scanActivity.active} scan(s) in queue`}
              <ArrowUpRightIcon className="size-3" />
            </Link>
          </CardContent>
        </Card>

        <Card size="sm">
          <CardHeader>
            <CardDescription>Projects</CardDescription>
            <CardTitle className="font-mono text-3xl">
              {overview.projectCount}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Link
              href="/projects"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              {pluralize(overview.totalAssets, "asset")} attached
              <ArrowUpRightIcon className="size-3" />
            </Link>
          </CardContent>
        </Card>

        <Card size="sm">
          <CardHeader>
            <CardDescription>Scan worker</CardDescription>
            <CardTitle className="font-mono text-3xl">
              {overview.onlineWorkers}
              <span className="text-base text-muted-foreground">
                /{overview.workers.length}
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent className="gap-2">
            <WorkerPill
              online={overview.onlineWorkers}
              total={overview.workers.length}
            />
            <Link
              href="/settings"
              className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              Manage worker tokens
              <ArrowUpRightIcon className="size-3" />
            </Link>
          </CardContent>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader>
            <CardTitle>Freshness</CardTitle>
            <CardDescription>
              What has actually been collected so far.
            </CardDescription>
          </CardHeader>
          <CardContent className="gap-2.5">
            {Object.entries(overview.assetCounts).map(([type, value]) => (
              <div
                key={type}
                className="flex items-center justify-between gap-3 text-sm"
              >
                <span className="flex items-center gap-2">
                  <StackIcon className="size-4 text-muted-foreground" />
                  {assetLabels[type] ?? titleCase(type)}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  {value === 0
                    ? "not connected"
                    : `${value} asset${value === 1 ? "" : "s"}`}
                </span>
              </div>
            ))}
            <div className="mt-2 border-t border-border pt-3 text-xs text-muted-foreground">
              Repository, domain, endpoint and network collectors are active.
              Wazuh events and Nmap inventory appear as soon as their first sync
              completes.
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Getting started</CardTitle>
            <CardDescription>Phase 0 foundation checklist.</CardDescription>
          </CardHeader>
          <CardContent className="gap-3">
            {setupSteps.map((step) => (
              <div key={step.label} className="flex items-start gap-2.5">
                {step.done ? (
                  <CheckCircleIcon
                    weight="fill"
                    className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
                  />
                ) : (
                  <CircleIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                )}
                <div className="min-w-0">
                  <p className="text-sm leading-snug">{step.label}</p>
                  <p className="truncate font-mono text-[11px] text-muted-foreground">
                    {step.detail}
                  </p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent activity</CardTitle>
            <CardDescription>Audited workspace actions.</CardDescription>
          </CardHeader>
          <CardContent>
            {overview.recentActivity.length === 0 ? (
              <Empty className="border border-dashed border-border p-6">
                <EmptyHeader>
                  <EmptyTitle className="text-sm">No activity yet</EmptyTitle>
                  <EmptyDescription className="text-xs">
                    Project and worker changes will appear here.
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : (
              <ul className="space-y-3">
                {overview.recentActivity.map((entry) => (
                  <li
                    key={entry.id}
                    className="flex items-start justify-between gap-3"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-sm">
                        {actionLabels[entry.action] ?? titleCase(entry.action)}
                      </p>
                      <p className="truncate font-mono text-[11px] text-muted-foreground">
                        {entry.targetType ?? "workspace"}
                      </p>
                    </div>
                    <span className="shrink-0 text-[11px] whitespace-nowrap text-muted-foreground">
                      {formatRelativeTime(entry.createdAt)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Potential incidents</CardTitle>
            <CardDescription>
              Deterministic correlation, newest first.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {activeIncidents.length === 0 ? (
              <Empty className="border border-dashed border-border p-6">
                <EmptyHeader>
                  <EmptyTitle className="text-sm">
                    No correlated incidents
                  </EmptyTitle>
                  <EmptyDescription className="text-xs">
                    Rules group repeated authentication failures, exposed remote
                    management, production secrets with domains and high-risk
                    clusters.
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : (
              <ul className="space-y-3">
                {activeIncidents.map(({ incident, findingCount }) => (
                  <li key={incident.id} className="flex items-start gap-2">
                    <SirenIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                    <div className="min-w-0 flex-1">
                      <Link
                        href={`/incidents/${incident.id}`}
                        className="line-clamp-2 text-sm leading-snug underline-offset-4 hover:underline"
                      >
                        {incident.title}
                      </Link>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={incident.severity} />
                        <IncidentStatusBadge status={incident.status} />
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {findingCount} finding
                          {findingCount === 1 ? "" : "s"}
                        </span>
                      </div>
                    </div>
                  </li>
                ))}
              </ul>
            )}
            <Link
              href="/incidents"
              className="mt-2 inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
            >
              All incidents
              <ArrowUpRightIcon className="size-3" />
            </Link>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Intelligence pipeline</CardTitle>
          <CardDescription>
            Where the platform stands right now — no placeholder findings.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            {
              title: "Findings",
              detail:
                overview.findings.total === 0
                  ? "No findings ingested yet — not the same as clean."
                  : `${overview.findings.total} open findings across scanned assets.`,
              href: "/findings",
              icon: ShieldWarningIcon,
            },
            {
              title: "Scans",
              detail:
                overview.scanActivity.completed === 0
                  ? "No completed scans yet."
                  : `${overview.scanActivity.completed} completed runs.`,
              href: "/scans",
              icon: PulseIcon,
            },
            {
              title: "Projects",
              detail: "Available now — create and organise assets.",
              href: "/projects",
              icon: FolderSimpleIcon,
            },
            {
              title: "Integrations",
              detail:
                "GitHub, Wazuh and authorized network ranges are live; AWS is a later phase.",
              href: "/integrations",
              icon: StackIcon,
            },
          ].map((item) => (
            <Link
              key={item.title}
              href={item.href}
              className="rounded-lg border border-border p-4 transition-colors hover:border-primary/40 hover:bg-muted/30"
            >
              <item.icon className="size-5 text-muted-foreground" />
              <p className="mt-3 text-sm font-medium">{item.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
                {item.detail}
              </p>
            </Link>
          ))}
        </CardContent>
      </Card>
    </>
  )
}
