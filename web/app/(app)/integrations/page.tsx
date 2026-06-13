import type { Metadata } from "next"
import Link from "next/link"
import {
  ArrowRightIcon,
  CloudIcon,
  DesktopIcon,
  HardDrivesIcon,
} from "@phosphor-icons/react/dist/ssr"

import { GithubPanel } from "@/components/integrations/github-panel"
import { PageHeader } from "@/components/page-header"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { canManageWorkspace, requireWorkspace } from "@/lib/auth/session"
import { isGithubAppConfigured } from "@/lib/env"
import { formatRelativeTime } from "@/lib/format"
import { getGithubConnection } from "@/lib/services/github"
import { listProjects } from "@/lib/services/projects"
import { isWorkerOnline, listWorkers } from "@/lib/services/workers"

export const metadata: Metadata = { title: "Integrations" }

const githubStatuses: Record<
  string,
  { title: string; detail: string; destructive?: boolean }
> = {
  connected: {
    title: "GitHub connected",
    detail:
      "Repositories were synced from the installation. Attach one to a project to make it scannable.",
  },
  not_configured: {
    title: "GitHub App is not configured",
    detail:
      "Add GITHUB_APP_ID, GITHUB_APP_SLUG and GITHUB_APP_PRIVATE_KEY to the web app environment, then try again.",
    destructive: true,
  },
  invalid_state: {
    title: "Installation could not be verified",
    detail:
      "The install state was missing, expired or signed for another session. Start the installation again.",
    destructive: true,
  },
  missing_installation: {
    title: "No installation returned",
    detail:
      "GitHub did not return an installation id. Try installing the app again and grant access to at least one repository.",
    destructive: true,
  },
  forbidden: {
    title: "Admin permission required",
    detail: "Only workspace owners and admins can connect or change GitHub.",
    destructive: true,
  },
  error: {
    title: "GitHub connection failed",
    detail:
      "NeoShield could not verify the installation with GitHub. Check the app credentials and try again.",
    destructive: true,
  },
  sign_in: {
    title: "Sign in required",
    detail: "Your session ended before the installation finished.",
    destructive: true,
  },
  workspace_required: {
    title: "Workspace required",
    detail: "Create a workspace before connecting GitHub.",
    destructive: true,
  },
}

export default async function IntegrationsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  const params = await searchParams
  const githubStatus =
    typeof params.github === "string" ? githubStatuses[params.github] : undefined

  const { workspace, role } = await requireWorkspace()
  const [workers, github, projects] = await Promise.all([
    listWorkers(workspace.id),
    getGithubConnection(workspace.id),
    listProjects(workspace.id),
  ])

  const activeWorkers = workers.filter((worker) => worker.status === "active")
  const online = activeWorkers.filter((worker) => isWorkerOnline(worker))
  const manage = canManageWorkspace(role)

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Connection status for every signal source. Optional modules stay disabled without breaking the platform."
      />

      {githubStatus ? (
        <Alert
          variant={githubStatus.destructive ? "destructive" : "default"}
          className="mb-4"
        >
          <AlertTitle>{githubStatus.title}</AlertTitle>
          <AlertDescription>{githubStatus.detail}</AlertDescription>
        </Alert>
      ) : null}

      <GithubPanel
        connection={github}
        projects={projects}
        canManage={manage}
        configured={isGithubAppConfigured()}
      />

      <Card className="mt-4">
        <CardHeader className="flex flex-row items-start justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <HardDrivesIcon className="size-5 text-muted-foreground" />
              Python scan worker
              <Badge
                variant="outline"
                className={`font-mono text-[10px] ${
                  online.length > 0
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    : ""
                }`}
              >
                {online.length > 0 ? "online" : "offline"}
              </Badge>
            </CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              Long-running FastAPI service that claims jobs and runs Gitleaks,
              OSV-Scanner and Trivy. Heartbeats every 30 seconds; online means
              seen in the last 90 seconds.
            </p>
          </div>
          <Button variant="outline" size="sm" render={<Link href="/settings" />}>
            Manage tokens
            <ArrowRightIcon data-icon="inline-end" />
          </Button>
        </CardHeader>
        <CardContent>
          {activeWorkers.length === 0 ? (
            <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
              No worker token has been issued. Create one in Settings, then set
              <code className="mx-1 rounded bg-muted px-1 py-0.5 font-mono text-xs">
                NEOSHIELD_WORKER_TOKEN
              </code>
              and{" "}
              <code className="mx-1 rounded bg-muted px-1 py-0.5 font-mono text-xs">
                NEOSHIELD_DATABASE_URL
              </code>
              in the Python service.
            </p>
          ) : (
            <div className="divide-y divide-border">
              {activeWorkers.map((worker) => (
                <div
                  key={worker.id}
                  className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={`size-1.5 rounded-full ${
                        isWorkerOnline(worker)
                          ? "bg-emerald-500"
                          : "bg-muted-foreground/50"
                      }`}
                    />
                    <span className="font-medium">{worker.name}</span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {worker.hostname ?? "unknown host"}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 font-mono text-[11px] text-muted-foreground">
                    <span>{worker.version ?? "version unknown"}</span>
                    <span>seen {formatRelativeTime(worker.lastSeenAt)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        {[
          {
            name: "Wazuh",
            phase: "Phase 2",
            icon: DesktopIcon,
            detail:
              "Endpoint alerts normalized from the Wazuh manager or indexer API. Management ports stay private.",
          },
          {
            name: "AWS",
            phase: "Phase 4",
            icon: CloudIcon,
            detail:
              "Read-only IAM, S3, security group and CloudTrail checks using the worker's local credential chain.",
          },
        ].map((provider) => (
          <Card key={provider.name} size="sm">
            <CardHeader>
              <div className="flex items-start justify-between">
                <provider.icon className="size-5 text-muted-foreground" />
                <div className="flex items-center gap-1.5">
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {provider.phase}
                  </Badge>
                  <Badge variant="secondary" className="font-mono text-[10px]">
                    not connected
                  </Badge>
                </div>
              </div>
              <CardTitle className="mt-3">{provider.name}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {provider.detail}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  )
}
