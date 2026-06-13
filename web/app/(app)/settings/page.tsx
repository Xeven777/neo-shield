import type { Metadata } from "next"

import { PageHeader } from "@/components/page-header"
import { WorkspaceNameForm } from "@/components/settings/workspace-name-form"
import { WorkerManager } from "@/components/settings/worker-manager"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { canManageWorkspace, requireWorkspace } from "@/lib/auth/session"
import { formatDate } from "@/lib/format"
import { isGoogleAuthEnabled, serverEnv } from "@/lib/env"
import { listWorkers } from "@/lib/services/workers"
import { listWorkspaceMembers } from "@/lib/services/workspaces"

export const metadata: Metadata = { title: "Settings" }

export default async function SettingsPage() {
  const { workspace, role } = await requireWorkspace()
  const [members, workers] = await Promise.all([
    listWorkspaceMembers(workspace.id),
    listWorkers(workspace.id),
  ])

  const env = serverEnv()
  const canManage = canManageWorkspace(role)

  const readiness = [
    {
      label: "Neon PostgreSQL",
      ready: Boolean(env.DATABASE_URL),
      detail: "Drizzle owns migrations; no local database container.",
    },
    {
      label: "Email delivery (Resend)",
      ready: Boolean(env.RESEND_API_KEY),
      detail: env.RESEND_API_KEY
        ? `Sending as ${env.EMAIL_FROM}`
        : "Codes and magic links log to the server console in development.",
    },
    {
      label: "Google OAuth",
      ready: isGoogleAuthEnabled(),
      detail: isGoogleAuthEnabled()
        ? "Enabled on the sign-in page."
        : "Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to enable.",
    },
    {
      label: "Worker bootstrap token",
      ready: Boolean(env.WORKER_BOOTSTRAP_TOKEN),
      detail: "Only used by the Python service's first registration call.",
    },
  ]

  return (
    <>
      <PageHeader
        title="Settings"
        description="Workspace identity, members, worker credentials and deployment readiness."
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Workspace</CardTitle>
            <CardDescription>
              The slug is fixed:{" "}
              <span className="font-mono">{workspace.slug}</span>
            </CardDescription>
          </CardHeader>
          <CardContent className="gap-5">
            <WorkspaceNameForm
              defaultName={workspace.name}
              disabled={!canManage}
            />
            <Separator />
            <div className="grid gap-2 text-xs text-muted-foreground">
              <div className="flex justify-between gap-3">
                <span>Workspace ID</span>
                <span className="truncate font-mono">{workspace.id}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span>Created</span>
                <span className="font-mono">
                  {formatDate(workspace.createdAt)}
                </span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Members</CardTitle>
            <CardDescription>
              Roles are enforced server-side on every read and write.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Member</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Joined</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {members.map((member) => (
                  <TableRow key={member.id}>
                    <TableCell>
                      <p className="font-medium">{member.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {member.email}
                      </p>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className="font-mono text-[10px]"
                      >
                        {member.role}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {formatDate(member.joinedAt)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <p className="mt-3 text-xs text-muted-foreground">
              Inviting additional members arrives with multi-user support. Phase
              0 keeps one workspace per user.
            </p>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Worker tokens</CardTitle>
          <CardDescription>
            Scoped, revocable credentials for the Python scan worker.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <WorkerManager
            workers={workers.map((worker) => ({
              id: worker.id,
              name: worker.name,
              tokenPrefix: worker.tokenPrefix,
              status: worker.status,
              version: worker.version,
              hostname: worker.hostname,
              lastSeenAt: worker.lastSeenAt,
              scopes: worker.scopes,
              isOnline: worker.isOnline,
            }))}
            canManage={canManage}
          />
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Deployment readiness</CardTitle>
          <CardDescription>
            Configuration is read from server-only environment variables.
          </CardDescription>
        </CardHeader>
        <CardContent className="gap-3">
          {readiness.map((item) => (
            <div
              key={item.label}
              className="flex flex-wrap items-start justify-between gap-2 border-b border-border pb-3 last:border-b-0 last:pb-0"
            >
              <div className="min-w-0">
                <p className="text-sm">{item.label}</p>
                <p className="text-xs text-muted-foreground">{item.detail}</p>
              </div>
              <Badge
                variant="outline"
                className={`font-mono text-[10px] ${
                  item.ready
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                    : "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                }`}
              >
                {item.ready ? "configured" : "missing"}
              </Badge>
            </div>
          ))}
        </CardContent>
      </Card>
    </>
  )
}
