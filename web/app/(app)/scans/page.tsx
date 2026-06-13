import type { Metadata } from "next"
import Link from "next/link"
import {
  DatabaseIcon,
  LockKeyIcon,
  PulseIcon,
  TimerIcon,
} from "@phosphor-icons/react/dist/ssr"

import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { requireWorkspace } from "@/lib/auth/session"
import { formatRelativeTime, titleCase } from "@/lib/format"
import { listScanJobs, listScanRuns } from "@/lib/services/scans"

export const metadata: Metadata = { title: "Scans" }

const jobStatusStyles: Record<string, string> = {
  queued: "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  leased: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  running: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  completed:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  cancelled: "",
}

const queueFacts = [
  {
    icon: DatabaseIcon,
    title: "PostgreSQL queue",
    detail:
      "Jobs are claimed with FOR UPDATE SKIP LOCKED. No Redis, no broker, no extra service to run.",
  },
  {
    icon: TimerIcon,
    title: "Leases and retries",
    detail:
      "Every job carries a lease expiry, attempt counter and heartbeat so a stopped worker cannot hold work forever.",
  },
  {
    icon: LockKeyIcon,
    title: "Separate credential",
    detail:
      "The Python worker authenticates with a revocable workspace-scoped token and writes with a restricted database role.",
  },
]

export default async function ScansPage() {
  const { workspace } = await requireWorkspace()
  const [jobs, runs] = await Promise.all([
    listScanJobs(workspace.id, 50),
    listScanRuns(workspace.id, 25),
  ])

  return (
    <>
      <PageHeader
        title="Scans"
        description="Scan history, duration, provenance and safe error summaries. Jobs are created by the app and executed by the Python worker."
      />

      <Card>
        <CardHeader>
          <CardTitle>Scan queue</CardTitle>
          <p className="text-sm text-muted-foreground">
            Newest first. Repository assets are scanned by the worker that claims
            the job.
          </p>
        </CardHeader>
        <CardContent>
          {jobs.length === 0 ? (
            <Empty className="border border-dashed border-border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <PulseIcon />
                </EmptyMedia>
                <EmptyTitle>No scans queued</EmptyTitle>
                <EmptyDescription>
                  Attach a GitHub repository to a project, then use “Scan now” on
                  the project page.
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="overflow-hidden rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Repository</TableHead>
                    <TableHead>Project</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Attempts</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {jobs.map(({ job, assetName, projectId, projectName }) => (
                    <TableRow key={job.id}>
                      <TableCell>
                        <Link
                          href={`/projects/${projectId}`}
                          className="font-mono text-xs underline-offset-4 hover:underline"
                        >
                          {assetName}
                        </Link>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {projectName}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`font-mono text-[10px] ${jobStatusStyles[job.status] ?? ""}`}
                        >
                          {job.status}
                        </Badge>
                        {job.errorSummary ? (
                          <p className="mt-1 max-w-64 truncate font-mono text-[10px] text-muted-foreground">
                            {job.errorSummary}
                          </p>
                        ) : null}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {job.attempts}/{job.maxAttempts}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {formatRelativeTime(job.createdAt)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Scan runs</CardTitle>
          <p className="text-sm text-muted-foreground">
            One row per worker execution, including which tools succeeded and how
            many findings were observed.
          </p>
        </CardHeader>
        <CardContent>
          {runs.length === 0 ? (
            <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
              No scan has run yet. A queued job stays queued until a worker with
              the scanner binaries is online.
            </p>
          ) : (
            <div className="overflow-hidden rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Repository</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Tools</TableHead>
                    <TableHead>Findings</TableHead>
                    <TableHead>Started</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {runs.map(({ run, assetName }) => (
                    <TableRow key={run.id}>
                      <TableCell className="font-mono text-xs">
                        {assetName}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`font-mono text-[10px] ${jobStatusStyles[run.status] ?? ""}`}
                        >
                          {run.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {run.tools.length === 0 ? (
                            <span className="text-xs text-muted-foreground">—</span>
                          ) : (
                            run.tools.map((tool) => (
                              <Badge
                                key={tool.name}
                                variant="secondary"
                                className="font-mono text-[10px]"
                                title={
                                  tool.error ??
                                  `${tool.findingCount} finding(s), ${titleCase(tool.status)}`
                                }
                              >
                                {tool.name}
                                {tool.status !== "ok" ? `:${tool.status}` : ""}
                              </Badge>
                            ))
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {run.findingCount}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {formatRelativeTime(run.startedAt)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="mt-4 grid gap-3 sm:grid-cols-3">
        {queueFacts.map((fact) => (
          <Card key={fact.title} size="sm">
            <CardHeader>
              <fact.icon className="size-5 text-muted-foreground" />
              <CardTitle className="mt-2 text-sm">{fact.title}</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs leading-relaxed text-muted-foreground">
                {fact.detail}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  )
}
