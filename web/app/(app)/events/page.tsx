import type { Metadata } from "next"
import Link from "next/link"
import { PulseIcon } from "@phosphor-icons/react/dist/ssr"

import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { requireWorkspace } from "@/lib/auth/session"
import { formatDateTime, formatRelativeTime, titleCase } from "@/lib/format"
import { getEventSeverityCounts, listSecurityEvents } from "@/lib/services/events"
import { listProjects } from "@/lib/services/projects"
import {
  eventFilterSchema,
  findingSeverities,
  findingSources,
  type EventFilter,
} from "@/lib/validation/schemas"

export const metadata: Metadata = { title: "Events" }

const PAGE_SIZE = 50

const severityStyles: Record<string, string> = {
  critical:
    "border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300",
  medium:
    "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  informational: "",
}

const selectClassName =
  "h-8 rounded-md border border-input bg-transparent px-2 text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

function first(value: string | string[] | undefined) {
  return Array.isArray(value) ? value[0] : value
}

function pageHref(filter: EventFilter, offset: number) {
  const params = new URLSearchParams()
  if (filter.severity) params.set("severity", filter.severity)
  if (filter.source) params.set("source", filter.source)
  if (filter.projectId) params.set("projectId", filter.projectId)
  if (filter.q) params.set("q", filter.q)
  if (offset > 0) params.set("page", String(offset / PAGE_SIZE))
  const query = params.toString()
  return query ? `/events?${query}` : "/events"
}

export default async function EventsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  const params = await searchParams
  const parsed = eventFilterSchema.safeParse({
    severity: first(params.severity) || undefined,
    source: first(params.source) || undefined,
    projectId: first(params.projectId) || undefined,
    q: first(params.q) || undefined,
  })
  const filter: EventFilter = parsed.success ? parsed.data : {}

  const pageNumber = Math.max(0, Number(first(params.page) ?? 0) || 0)
  const offset = pageNumber * PAGE_SIZE

  const { workspace } = await requireWorkspace()
  const [page, projects, counts] = await Promise.all([
    listSecurityEvents(workspace.id, filter, {
      limit: PAGE_SIZE,
      offset,
    }),
    listProjects(workspace.id),
    getEventSeverityCounts(workspace.id),
  ])

  const hasPrevious = page.offset > 0
  const hasNext = page.offset + page.items.length < page.total
  const filtered =
    Boolean(filter.severity) ||
    Boolean(filter.source) ||
    Boolean(filter.projectId) ||
    Boolean(filter.q)

  return (
    <>
      <PageHeader
        title="Events"
        description="Endpoint telemetry normalized from Wazuh. Alerts are stored as events even when they do not become findings; raw logs and credentials are never persisted."
      />

      <div className="mb-4 flex flex-wrap gap-1.5">
        {findingSeverities.map((severity) => (
          <Badge
            key={severity}
            variant="outline"
            className={`font-mono text-[10px] ${severityStyles[severity] ?? ""}`}
          >
            {counts.bySeverity[severity]} {severity}
          </Badge>
        ))}
        <Badge variant="secondary" className="font-mono text-[10px]">
          {counts.total} total
        </Badge>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Event history</CardTitle>
          <p className="text-sm text-muted-foreground">
            Newest first. Filter by severity, source, project or a free-text
            query across titles, agents, rule ids and source addresses.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            method="get"
            className="flex flex-wrap items-end gap-2"
            aria-label="Filter events"
          >
            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Severity
              </span>
              <select
                name="severity"
                defaultValue={filter.severity ?? ""}
                className={selectClassName}
              >
                <option value="">Any</option>
                {findingSeverities.map((severity) => (
                  <option key={severity} value={severity}>
                    {titleCase(severity)}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Source
              </span>
              <select
                name="source"
                defaultValue={filter.source ?? ""}
                className={selectClassName}
              >
                <option value="">Any</option>
                {findingSources.map((source) => (
                  <option key={source} value={source}>
                    {titleCase(source)}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Project
              </span>
              <select
                name="projectId"
                defaultValue={filter.projectId ?? ""}
                className={selectClassName}
              >
                <option value="">Any</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>

            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Search
              </span>
              <Input
                name="q"
                defaultValue={filter.q ?? ""}
                placeholder="agent, rule, source IP"
                className="w-56"
              />
            </label>

            <Button type="submit" size="sm" variant="outline">
              Filter
            </Button>
            {filtered ? (
              <Button
                size="sm"
                variant="ghost"
                nativeButton={false}
                render={<Link href="/events" />}
              >
                Reset
              </Button>
            ) : null}
          </form>

          {page.items.length === 0 ? (
            <Empty className="border border-dashed border-border">
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <PulseIcon />
                </EmptyMedia>
                <EmptyTitle>
                  {filtered ? "No matching events" : "No events collected yet"}
                </EmptyTitle>
                <EmptyDescription>
                  {filtered
                    ? "Adjust the filters to see more history."
                    : "Enable Wazuh ingestion in Integrations and run an endpoint sync. Alerts above the configured minimum rule level become events."}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="overflow-hidden rounded-md border border-border">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Time</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Event</TableHead>
                    <TableHead>Agent</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Project</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {page.items.map(({ event, assetName, projectId, projectName }) => (
                    <TableRow key={event.id}>
                      <TableCell className="font-mono text-[11px] whitespace-nowrap text-muted-foreground">
                        <span title={formatDateTime(event.eventTime)}>
                          {formatRelativeTime(event.eventTime)}
                        </span>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`font-mono text-[10px] ${severityStyles[event.severity] ?? ""}`}
                        >
                          {event.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {event.category}
                      </TableCell>
                      <TableCell>
                        <p className="max-w-80 truncate text-sm font-medium">
                          {event.title}
                        </p>
                        <p className="max-w-80 truncate font-mono text-[10px] text-muted-foreground">
                          rule {event.ruleId ?? "—"} · level{" "}
                          {event.ruleLevel ?? "—"}
                        </p>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        <p>{event.agentName ?? "—"}</p>
                        <p>{event.sourceIp ?? ""}</p>
                      </TableCell>
                      <TableCell className="text-sm">
                        <Link
                          href={`/assets/${event.assetId}`}
                          className="underline-offset-4 hover:underline"
                        >
                          {assetName}
                        </Link>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        <Link
                          href={`/projects/${projectId}`}
                          className="underline-offset-4 hover:underline"
                        >
                          {projectName}
                        </Link>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}

          {page.total > 0 ? (
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-mono text-[11px] text-muted-foreground">
                {page.offset + 1}–
                {page.offset + page.items.length} of {page.total}
              </p>
              <div className="flex gap-2">
                {hasPrevious ? (
                  <Button
                    size="sm"
                    variant="outline"
                    nativeButton={false}
                    render={
                      <Link href={pageHref(filter, page.offset - PAGE_SIZE)} />
                    }
                  >
                    Previous
                  </Button>
                ) : null}
                {hasNext ? (
                  <Button
                    size="sm"
                    variant="outline"
                    nativeButton={false}
                    render={
                      <Link href={pageHref(filter, page.offset + PAGE_SIZE)} />
                    }
                  >
                    Next
                  </Button>
                ) : null}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </>
  )
}
