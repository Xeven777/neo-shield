import type { Metadata } from "next"
import Link from "next/link"
import { SirenIcon } from "@phosphor-icons/react/dist/ssr"

import { IncidentStatusBadge } from "@/components/incidents/badges"
import { SeverityBadge } from "@/components/findings/badges"
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
import type { IncidentStatus } from "@/lib/db/schema"
import { formatRelativeTime, pluralize, titleCase } from "@/lib/format"
import {
  getIncidentCounts,
  listIncidents,
  refreshIncidents,
} from "@/lib/services/incidents"
import { listProjects } from "@/lib/services/projects"
import {
  findingSeverities,
  incidentFilterSchema,
  incidentStatuses,
} from "@/lib/validation/schemas"

export const metadata: Metadata = { title: "Incidents" }

const PAGE_SIZE = 20

const selectClassName =
  "h-9 rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

function stringParam(value: string | string[] | undefined) {
  return typeof value === "string" && value.length > 0 ? value : undefined
}

export default async function IncidentsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  const params = await searchParams
  const { workspace } = await requireWorkspace()

  const parsed = incidentFilterSchema.safeParse({
    status: stringParam(params.status),
    severity: stringParam(params.severity),
    projectId: stringParam(params.projectId),
    q: stringParam(params.q),
  })
  const filter = parsed.success ? parsed.data : {}

  const requestedPage = Number(stringParam(params.page) ?? 1)
  const page = Number.isFinite(requestedPage)
    ? Math.max(Math.trunc(requestedPage), 1)
    : 1

  // Deterministic reconciliation: rules are re-evaluated before rendering.
  await refreshIncidents(workspace.id)

  const [counts, results, projects] = await Promise.all([
    getIncidentCounts(workspace.id),
    listIncidents(workspace.id, filter, {
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    }),
    listProjects(workspace.id),
  ])

  const totalPages = Math.max(Math.ceil(results.total / PAGE_SIZE), 1)

  const pageHref = (target: number) => {
    const query = new URLSearchParams()
    if (filter.status) query.set("status", filter.status)
    if (filter.severity) query.set("severity", filter.severity)
    if (filter.projectId) query.set("projectId", filter.projectId)
    if (filter.q) query.set("q", filter.q)
    if (target > 1) query.set("page", String(target))
    const suffix = query.toString()
    return suffix ? `/incidents?${suffix}` : "/incidents"
  }

  const activeFilters = Object.values(filter).filter(Boolean).length

  return (
    <>
      <PageHeader
        title="Incidents"
        description="Deterministic correlation rules group related findings by asset, address, project and time window. Every incident shows its rule, evidence and timeline — correlation never claims to prove an attack."
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {incidentStatuses.map((status) => (
          <Badge
            key={status}
            variant="outline"
            className="font-mono text-[10px]"
          >
            {status} {counts.byStatus[status as IncidentStatus]}
          </Badge>
        ))}
        <span className="font-mono text-[11px] text-muted-foreground">
          {pluralize(counts.active, "active incident")} ·{" "}
          {pluralize(counts.total, "incident")} total
        </span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Filter</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            method="get"
            className="flex flex-wrap items-end gap-2"
            aria-label="Filter incidents"
          >
            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Search
              </span>
              <Input
                name="q"
                defaultValue={filter.q ?? ""}
                placeholder="Title, rule or reason"
                className="w-56"
              />
            </label>

            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Status
              </span>
              <select
                name="status"
                defaultValue={filter.status ?? ""}
                className={selectClassName}
              >
                <option value="">Any</option>
                {incidentStatuses.map((status) => (
                  <option key={status} value={status}>
                    {titleCase(status)}
                  </option>
                ))}
              </select>
            </label>

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

            <Button type="submit" size="sm">
              Apply
            </Button>
            {activeFilters > 0 ? (
              <Button
                variant="ghost"
                size="sm"
                render={<Link href="/incidents" />}
              >
                Reset
              </Button>
            ) : null}
          </form>
        </CardContent>
      </Card>

      <div className="mt-4">
        {results.items.length === 0 ? (
          <Empty className="border border-border bg-card/40">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <SirenIcon />
              </EmptyMedia>
              <EmptyTitle>
                {activeFilters > 0
                  ? "No incidents match"
                  : "No correlated incidents"}
              </EmptyTitle>
              <EmptyDescription>
                {activeFilters > 0
                  ? "Adjust or reset the filters to see other incidents."
                  : "Correlation runs over open findings and recent Wazuh events. An empty list means no rule currently matches — not that the workspace is clean. Rules cover repeated endpoint authentication failures, exposed SSH/RDP with failures, secrets in production projects with domains, high-risk clusters and source-IP authentication bursts."}
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        ) : (
          <Card>
            <CardContent className="pt-6">
              <div className="overflow-hidden rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-24">Severity</TableHead>
                      <TableHead>Incident</TableHead>
                      <TableHead>Project</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Related</TableHead>
                      <TableHead className="text-right">
                        Last detected
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.items.map(
                      ({ incident, projectName, findingCount }) => (
                        <TableRow key={incident.id}>
                          <TableCell>
                            <SeverityBadge severity={incident.severity} />
                          </TableCell>
                          <TableCell className="max-w-96">
                            <Link
                              href={`/incidents/${incident.id}`}
                              className="line-clamp-2 text-sm font-medium underline-offset-4 hover:underline"
                            >
                              {incident.title}
                            </Link>
                            <p className="truncate font-mono text-[10px] text-muted-foreground">
                              {incident.correlationRule}
                            </p>
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {projectName}
                          </TableCell>
                          <TableCell>
                            <IncidentStatusBadge status={incident.status} />
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs text-muted-foreground">
                            {findingCount}
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs whitespace-nowrap text-muted-foreground">
                            {formatRelativeTime(incident.lastDetectedAt)}
                          </TableCell>
                        </TableRow>
                      )
                    )}
                  </TableBody>
                </Table>
              </div>

              <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                <span className="font-mono text-[11px] text-muted-foreground">
                  {results.total === 0
                    ? "0 incidents"
                    : `${results.offset + 1}–${Math.min(
                        results.offset + results.items.length,
                        results.total
                      )} of ${results.total}`}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page <= 1}
                    render={
                      page > 1 ? <Link href={pageHref(page - 1)} /> : undefined
                    }
                  >
                    Previous
                  </Button>
                  <span className="font-mono text-[11px] text-muted-foreground">
                    page {page} / {totalPages}
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= totalPages}
                    render={
                      page < totalPages ? (
                        <Link href={pageHref(page + 1)} />
                      ) : undefined
                    }
                  >
                    Next
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </>
  )
}
