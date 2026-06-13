import type { Metadata } from "next"
import Link from "next/link"
import { ShieldWarningIcon } from "@phosphor-icons/react/dist/ssr"

import { FindingStatusBadge, SeverityBadge } from "@/components/findings/badges"
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
import type { FindingSeverity } from "@/lib/db/schema"
import { formatRelativeTime, pluralize, titleCase } from "@/lib/format"
import { getFindingCounts, listFindings } from "@/lib/services/findings"
import { listProjects } from "@/lib/services/projects"
import {
  findingFilterSchema,
  findingSeverities,
  findingSources,
  findingStatuses,
} from "@/lib/validation/schemas"

export const metadata: Metadata = { title: "Findings" }

const PAGE_SIZE = 25

const selectClassName =
  "h-9 rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

function stringParam(value: string | string[] | undefined) {
  return typeof value === "string" && value.length > 0 ? value : undefined
}

export default async function FindingsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
}) {
  const params = await searchParams
  const { workspace } = await requireWorkspace()

  const parsed = findingFilterSchema.safeParse({
    severity: stringParam(params.severity),
    status: stringParam(params.status),
    source: stringParam(params.source),
    projectId: stringParam(params.projectId),
    q: stringParam(params.q),
  })
  const filter = parsed.success ? parsed.data : {}

  const requestedPage = Number(stringParam(params.page) ?? 1)
  const page = Number.isFinite(requestedPage)
    ? Math.max(Math.trunc(requestedPage), 1)
    : 1

  const [counts, results, projects] = await Promise.all([
    getFindingCounts(workspace.id),
    listFindings(workspace.id, filter, {
      limit: PAGE_SIZE,
      offset: (page - 1) * PAGE_SIZE,
    }),
    listProjects(workspace.id),
  ])

  const totalPages = Math.max(Math.ceil(results.total / PAGE_SIZE), 1)

  const pageHref = (target: number) => {
    const query = new URLSearchParams()
    if (filter.severity) query.set("severity", filter.severity)
    if (filter.status) query.set("status", filter.status)
    if (filter.source) query.set("source", filter.source)
    if (filter.projectId) query.set("projectId", filter.projectId)
    if (filter.q) query.set("q", filter.q)
    if (target > 1) query.set("page", String(target))
    const suffix = query.toString()
    return suffix ? `/findings?${suffix}` : "/findings"
  }

  const activeFilters = Object.values(filter).filter(Boolean).length

  return (
    <>
      <PageHeader
        title="Findings"
        description="One normalized finding model across every scanner, deduplicated per asset with redacted evidence."
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        {findingSeverities.map((severity) => (
          <Badge
            key={severity}
            variant="outline"
            className="font-mono text-[10px]"
          >
            {severity} {counts.bySeverity[severity as FindingSeverity]}
          </Badge>
        ))}
        <span className="font-mono text-[11px] text-muted-foreground">
          {pluralize(counts.total, "open finding")} · resolved findings are
          hidden from these counts
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
            aria-label="Filter findings"
          >
            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Search
              </span>
              <Input
                name="q"
                defaultValue={filter.q ?? ""}
                placeholder="Title, rule or key"
                className="w-52"
              />
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
                Status
              </span>
              <select
                name="status"
                defaultValue={filter.status ?? ""}
                className={selectClassName}
              >
                <option value="">Any</option>
                {findingStatuses.map((status) => (
                  <option key={status} value={status}>
                    {titleCase(status)}
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

            <Button type="submit" size="sm">
              Apply
            </Button>
            {activeFilters > 0 ? (
              <Button
                variant="ghost"
                size="sm"
                render={<Link href="/findings" />}
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
                <ShieldWarningIcon />
              </EmptyMedia>
              <EmptyTitle>
                {activeFilters > 0
                  ? "No findings match"
                  : "No findings ingested yet"}
              </EmptyTitle>
              <EmptyDescription>
                {activeFilters > 0
                  ? "Adjust or reset the filters to see other findings."
                  : "Queue a scan from a project. Gitleaks, OSV-Scanner and Trivy results appear here once a worker completes a run. An empty feed is not the same as a clean repository."}
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
                      <TableHead>Finding</TableHead>
                      <TableHead>Asset</TableHead>
                      <TableHead>Project</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead className="text-right">Last seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {results.items.map(
                      ({ finding, assetName, projectName }) => (
                        <TableRow key={finding.id}>
                          <TableCell>
                            <SeverityBadge severity={finding.severity} />
                          </TableCell>
                          <TableCell className="max-w-80">
                            <Link
                              href={`/findings/${finding.id}`}
                              className="line-clamp-2 text-sm font-medium underline-offset-4 hover:underline"
                            >
                              {finding.title}
                            </Link>
                            <p className="truncate font-mono text-[10px] text-muted-foreground">
                              {finding.sourceTool}
                              {finding.sourceRuleId
                                ? ` · ${finding.sourceRuleId}`
                                : ""}
                            </p>
                          </TableCell>
                          <TableCell className="max-w-48 truncate font-mono text-xs text-muted-foreground">
                            {assetName}
                          </TableCell>
                          <TableCell className="text-sm text-muted-foreground">
                            {projectName}
                          </TableCell>
                          <TableCell>
                            <FindingStatusBadge status={finding.status} />
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs whitespace-nowrap text-muted-foreground">
                            {formatRelativeTime(finding.lastSeenAt)}
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
                    ? "0 findings"
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
