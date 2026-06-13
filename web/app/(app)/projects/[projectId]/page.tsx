import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { ArrowLeftIcon, StackIcon } from "@phosphor-icons/react/dist/ssr"

import { DeleteProjectDialog } from "@/components/projects/delete-project-dialog"
import { ProjectDialog } from "@/components/projects/project-dialog"
import { ScanNowButton } from "@/components/scans/scan-now-button"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
import { requireWorkspace, canManageWorkspace } from "@/lib/auth/session"
import { formatDateTime, formatRelativeTime, titleCase } from "@/lib/format"
import { getProject, listProjectAssets } from "@/lib/services/projects"
import { listProjectScanJobs } from "@/lib/services/scans"

export const metadata: Metadata = { title: "Project" }

export default async function ProjectDetailPage({
  params,
}: {
  params: Promise<{ projectId: string }>
}) {
  const { projectId } = await params
  const { workspace, role } = await requireWorkspace()

  const project = await getProject(workspace.id, projectId)
  if (!project) notFound()

  const [assets, scanJobs] = await Promise.all([
    listProjectAssets(project.id),
    listProjectScanJobs(project.id),
  ])

  const latestJobByAsset = new Map<string, (typeof scanJobs)[number]["job"]>()
  for (const entry of scanJobs) {
    if (!latestJobByAsset.has(entry.job.assetId)) {
      latestJobByAsset.set(entry.job.assetId, entry.job)
    }
  }

  const canScan = canManageWorkspace(role)

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="-ml-2 mb-4"
        render={<Link href="/projects" />}
      >
        <ArrowLeftIcon />
        All projects
      </Button>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              {project.name}
            </h1>
            <Badge variant="secondary" className="font-mono text-[10px]">
              {project.environment}
            </Badge>
            <Badge variant="outline" className="font-mono text-[10px]">
              {titleCase(project.criticality)} criticality
            </Badge>
          </div>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            {project.description || "No description yet."}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <ProjectDialog
            mode="edit"
            project={{
              id: project.id,
              name: project.name,
              description: project.description,
              environment: project.environment,
              criticality: project.criticality,
            }}
          />
          <DeleteProjectDialog
            projectId={project.id}
            projectName={project.name}
          />
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Assets</CardTitle>
            <CardDescription>
              Repositories, domains, endpoints and networks attached to this
              project.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {assets.length === 0 ? (
              <Empty className="border border-dashed border-border">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <StackIcon />
                  </EmptyMedia>
                  <EmptyTitle>No assets attached</EmptyTitle>
                  <EmptyDescription>
                    Asset connections arrive in Phase 1 (GitHub, domains) and
                    Phase 2 (Wazuh endpoints, authorized networks).
                  </EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Identifier</TableHead>
                    <TableHead>Last scan</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((asset) => {
                    const latestJob = latestJobByAsset.get(asset.id)

                    return (
                      <TableRow key={asset.id}>
                        <TableCell className="font-medium">
                          {asset.displayName}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {asset.type}
                        </TableCell>
                        <TableCell className="max-w-64 truncate font-mono text-xs text-muted-foreground">
                          {asset.identifier}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {latestJob
                            ? `${latestJob.status} · ${formatRelativeTime(
                                latestJob.createdAt
                              )}`
                            : asset.enabled
                              ? "never"
                              : "disabled"}
                        </TableCell>
                        <TableCell className="text-right">
                          {asset.type === "repository" ? (
                            <ScanNowButton
                              assetId={asset.id}
                              disabled={!canScan || !asset.enabled}
                            />
                          ) : null}
                        </TableCell>
                      </TableRow>
                    )
                  })}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Project metadata</CardTitle>
            <CardDescription>Read-only identifiers and timestamps.</CardDescription>
          </CardHeader>
          <CardContent className="gap-3 text-sm">
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Project ID</span>
              <span className="truncate font-mono text-xs">{project.id}</span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Created</span>
              <span className="font-mono text-xs">
                {formatDateTime(project.createdAt)}
              </span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Updated</span>
              <span className="font-mono text-xs">
                {formatDateTime(project.updatedAt)}
              </span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Scan state</span>
              <Badge variant="outline" className="font-mono text-[10px]">
                not scanned
              </Badge>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-muted-foreground">Health score</span>
              <span className="font-mono text-xs text-muted-foreground">—</span>
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  )
}
