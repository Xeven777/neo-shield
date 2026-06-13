import type { Metadata } from "next"
import Link from "next/link"
import {
  ArrowRightIcon,
  FolderSimpleIcon,
} from "@phosphor-icons/react/dist/ssr"

import { PageHeader } from "@/components/page-header"
import { ProjectDialog } from "@/components/projects/project-dialog"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { requireWorkspace } from "@/lib/auth/session"
import { formatDate, pluralize, titleCase } from "@/lib/format"
import { listProjects } from "@/lib/services/projects"

export const metadata: Metadata = { title: "Projects" }

const criticalityStyles: Record<string, string> = {
  high: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  medium:
    "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
}

export default async function ProjectsPage() {
  const { workspace } = await requireWorkspace()
  const projects = await listProjects(workspace.id)

  return (
    <>
      <PageHeader
        title="Projects"
        description="Group the assets you assess together. Scores, findings and scans will roll up per project."
        actions={<ProjectDialog mode="create" />}
      />

      {projects.length === 0 ? (
        <Empty className="border border-border bg-card/40">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <FolderSimpleIcon />
            </EmptyMedia>
            <EmptyTitle>No projects yet</EmptyTitle>
            <EmptyDescription>
              Create your first project, then attach a GitHub repository or add
              a domain.
            </EmptyDescription>
          </EmptyHeader>
          <ProjectDialog mode="create" />
        </Empty>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          {projects.map((project) => (
            <Link
              key={project.id}
              href={`/projects/${project.id}`}
              className="group"
            >
              <Card className="h-full transition-colors group-hover:border-primary/40">
                <CardHeader>
                  <div className="flex items-start justify-between gap-3">
                    <CardTitle className="min-w-0 truncate">
                      {project.name}
                    </CardTitle>
                    <ArrowRightIcon className="mt-1 size-4 shrink-0 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                  </div>
                  <p className="line-clamp-2 min-h-10 text-sm text-muted-foreground">
                    {project.description || "No description yet."}
                  </p>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge
                      variant="secondary"
                      className="font-mono text-[10px]"
                    >
                      {project.environment}
                    </Badge>
                    <Badge
                      variant="outline"
                      className={`font-mono text-[10px] ${criticalityStyles[project.criticality] ?? ""}`}
                    >
                      {titleCase(project.criticality)}
                    </Badge>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {pluralize(project.assetCount, "asset")}
                    </Badge>
                  </div>
                  <p className="mt-3 text-xs text-muted-foreground">
                    Created {formatDate(project.createdAt)} · not scanned
                  </p>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      )}
    </>
  )
}
