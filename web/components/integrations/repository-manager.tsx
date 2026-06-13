"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import {
  FolderSimpleIcon,
  LinkBreakIcon,
  LinkIcon,
} from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  attachRepositoryAction,
  detachRepositoryAction,
} from "@/app/(app)/integrations/actions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

const selectClassName =
  "h-8 w-full min-w-40 rounded-md border border-input bg-transparent px-2 text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50"

type Repository = {
  id: string
  fullName: string
  defaultBranch: string
  private: boolean
  projectId: string | null
  assetId: string | null
}

export function RepositoryManager({
  repositories,
  projects,
  canManage,
}: {
  repositories: Repository[]
  projects: Array<{ id: string; name: string; assetCount: number }>
  canManage: boolean
}) {
  const router = useRouter()
  const [pendingId, setPendingId] = React.useState<string | null>(null)
  const [selection, setSelection] = React.useState<Record<string, string>>({})
  const [query, setQuery] = React.useState("")

  const filtered = repositories.filter((repository) =>
    repository.fullName.toLowerCase().includes(query.trim().toLowerCase())
  )

  async function attach(repository: Repository) {
    const projectId = selection[repository.id] ?? repository.projectId ?? ""

    if (!projectId) {
      toast.error("Choose a project for this repository first.")
      return
    }

    const formData = new FormData()
    formData.set("repositoryId", repository.id)
    formData.set("projectId", projectId)

    setPendingId(repository.id)
    const result = await attachRepositoryAction(undefined, formData)
    setPendingId(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Repository attached.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not attach the repository.")
  }

  async function detach(repository: Repository) {
    setPendingId(repository.id)
    const result = await detachRepositoryAction(repository.id)
    setPendingId(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Repository detached.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not detach the repository.")
  }

  if (projects.length === 0) {
    return (
      <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
        Create a{" "}
        <Link href="/projects" className="underline underline-offset-4">
          project
        </Link>{" "}
        before attaching repositories.
      </p>
    )
  }

  return (
    <div className="space-y-3">
      <Input
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="Filter repositories"
        className="max-w-xs"
        aria-label="Filter repositories"
      />

      <div className="overflow-hidden rounded-md border border-border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Repository</TableHead>
              <TableHead>Project</TableHead>
              <TableHead className="w-48 text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={3}
                  className="py-6 text-center text-sm text-muted-foreground"
                >
                  No repositories match.
                </TableCell>
              </TableRow>
            ) : (
              filtered.map((repository) => {
                const pending = pendingId === repository.id
                const linkedProject = projects.find(
                  (project) => project.id === repository.projectId
                )

                return (
                  <TableRow key={repository.id}>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs">
                          {repository.fullName}
                        </span>
                        {repository.private ? (
                          <Badge
                            variant="outline"
                            className="font-mono text-[10px]"
                          >
                            private
                          </Badge>
                        ) : null}
                        <span className="font-mono text-[10px] text-muted-foreground">
                          {repository.defaultBranch}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      {repository.assetId && linkedProject ? (
                        <div className="flex items-center gap-2">
                          <FolderSimpleIcon className="size-4 text-muted-foreground" />
                          <Link
                            href={`/projects/${linkedProject.id}`}
                            className="text-xs underline-offset-4 hover:underline"
                          >
                            {linkedProject.name}
                          </Link>
                        </div>
                      ) : (
                        <select
                          className={selectClassName}
                          aria-label={`Project for ${repository.fullName}`}
                          value={selection[repository.id] ?? ""}
                          onChange={(event) =>
                            setSelection((current) => ({
                              ...current,
                              [repository.id]: event.target.value,
                            }))
                          }
                          disabled={!canManage || pending}
                        >
                          <option value="">Select project…</option>
                          {projects.map((project) => (
                            <option key={project.id} value={project.id}>
                              {project.name}
                            </option>
                          ))}
                        </select>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <Button
                          size="sm"
                          variant={repository.assetId ? "ghost" : "outline"}
                          onClick={() => attach(repository)}
                          disabled={
                            !canManage ||
                            pending ||
                            (!selection[repository.id] && !repository.projectId)
                          }
                          title={
                            canManage
                              ? "Attach repository to a project"
                              : "Only workspace admins can attach repositories"
                          }
                        >
                          {pending ? <Spinner /> : <LinkIcon />}
                          {repository.assetId ? "Move" : "Attach"}
                        </Button>
                        {repository.assetId ? (
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => detach(repository)}
                            disabled={!canManage || pending}
                          >
                            <LinkBreakIcon />
                            Detach
                          </Button>
                        ) : null}
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}
