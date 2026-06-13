"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import {
  GlobeIcon,
  PlusIcon,
  PowerIcon,
} from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  addDomainAction,
  setDomainEnabledAction,
} from "@/app/(app)/integrations/actions"
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

export type DomainRow = {
  assetId: string
  domain: string
  projectId: string
  projectName: string
  enabled: boolean
}

export function DomainPanel({
  domains,
  projects,
  canManage,
}: {
  domains: DomainRow[]
  projects: Array<{ id: string; name: string }>
  canManage: boolean
}) {
  const router = useRouter()
  const [domain, setDomain] = React.useState("")
  const [projectId, setProjectId] = React.useState(projects[0]?.id ?? "")
  const [adding, setAdding] = React.useState(false)
  const [pendingId, setPendingId] = React.useState<string | null>(null)

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!projectId) {
      toast.error("Create a project before adding a domain.")
      return
    }

    const formData = new FormData()
    formData.set("projectId", projectId)
    formData.set("domain", domain)

    setAdding(true)
    const result = await addDomainAction(undefined, formData)
    setAdding(false)

    if (result?.status === "success") {
      toast.success(result.message ?? "Domain added.")
      setDomain("")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not add the domain.")
  }

  async function toggle(row: DomainRow) {
    setPendingId(row.assetId)
    const result = await setDomainEnabledAction(row.assetId, !row.enabled)
    setPendingId(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Domain updated.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not update the domain.")
  }

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <GlobeIcon className="size-5 text-muted-foreground" />
          Domains
          <Badge variant="outline" className="font-mono text-[10px]">
            {domains.filter((row) => row.enabled).length} active
          </Badge>
        </CardTitle>
        <CardDescription className="max-w-2xl">
          DNS, TLS, HTTPS redirects and security headers for domains you own.
          Checks reject private, loopback and reserved addresses, so an internal
          hostname cannot be probed through this worker.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {projects.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            Create a project before adding a domain.
          </p>
        ) : (
          <form
            onSubmit={submit}
            className="flex flex-wrap items-end gap-2"
            aria-label="Add a domain"
          >
            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Domain
              </span>
              <Input
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="example.com"
                className="w-64"
                autoComplete="off"
                spellCheck={false}
                disabled={!canManage || adding}
              />
            </label>

            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Project
              </span>
              <select
                className={selectClassName}
                value={projectId}
                onChange={(event) => setProjectId(event.target.value)}
                disabled={!canManage || adding}
              >
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>

            <Button
              type="submit"
              size="sm"
              disabled={!canManage || adding || !domain.trim()}
              title={
                canManage ? undefined : "Only workspace admins can add domains"
              }
            >
              {adding ? <Spinner /> : <PlusIcon />}
              Add domain
            </Button>
          </form>
        )}

        {domains.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            No domains yet. Add one you control, then queue a scan. NeoShield
            only reads public DNS records and HTTP responses; it never changes
            DNS or server configuration.
          </p>
        ) : (
          <div className="overflow-hidden rounded-md border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead>Project</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {domains.map((row) => {
                  const pending = pendingId === row.assetId

                  return (
                    <TableRow key={row.assetId}>
                      <TableCell className="font-mono text-xs">
                        {row.domain}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {row.projectName}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="font-mono text-[10px]"
                        >
                          {row.enabled ? "enabled" : "disabled"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <ScanNowButton
                            assetId={row.assetId}
                            disabled={!canManage || !row.enabled}
                          />
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => toggle(row)}
                            disabled={!canManage || pending}
                            title={
                              canManage
                                ? undefined
                                : "Only workspace admins can change domains"
                            }
                          >
                            {pending ? <Spinner /> : <PowerIcon />}
                            {row.enabled ? "Disable" : "Enable"}
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
