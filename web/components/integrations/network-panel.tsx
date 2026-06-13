"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { NetworkIcon, PlusIcon, PowerIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  addNetworkAction,
  setNetworkEnabledAction,
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
import { formatRelativeTime } from "@/lib/format"
import { parseNetworkScope, type NetworkScope } from "@/lib/validation/network"

const selectClassName =
  "h-8 w-full min-w-40 rounded-md border border-input bg-transparent px-2 text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50"

export type NetworkRow = {
  assetId: string
  cidr: string
  scanProfile: string
  enabled: boolean
  projectId: string
  projectName: string
  hostCount: number
  activeHostCount: number
  activeServiceCount: number
  confirmedAt: string | null
  scanReady: boolean
}

function scopePreview(value: string): {
  scope: NetworkScope | null
  error: string | null
} {
  if (!value.trim()) return { scope: null, error: null }
  try {
    return { scope: parseNetworkScope(value), error: null }
  } catch (error) {
    return {
      scope: null,
      error: error instanceof Error ? error.message : "Enter a valid CIDR.",
    }
  }
}

export function NetworkPanel({
  networks,
  projects,
  canManage,
}: {
  networks: NetworkRow[]
  projects: Array<{ id: string; name: string }>
  canManage: boolean
}) {
  const router = useRouter()
  const [projectId, setProjectId] = React.useState(projects[0]?.id ?? "")
  const [cidr, setCidr] = React.useState("")
  const [confirmation, setConfirmation] = React.useState("")
  const [scanProfile, setScanProfile] = React.useState("services")
  const [authorized, setAuthorized] = React.useState(false)
  const [adding, setAdding] = React.useState(false)
  const [pendingId, setPendingId] = React.useState<string | null>(null)

  const { scope, error: scopeError } = scopePreview(cidr)
  const confirmationMatches = Boolean(scope && confirmation === scope.cidr)
  const canSubmit =
    canManage &&
    !adding &&
    Boolean(projectId) &&
    Boolean(scope) &&
    authorized &&
    confirmationMatches

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!projectId) {
      toast.error("Create a project before adding a network range.")
      return
    }
    if (!scope) {
      toast.error(scopeError ?? "Enter a valid CIDR range.")
      return
    }
    if (confirmation !== scope.cidr) {
      toast.error(`Type ${scope.cidr} exactly to confirm the scope.`)
      return
    }
    if (!authorized) {
      toast.error("Confirm that you are authorized to scan this range.")
      return
    }

    const formData = new FormData()
    formData.set("projectId", projectId)
    formData.set("cidr", scope.cidr)
    formData.set("scanProfile", scanProfile)
    formData.set("confirmation", confirmation)
    if (authorized) formData.set("authorization", "on")

    setAdding(true)
    const result = await addNetworkAction(undefined, formData)
    setAdding(false)

    if (result?.status === "success") {
      toast.success(result.message ?? "Network range added.")
      setCidr("")
      setConfirmation("")
      setAuthorized(false)
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not add the network range.")
  }

  async function toggle(row: NetworkRow) {
    setPendingId(row.assetId)
    const result = await setNetworkEnabledAction(row.assetId, !row.enabled)
    setPendingId(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Network range updated.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not update the network range.")
  }

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <NetworkIcon className="size-5 text-muted-foreground" />
          Authorized network discovery
          <Badge variant="outline" className="font-mono text-[10px]">
            {networks.filter((row) => row.enabled).length} active
          </Badge>
        </CardTitle>
        <CardDescription className="max-w-3xl">
          Nmap host discovery and light service detection on ranges you
          explicitly confirm. Only RFC1918 and CGNAT space is accepted, never
          larger than a /24; no scripts, exploitation, brute force or public
          targets.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {projects.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            Create a project before adding a network range.
          </p>
        ) : (
          <form
            onSubmit={submit}
            className="space-y-3"
            aria-label="Add an authorized network range"
          >
            <div className="flex flex-wrap items-end gap-2">
              <label className="space-y-1">
                <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                  Exact CIDR
                </span>
                <Input
                  value={cidr}
                  onChange={(event) => {
                    setCidr(event.target.value)
                    setConfirmation("")
                    setAuthorized(false)
                  }}
                  placeholder="192.168.1.0/24"
                  className="w-56 font-mono"
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

              <label className="space-y-1">
                <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                  Profile
                </span>
                <select
                  className={selectClassName}
                  value={scanProfile}
                  onChange={(event) => setScanProfile(event.target.value)}
                  disabled={!canManage || adding}
                >
                  <option value="services">Discovery + services</option>
                  <option value="discovery">Discovery only</option>
                </select>
              </label>
            </div>

            {scopeError ? (
              <p className="text-xs text-rose-600 dark:text-rose-400">
                {scopeError}
              </p>
            ) : null}

            {scope ? (
              <div className="space-y-2 rounded-md border border-border bg-muted/30 p-3">
                <p className="font-mono text-xs">
                  Target: {scope.cidr} · {scope.addressCount} addresses ·{" "}
                  {scope.usableHosts} usable hosts
                </p>
                <p className="font-mono text-[11px] text-muted-foreground">
                  {scope.firstAddress} – {scope.lastAddress}
                </p>
                <label className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={authorized}
                    onChange={(event) => setAuthorized(event.target.checked)}
                    disabled={!canManage || adding}
                    className="size-3.5"
                  />
                  I own this network or have explicit written authorization to
                  scan it.
                </label>
                <label className="block space-y-1">
                  <span className="block text-xs text-muted-foreground">
                    Type{" "}
                    <code className="font-mono text-foreground">
                      {scope.cidr}
                    </code>{" "}
                    exactly to confirm the scope.
                  </span>
                  <Input
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                    placeholder={scope.cidr}
                    className="w-56 font-mono"
                    autoComplete="off"
                    spellCheck={false}
                    disabled={!canManage || adding}
                  />
                </label>
              </div>
            ) : null}

            <Button
              type="submit"
              size="sm"
              disabled={!canSubmit}
              title={
                canManage
                  ? undefined
                  : "Only workspace admins can add network ranges"
              }
            >
              {adding ? <Spinner /> : <PlusIcon />}
              Add authorized range
            </Button>
          </form>
        )}

        {networks.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            No authorized ranges yet. Add a private CIDR you control to record
            the exact scope and queue a discovery scan.
          </p>
        ) : (
          <div className="overflow-hidden rounded-md border border-border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Range</TableHead>
                  <TableHead>Project</TableHead>
                  <TableHead>Profile</TableHead>
                  <TableHead>Inventory</TableHead>
                  <TableHead>Authorized</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {networks.map((row) => {
                  const pending = pendingId === row.assetId

                  return (
                    <TableRow key={row.assetId}>
                      <TableCell className="font-mono text-xs">
                        {row.cidr}
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {row.projectName}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {row.scanProfile}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {row.activeHostCount}/{row.hostCount} hosts ·{" "}
                        {row.activeServiceCount} services
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {row.confirmedAt
                          ? formatRelativeTime(row.confirmedAt)
                          : "missing"}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className="font-mono text-[10px]"
                        >
                          {row.enabled ? "enabled" : "disabled"}
                        </Badge>
                        {!row.scanReady ? (
                          <p className="mt-1 font-mono text-[10px] text-rose-600 dark:text-rose-400">
                            re-confirm scope
                          </p>
                        ) : null}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <ScanNowButton
                            assetId={row.assetId}
                            disabled={
                              !canManage || !row.enabled || !row.scanReady
                            }
                          />
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => toggle(row)}
                            disabled={!canManage || pending}
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

        <p className="text-xs leading-relaxed text-muted-foreground">
          The worker executes Nmap as an argv list with timeouts and bounded
          output. Discovery-only runs never resolve service findings; service
          disappearance is only resolved by a complete service-profile run.
        </p>
      </CardContent>
    </Card>
  )
}
