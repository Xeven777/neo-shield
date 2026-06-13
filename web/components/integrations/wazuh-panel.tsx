"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { DesktopIcon, PowerIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  connectWazuhAction,
  disconnectWazuhAction,
} from "@/app/(app)/integrations/actions"
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
import { formatRelativeTime } from "@/lib/format"

const selectClassName =
  "h-8 w-full min-w-40 rounded-md border border-input bg-transparent px-2 text-xs shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 disabled:opacity-50"

export type WazuhPanelOverview = {
  status: "pending" | "connected" | "disconnected" | "error" | null
  minLevel: number | null
  projectId: string | null
  lastSyncedAt: Date | null
  syncCursor: Date | null
  lastError: string | null
  endpointCount: number
  events24h: number
  events7d: number
  openFindings: number
  lastEventAt: Date | null
}

const statusStyles: Record<string, string> = {
  connected:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  pending:
    "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  error: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  disconnected: "",
}

export function WazuhPanel({
  overview,
  projects,
  canManage,
}: {
  overview: WazuhPanelOverview
  projects: Array<{ id: string; name: string }>
  canManage: boolean
}) {
  const router = useRouter()
  const [projectId, setProjectId] = React.useState(
    overview.projectId ?? projects[0]?.id ?? ""
  )
  const [minLevel, setMinLevel] = React.useState(
    String(overview.minLevel ?? 5)
  )
  const [pending, setPending] = React.useState<"connect" | "disconnect" | null>(
    null
  )

  const active =
    overview.status === "connected" ||
    overview.status === "pending" ||
    overview.status === "error"

  async function connect(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()

    if (!projectId) {
      toast.error("Create a project before enabling Wazuh ingestion.")
      return
    }

    const formData = new FormData()
    formData.set("projectId", projectId)
    formData.set("minLevel", minLevel)

    setPending("connect")
    const result = await connectWazuhAction(undefined, formData)
    setPending(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Wazuh ingestion enabled.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not enable Wazuh ingestion.")
  }

  async function disconnect() {
    setPending("disconnect")
    const result = await disconnectWazuhAction()
    setPending(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Wazuh ingestion disabled.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not disable Wazuh ingestion.")
  }

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <DesktopIcon className="size-5 text-muted-foreground" />
          Endpoint monitoring (Wazuh)
          <Badge
            variant="outline"
            className={`font-mono text-[10px] ${
              statusStyles[overview.status ?? ""] ?? ""
            }`}
          >
            {overview.status ?? "not connected"}
          </Badge>
        </CardTitle>
        <CardDescription className="max-w-3xl">
          The worker pulls alerts from the Wazuh indexer, stores redacted events
          and normalized findings, and maps agents to endpoint assets. Indexer
          and manager credentials stay in the worker environment; the UI only
          binds a project and a minimum rule level.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-4">
          {[
            { label: "Endpoints", value: overview.endpointCount },
            { label: "Events 24h", value: overview.events24h },
            { label: "Events 7d", value: overview.events7d },
            { label: "Open findings", value: overview.openFindings },
          ].map((stat) => (
            <div
              key={stat.label}
              className="rounded-md border border-border px-3 py-2"
            >
              <p className="font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                {stat.label}
              </p>
              <p className="font-mono text-xl">{stat.value}</p>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-[11px] text-muted-foreground">
          <span>last event: {formatRelativeTime(overview.lastEventAt)}</span>
          <span>last sync: {formatRelativeTime(overview.lastSyncedAt)}</span>
          <span>
            cursor: {overview.syncCursor ? formatRelativeTime(overview.syncCursor) : "—"}
          </span>
        </div>

        {overview.lastError ? (
          <p className="rounded-md border border-rose-500/30 bg-rose-500/10 px-3 py-2 font-mono text-xs text-rose-700 dark:text-rose-300">
            {overview.lastError}
          </p>
        ) : null}

        {projects.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            Create a project before enabling Wazuh ingestion.
          </p>
        ) : (
          <form
            onSubmit={connect}
            className="flex flex-wrap items-end gap-2"
            aria-label="Enable Wazuh ingestion"
          >
            <label className="space-y-1">
              <span className="block font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Project
              </span>
              <select
                className={selectClassName}
                value={projectId}
                onChange={(event) => setProjectId(event.target.value)}
                disabled={!canManage || pending !== null}
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
                Minimum rule level
              </span>
              <Input
                type="number"
                min={0}
                max={16}
                value={minLevel}
                onChange={(event) => setMinLevel(event.target.value)}
                className="w-28"
                disabled={!canManage || pending !== null}
              />
            </label>

            <Button
              type="submit"
              size="sm"
              disabled={!canManage || pending !== null}
              title={
                canManage
                  ? undefined
                  : "Only workspace admins can configure endpoint monitoring"
              }
            >
              {pending === "connect" ? <Spinner /> : <DesktopIcon />}
              {active ? "Update ingestion" : "Enable ingestion"}
            </Button>

            {active ? (
              <Button
                type="button"
                size="sm"
                variant="ghost"
                onClick={disconnect}
                disabled={!canManage || pending !== null}
              >
                {pending === "disconnect" ? <Spinner /> : <PowerIcon />}
                Disable
              </Button>
            ) : null}
          </form>
        )}

        <p className="text-xs leading-relaxed text-muted-foreground">
          Requires{" "}
          <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px]">
            NEOSHIELD_WAZUH_ENABLED
          </code>{" "}
          plus indexer credentials (and optionally the manager API for agent
          inventory) in the Python worker environment. The worker polls
          continuously while ingestion is enabled; disabling keeps historical
          events and findings.
        </p>
      </CardContent>
    </Card>
  )
}
