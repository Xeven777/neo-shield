import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import {
  ArrowLeftIcon,
  DesktopIcon,
  NetworkIcon,
  PulseIcon,
  ShieldWarningIcon,
} from "@phosphor-icons/react/dist/ssr"

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
import { canManageWorkspace, requireWorkspace } from "@/lib/auth/session"
import {
  formatDateTime,
  formatRelativeTime,
  pluralize,
  titleCase,
} from "@/lib/format"
import { getAssetDetail } from "@/lib/services/endpoints"
import { networkConfigIsScanReady } from "@/lib/services/network"

export const metadata: Metadata = { title: "Asset" }

const severityStyles: Record<string, string> = {
  critical:
    "border-rose-500/40 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300",
  medium:
    "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  informational: "",
}

const statusStyles: Record<string, string> = {
  completed:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  partial:
    "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  failed: "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  running:
    "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  active:
    "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  disconnected:
    "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
  missing: "border-muted-foreground/30 bg-muted/40 text-muted-foreground",
}

const SCANNABLE_TYPES = ["repository", "domain", "endpoint", "network"]

function snapshotNumber(snapshot: Record<string, unknown>, key: string) {
  const value = snapshot[key]
  return typeof value === "number" ? value : null
}

function text(value: unknown) {
  return typeof value === "string" && value ? value : null
}

export default async function AssetDetailPage({
  params,
}: {
  params: Promise<{ assetId: string }>
}) {
  const { assetId } = await params
  const { workspace, role } = await requireWorkspace()

  const detail = await getAssetDetail(workspace.id, assetId)
  if (!detail) notFound()

  const {
    asset,
    projectId,
    projectName,
    findings,
    runs,
    openFindingCount,
    agent,
    events,
    hosts,
    latestRun,
    previousRun,
  } = detail

  const canScan = canManageWorkspace(role)
  const scannable = SCANNABLE_TYPES.includes(asset.type)
  const isEndpoint = asset.type === "endpoint"
  const isNetwork = asset.type === "network"

  const config = asset.config as {
    cidr?: unknown
    scanProfile?: unknown
    authorization?: {
      confirmedAt?: unknown
      statement?: unknown
      scope?: unknown
    }
  }

  const activeHosts = hosts.filter((host) => host.status === "active")
  const activeServices = hosts.reduce(
    (total, host) =>
      total + host.services.filter((service) => service.status === "active").length,
    0
  )
  const latestHosts = latestRun
    ? snapshotNumber(latestRun.targetSnapshot, "hostsFound")
    : null
  const previousHosts = previousRun
    ? snapshotNumber(previousRun.targetSnapshot, "hostsFound")
    : null
  const hostDelta =
    latestHosts !== null && previousHosts !== null
      ? latestHosts - previousHosts
      : null

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="mb-4 -ml-2"
        nativeButton={false}
        render={<Link href="/assets" />}
      >
        <ArrowLeftIcon />
        All assets
      </Button>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="font-heading text-2xl font-semibold tracking-tight">
              {asset.displayName}
            </h1>
            <Badge variant="secondary" className="font-mono text-[10px]">
              {titleCase(asset.type)}
            </Badge>
            <Badge variant="outline" className="font-mono text-[10px]">
              {asset.enabled ? "enabled" : "disabled"}
            </Badge>
          </div>
          <p className="mt-1 max-w-2xl truncate font-mono text-xs text-muted-foreground">
            {asset.identifier}
          </p>
          <p className="mt-2 text-sm text-muted-foreground">
            Project{" "}
            <Link
              href={`/projects/${projectId}`}
              className="text-foreground underline-offset-4 hover:underline"
            >
              {projectName}
            </Link>
            {" · "}added {formatRelativeTime(asset.createdAt)}
          </p>
        </div>
        {scannable ? (
          <ScanNowButton
            assetId={asset.id}
            disabled={!canScan || !asset.enabled}
          />
        ) : null}
      </div>

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[
          {
            label: "Open findings",
            value: openFindingCount,
            detail: pluralize(findings.length, "finding") + " in total",
          },
          {
            label: "Scan runs",
            value: runs.length,
            detail:
              runs.length === 0 ? "never scanned" : `latest ${formatRelativeTime(runs[0].startedAt)}`,
          },
          {
            label: "Events",
            value: events.length,
            detail: isEndpoint ? "endpoint alert history" : "endpoint sources only",
          },
          {
            label: isNetwork ? "Active hosts" : "Latest run",
            value: isNetwork ? activeHosts.length : (latestRun?.status ?? "—"),
            detail: isNetwork
              ? `${activeServices} active services`
              : latestRun
                ? formatRelativeTime(latestRun.startedAt)
                : "not scanned",
          },
        ].map((stat) => (
          <Card key={stat.label} size="sm">
            <CardHeader>
              <CardDescription>{stat.label}</CardDescription>
              <CardTitle className="font-mono text-2xl capitalize">
                {stat.value}
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground">{stat.detail}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {isEndpoint ? (
        <Card className="mt-3">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <DesktopIcon className="size-5 text-muted-foreground" />
              Wazuh agent
            </CardTitle>
            <CardDescription>
              Inventory comes from the manager API when configured. Event
              history is normalized from indexer alerts.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {agent ? (
              <div className="grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
                {[
                  ["Status", agent.status],
                  ["Agent ID", agent.externalId],
                  ["Name", agent.name],
                  ["IP address", agent.ipAddress ?? "—"],
                  ["OS", [agent.osName, agent.osVersion].filter(Boolean).join(" ") || "—"],
                  ["Platform", agent.osPlatform ?? "—"],
                  ["Agent version", agent.agentVersion ?? "—"],
                  ["Last seen", agent.lastSeenAt ? formatDateTime(agent.lastSeenAt) : "—"],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0">
                    <p className="font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                      {label}
                    </p>
                    <p className="truncate font-mono text-xs">{value}</p>
                  </div>
                ))}
              </div>
            ) : (
              <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
                No agent inventory yet. Run an endpoint sync from the project
                page; the worker writes the agent record when it polls the
                manager or sees an alert.
              </p>
            )}
          </CardContent>
        </Card>
      ) : null}

      {isNetwork ? (
        <>
          <Card className="mt-3">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <NetworkIcon className="size-5 text-muted-foreground" />
                Authorized scope
              </CardTitle>
              <CardDescription>
                The recorded scope is re-validated by the worker before every
                Nmap run.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
                {[
                  ["CIDR", text(config.cidr) ?? "—"],
                  ["Profile", text(config.scanProfile) ?? "—"],
                  [
                    "Confirmed",
                    text(config.authorization?.confirmedAt)
                      ? formatDateTime(text(config.authorization?.confirmedAt) as string)
                      : "missing",
                  ],
                  [
                    "Scan ready",
                    networkConfigIsScanReady(asset.config) ? "yes" : "no",
                  ],
                  ["Scope", text(config.authorization?.scope) ?? "—"],
                  [
                    "Hosts now",
                    latestHosts !== null ? String(latestHosts) : "—",
                  ],
                  [
                    "Previous run",
                    previousHosts !== null ? String(previousHosts) : "—",
                  ],
                  [
                    "Delta",
                    hostDelta === null
                      ? "—"
                      : hostDelta > 0
                        ? `+${hostDelta}`
                        : String(hostDelta),
                  ],
                ].map(([label, value]) => (
                  <div key={label} className="min-w-0">
                    <p className="font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                      {label}
                    </p>
                    <p className="truncate font-mono text-xs">{value}</p>
                  </div>
                ))}
              </div>
              {text(config.authorization?.statement) ? (
                <p className="rounded-md border border-border bg-muted/30 p-3 text-xs text-muted-foreground">
                  {text(config.authorization?.statement)}
                </p>
              ) : null}
            </CardContent>
          </Card>

          <Card className="mt-3">
            <CardHeader>
              <CardTitle>Discovered hosts</CardTitle>
              <CardDescription>
                {pluralize(hosts.length, "host")} recorded; {activeHosts.length}{" "}
                currently active. Missing services are resolved only by a
                complete service-profile run.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {hosts.length === 0 ? (
                <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
                  No hosts discovered yet. Queue a scan for this range.
                </p>
              ) : (
                <div className="overflow-hidden rounded-md border border-border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Address</TableHead>
                        <TableHead>Host</TableHead>
                        <TableHead>MAC / vendor</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Services</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {hosts.map((host) => (
                        <TableRow key={host.id}>
                          <TableCell className="font-mono text-xs">
                            {host.address}
                          </TableCell>
                          <TableCell className="text-sm">
                            {host.hostname ?? "—"}
                          </TableCell>
                          <TableCell className="font-mono text-[11px] text-muted-foreground">
                            {[host.macAddress, host.vendor]
                              .filter(Boolean)
                              .join(" · ") || "—"}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={`font-mono text-[10px] ${statusStyles[host.status] ?? ""}`}
                            >
                              {host.status}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            {host.services.length === 0 ? (
                              <span className="text-xs text-muted-foreground">
                                —
                              </span>
                            ) : (
                              <div className="flex max-w-xl flex-wrap gap-1">
                                {host.services.map((service) => (
                                  <Badge
                                    key={service.id}
                                    variant="secondary"
                                    className={`font-mono text-[10px] ${
                                      service.status === "missing"
                                        ? "opacity-60 line-through"
                                        : ""
                                    }`}
                                    title={
                                      [
                                        service.product,
                                        service.version,
                                        service.extraInfo,
                                      ]
                                        .filter(Boolean)
                                        .join(" ") || service.serviceName || ""
                                    }
                                  >
                                    {service.port}/{service.protocol}
                                    {service.serviceName
                                      ? ` ${service.serviceName}`
                                      : ""}
                                  </Badge>
                                ))}
                              </div>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </CardContent>
          </Card>
        </>
      ) : null}

      <div className="mt-3 grid gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldWarningIcon className="size-5 text-muted-foreground" />
              Findings
            </CardTitle>
            <CardDescription>
              Normalized findings for this asset. No findings is not the same as
              clean unless a scan completed.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {findings.length === 0 ? (
              <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
                {runs.length === 0
                  ? "No scan has completed for this asset yet."
                  : "No findings recorded for this asset."}
              </p>
            ) : (
              <div className="overflow-hidden rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Finding</TableHead>
                      <TableHead>Severity</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Last seen</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.map(({ finding }) => (
                      <TableRow key={finding.id}>
                        <TableCell>
                          <Link
                            href={`/findings/${finding.id}`}
                            className="line-clamp-2 max-w-64 text-sm underline-offset-4 hover:underline"
                          >
                            {finding.title}
                          </Link>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`font-mono text-[10px] ${severityStyles[finding.severity] ?? ""}`}
                          >
                            {finding.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {finding.status}
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {formatRelativeTime(finding.lastSeenAt)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <PulseIcon className="size-5 text-muted-foreground" />
              Scan runs
            </CardTitle>
            <CardDescription>
              One row per worker execution with tools and bounded provenance.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {runs.length === 0 ? (
              <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
                No scan runs yet.
              </p>
            ) : (
              <div className="overflow-hidden rounded-md border border-border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Started</TableHead>
                      <TableHead>Scanner</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Findings</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {runs.map((run) => (
                      <TableRow key={run.id}>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {formatRelativeTime(run.startedAt)}
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {run.scanner}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={`font-mono text-[10px] ${statusStyles[run.status] ?? ""}`}
                          >
                            {run.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs">
                          {run.findingCount}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {isEndpoint ? (
        <Card className="mt-3">
          <CardHeader>
            <CardTitle>Recent events</CardTitle>
            <CardDescription>
              Newest 25 normalized alerts for this endpoint. Evidence is
              redacted; raw logs are never stored.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {events.length === 0 ? (
              <Empty className="border border-dashed border-border">
                <EmptyHeader>
                  <EmptyMedia variant="icon">
                    <PulseIcon />
                  </EmptyMedia>
                  <EmptyTitle>No events yet</EmptyTitle>
                  <EmptyDescription>
                    Run an endpoint sync after the agent produces alerts above
                    the configured minimum rule level.
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
                      <TableHead>Rule</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.map((event) => (
                      <TableRow key={event.id}>
                        <TableCell className="font-mono text-[11px] whitespace-nowrap text-muted-foreground">
                          {formatDateTime(event.eventTime)}
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
                        <TableCell className="max-w-96">
                          <p className="truncate text-sm">{event.title}</p>
                          <p className="truncate font-mono text-[10px] text-muted-foreground">
                            {event.description}
                          </p>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">
                          {event.ruleId ?? "—"}
                          {event.ruleLevel !== null
                            ? ` · level ${event.ruleLevel}`
                            : ""}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
    </>
  )
}
