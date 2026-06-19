import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { ArrowLeftIcon } from "@phosphor-icons/react/dist/ssr"

import { IncidentStatusBadge } from "@/components/incidents/badges"
import { IncidentNoteForm } from "@/components/incidents/note-form"
import { IncidentStatusForm } from "@/components/incidents/status-form"
import { SeverityBadge } from "@/components/findings/badges"
import { PageHeader } from "@/components/page-header"
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { canManageWorkspace, requireWorkspace } from "@/lib/auth/session"
import {
  RULE_DESCRIPTIONS,
  type CorrelationRule,
} from "@/lib/intelligence/correlation"
import { formatDateTime, formatRelativeTime, titleCase } from "@/lib/format"
import { getIncident } from "@/lib/services/incidents"

export const metadata: Metadata = { title: "Incident" }

const eventLabels: Record<string, string> = {
  created: "Incident created",
  signal_changed: "Related findings changed",
  status_changed: "Status changed",
  note: "Investigation note",
  auto_resolved: "Auto-resolved",
}

export default async function IncidentDetailPage({
  params,
}: {
  params: Promise<{ incidentId: string }>
}) {
  const { incidentId } = await params
  const { workspace, role } = await requireWorkspace()

  const detail = await getIncident(workspace.id, incidentId)
  if (!detail) notFound()

  const { incident, projectName, findings, events } = detail
  const rule = incident.correlationRule as CorrelationRule
  const ruleDescription = RULE_DESCRIPTIONS[rule] ?? ""
  const canManage = canManageWorkspace(role)
  const closed = incident.status === "resolved" || incident.status === "closed"

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="mb-4 -ml-2"
        nativeButton={false}
        render={<Link href="/incidents" />}
      >
        <ArrowLeftIcon />
        All incidents
      </Button>

      <PageHeader
        title={incident.title}
        description={`${titleCase(incident.status)} · ${projectName} · rule ${incident.correlationRule}`}
        actions={<SeverityBadge severity={incident.severity} />}
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <IncidentStatusBadge status={incident.status} />
        <Badge variant="outline" className="font-mono text-[10px]">
          {incident.correlationRule}
        </Badge>
        <span className="font-mono text-[11px] text-muted-foreground">
          first detected {formatRelativeTime(incident.firstDetectedAt)} · last{" "}
          {formatRelativeTime(incident.lastDetectedAt)} · {detail.findingCount}{" "}
          related finding
          {detail.findingCount === 1 ? "" : "s"}
        </span>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Summary</CardTitle>
              <CardDescription>
                {ruleDescription ||
                  "Deterministic correlation over open findings and recent events."}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <p className="leading-relaxed text-muted-foreground">
                {incident.summary}
              </p>
              <div className="rounded-md border border-border bg-muted/30 p-3">
                <p className="mb-1 font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                  Why these signals are grouped
                </p>
                <p className="text-xs leading-relaxed">{incident.reason}</p>
              </div>
              <p className="text-xs text-muted-foreground">
                Correlation shows related activity. It does not prove an attack
                or that any account was compromised.
              </p>
              <details>
                <summary className="cursor-pointer font-mono text-[10px] tracking-wide text-muted-foreground uppercase hover:text-foreground">
                  Evidence
                </summary>
                <pre className="mt-2 max-h-64 overflow-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-[11px] leading-relaxed">
                  {JSON.stringify(incident.evidence, null, 2)}
                </pre>
              </details>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Related findings</CardTitle>
              <CardDescription>
                Each row keeps the reason it was associated with this incident.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {findings.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No open findings are currently linked. The incident reason and
                  timeline are preserved.
                </p>
              ) : (
                <div className="overflow-hidden rounded-md border border-border">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-24">Severity</TableHead>
                        <TableHead>Finding</TableHead>
                        <TableHead>Asset</TableHead>
                        <TableHead>Why linked</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findings.map(({ link, finding, assetName }) => (
                        <TableRow key={link.id}>
                          <TableCell>
                            <SeverityBadge severity={finding.severity} />
                          </TableCell>
                          <TableCell className="max-w-72">
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
                          <TableCell className="max-w-40 truncate font-mono text-xs text-muted-foreground">
                            {assetName}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {link.reason}
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

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Status</CardTitle>
              <CardDescription>
                {canManage
                  ? "Status changes are audited and never delete the incident."
                  : "Only workspace admins can change incident status."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {canManage ? (
                <IncidentStatusForm
                  incidentId={incident.id}
                  currentStatus={incident.status}
                />
              ) : (
                <IncidentStatusBadge status={incident.status} />
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Add investigation note</CardTitle>
            </CardHeader>
            <CardContent>
              <IncidentNoteForm incidentId={incident.id} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Context</CardTitle>
            </CardHeader>
            <CardContent className="gap-2.5 text-sm">
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Project</span>
                <Link
                  href={`/projects/${incident.projectId}`}
                  className="max-w-40 truncate text-xs underline-offset-4 hover:underline"
                >
                  {projectName}
                </Link>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Correlation key</span>
                <span className="max-w-40 truncate font-mono text-[10px] text-muted-foreground">
                  {incident.correlationKey}
                </span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">First detected</span>
                <span className="font-mono text-xs">
                  {formatDateTime(incident.firstDetectedAt)}
                </span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Last detected</span>
                <span className="font-mono text-xs">
                  {formatDateTime(incident.lastDetectedAt)}
                </span>
              </div>
              {incident.resolvedAt ? (
                <div className="flex justify-between gap-3">
                  <span className="text-muted-foreground">Resolved</span>
                  <span className="font-mono text-xs">
                    {formatDateTime(incident.resolvedAt)}
                  </span>
                </div>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Timeline</CardTitle>
              <CardDescription>
                {closed
                  ? "Closed incidents keep their full history."
                  : "System events and investigation notes, newest first."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {events.length === 0 ? (
                <p className="text-xs text-muted-foreground">No events yet.</p>
              ) : (
                <ul className="space-y-3">
                  {events.map(({ event, actorName }) => (
                    <li key={event.id} className="text-xs">
                      <p className="font-mono">
                        {event.fromStatus
                          ? `${event.fromStatus} → ${event.toStatus}`
                          : (eventLabels[event.type] ?? event.type)}
                      </p>
                      {event.note ? (
                        <p className="mt-0.5 leading-relaxed text-muted-foreground">
                          {event.note}
                        </p>
                      ) : null}
                      <p className="mt-0.5 font-mono text-[10px] text-muted-foreground">
                        {formatRelativeTime(event.createdAt)} ·{" "}
                        {actorName ?? "system"}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}
