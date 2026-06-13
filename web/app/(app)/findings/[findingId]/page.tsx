import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import {
  ArrowLeftIcon,
  ArrowSquareOutIcon,
  FileTextIcon,
  PackageIcon,
} from "@phosphor-icons/react/dist/ssr"

import {
  FindingStatusBadge,
  SeverityBadge,
} from "@/components/findings/badges"
import { FindingStatusForm } from "@/components/findings/status-form"
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
import { requireWorkspace } from "@/lib/auth/session"
import { formatDateTime, formatRelativeTime, titleCase } from "@/lib/format"
import { getFinding } from "@/lib/services/findings"

export const metadata: Metadata = { title: "Finding" }

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ findingId: string }>
}) {
  const { findingId } = await params
  const { workspace } = await requireWorkspace()

  const detail = await getFinding(workspace.id, findingId)
  if (!detail) notFound()

  const { finding, assetName, projectName, projectId, evidence, events } = detail

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="-ml-2 mb-4"
        render={<Link href="/findings" />}
      >
        <ArrowLeftIcon />
        All findings
      </Button>

      <PageHeader
        title={finding.title}
        description={`${titleCase(finding.category)} · ${finding.sourceTool}${
          finding.sourceRuleId ? ` · ${finding.sourceRuleId}` : ""
        }`}
        actions={<SeverityBadge severity={finding.severity} />}
      />

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <FindingStatusBadge status={finding.status} />
        <Badge variant="outline" className="font-mono text-[10px]">
          {finding.source}
        </Badge>
        {finding.cveId ? (
          <Badge variant="outline" className="font-mono text-[10px]">
            {finding.cveId}
          </Badge>
        ) : null}
        {finding.cvssScore !== null ? (
          <Badge variant="outline" className="font-mono text-[10px]">
            CVSS {finding.cvssScore.toFixed(1)}
          </Badge>
        ) : null}
        {finding.confidence ? (
          <Badge variant="secondary" className="font-mono text-[10px]">
            {finding.confidence} confidence
          </Badge>
        ) : null}
        <span className="font-mono text-[11px] text-muted-foreground">
          seen {finding.occurrenceCount}× · last {formatRelativeTime(finding.lastSeenAt)}
        </span>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
                {finding.description}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Evidence</CardTitle>
              <CardDescription>
                Redacted at ingestion. Secret values are never stored — only a
                locator, rule and masked context.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              {!evidence ? (
                <p className="text-muted-foreground">
                  No structured evidence was captured for this finding.
                </p>
              ) : (
                <>
                  {evidence.filePath ? (
                    <div className="flex items-start gap-2">
                      <FileTextIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                      <span className="font-mono text-xs break-all">
                        {evidence.filePath}
                      </span>
                    </div>
                  ) : null}
                  {evidence.packageName ? (
                    <div className="flex items-start gap-2">
                      <PackageIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                      <span className="font-mono text-xs">
                        {evidence.packageName}
                        {evidence.packageVersion
                          ? `@${evidence.packageVersion}`
                          : ""}
                        {evidence.fixedVersion
                          ? ` → fixed in ${evidence.fixedVersion}`
                          : ""}
                      </span>
                    </div>
                  ) : null}
                  {Object.keys(evidence.evidence).length > 0 ? (
                    <pre className="max-h-72 overflow-auto rounded-md border border-border bg-muted/30 p-3 font-mono text-[11px] leading-relaxed">
                      {JSON.stringify(evidence.evidence, null, 2)}
                    </pre>
                  ) : null}
                </>
              )}
            </CardContent>
          </Card>

          {finding.remediation ? (
            <Card>
              <CardHeader>
                <CardTitle>Remediation</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm leading-relaxed whitespace-pre-wrap text-muted-foreground">
                  {finding.remediation}
                </p>
              </CardContent>
            </Card>
          ) : null}

          {finding.references.length > 0 ? (
            <Card>
              <CardHeader>
                <CardTitle>References</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5">
                {finding.references.map((reference) => (
                  <a
                    key={reference}
                    href={reference}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="flex items-center gap-1.5 text-xs break-all text-muted-foreground underline-offset-4 hover:text-foreground hover:underline"
                  >
                    <ArrowSquareOutIcon className="size-3.5 shrink-0" />
                    {reference}
                  </a>
                ))}
              </CardContent>
            </Card>
          ) : null}
        </div>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Context</CardTitle>
            </CardHeader>
            <CardContent className="gap-2.5 text-sm">
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Asset</span>
                <span className="max-w-40 truncate font-mono text-xs">
                  {assetName}
                </span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Project</span>
                <Link
                  href={`/projects/${projectId}`}
                  className="max-w-40 truncate text-xs underline-offset-4 hover:underline"
                >
                  {projectName}
                </Link>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">First seen</span>
                <span className="font-mono text-xs">
                  {formatDateTime(finding.firstSeenAt)}
                </span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Last seen</span>
                <span className="font-mono text-xs">
                  {formatDateTime(finding.lastSeenAt)}
                </span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-muted-foreground">Occurrences</span>
                <span className="font-mono text-xs">
                  {finding.occurrenceCount}
                </span>
              </div>
              <div className="flex flex-col gap-1">
                <span className="text-muted-foreground">Stable key</span>
                <span className="font-mono text-[10px] break-all text-muted-foreground">
                  {finding.stableKey}
                </span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Change status</CardTitle>
              <CardDescription>
                Status changes are audited and never delete the finding.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <FindingStatusForm
                findingId={finding.id}
                currentStatus={finding.status}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Status history</CardTitle>
            </CardHeader>
            <CardContent>
              {events.length === 0 ? (
                <p className="text-xs text-muted-foreground">
                  No manual status changes yet.
                </p>
              ) : (
                <ul className="space-y-3">
                  {events.map((event) => (
                    <li key={event.id} className="text-xs">
                      <p className="font-mono">
                        {event.fromStatus ? `${event.fromStatus} → ` : ""}
                        {event.toStatus}
                      </p>
                      <p className="text-muted-foreground">
                        {formatRelativeTime(event.createdAt)}
                        {event.note ? ` · ${event.note}` : ""}
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
