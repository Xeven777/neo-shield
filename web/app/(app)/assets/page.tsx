import type { Metadata } from "next"
import Link from "next/link"
import { StackIcon } from "@phosphor-icons/react/dist/ssr"

import { PageHeader } from "@/components/page-header"
import { Badge } from "@/components/ui/badge"
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
import { requireWorkspace } from "@/lib/auth/session"
import { formatRelativeTime, titleCase } from "@/lib/format"
import { listWorkspaceAssets } from "@/lib/services/assets"

export const metadata: Metadata = { title: "Assets" }

export default async function AssetsPage() {
  const { workspace } = await requireWorkspace()
  const rows = await listWorkspaceAssets(workspace.id)

  return (
    <>
      <PageHeader
        title="Assets"
        description="Every asset belongs to a project and keeps its own scan state. Assets are never deleted with their history."
      />

      {rows.length === 0 ? (
        <Empty className="border border-border bg-card/40">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <StackIcon />
            </EmptyMedia>
            <EmptyTitle>No assets connected</EmptyTitle>
            <EmptyDescription>
              Phase 1 adds GitHub repositories and domains. Phase 2 adds Wazuh
              endpoints and authorized network ranges.
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      ) : (
        <div className="rounded-lg border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Asset</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Project</TableHead>
                <TableHead>Enabled</TableHead>
                <TableHead>Added</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map(({ asset, projectName, projectId }) => (
                <TableRow key={asset.id}>
                  <TableCell>
                    <p className="font-medium">{asset.displayName}</p>
                    <p className="max-w-72 truncate font-mono text-xs text-muted-foreground">
                      {asset.identifier}
                    </p>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {titleCase(asset.type)}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Link
                      href={`/projects/${projectId}`}
                      className="text-sm underline-offset-4 hover:underline"
                    >
                      {projectName}
                    </Link>
                  </TableCell>
                  <TableCell className="text-sm">
                    {asset.enabled ? "Yes" : "No"}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {formatRelativeTime(asset.createdAt)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </>
  )
}
