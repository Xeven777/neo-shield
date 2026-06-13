"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { ArrowClockwiseIcon, CopyIcon, PlusIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  createWorkerAction,
  revokeWorkerAction,
} from "@/app/(app)/settings/actions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
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
import { formatDateTime } from "@/lib/format"

export type WorkerRow = {
  id: string
  name: string
  tokenPrefix: string
  status: "active" | "revoked"
  version: string | null
  hostname: string | null
  lastSeenAt: Date | null
  scopes: string[]
  isOnline: boolean
}

export function WorkerManager({
  workers,
  canManage,
}: {
  workers: WorkerRow[]
  canManage: boolean
}) {
  const router = useRouter()
  const [open, setOpen] = React.useState(false)
  const [creating, setCreating] = React.useState(false)
  const [createError, setCreateError] = React.useState<string | null>(null)
  const [issued, setIssued] = React.useState<{
    token: string
    name: string
  } | null>(null)
  const [revoking, setRevoking] = React.useState<string | null>(null)
  const [refreshing, setRefreshing] = React.useState(false)

  async function createToken(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)

    setCreating(true)
    setCreateError(null)
    const result = await createWorkerAction(undefined, formData)
    setCreating(false)

    if (result?.status === "success" && result.token) {
      setIssued({ token: result.token, name: result.workerName ?? "worker" })
      setOpen(false)
      toast.success("Worker token issued. Copy it now — it is shown once.")
      return
    }

    const errorMessage = result?.message ?? "Could not create the worker token."
    setCreateError(errorMessage)
    toast.error(errorMessage)
  }

  async function revoke(workerId: string) {
    setRevoking(workerId)
    const result = await revokeWorkerAction(workerId)
    setRevoking(null)

    if (result?.status === "success") {
      toast.success("Worker revoked.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not revoke the worker.")
  }

  function copyToken() {
    if (!issued) return
    navigator.clipboard
      .writeText(issued.token)
      .then(() => toast.success("Token copied."))
      .catch(() => toast.error("Could not copy. Select the token manually."))
  }

  function refresh() {
    setRefreshing(true)
    router.refresh()
    setTimeout(() => setRefreshing(false), 600)
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm text-muted-foreground">
          Tokens authenticate the Python worker against the heartbeat and job
          APIs. Only a SHA-256 hash is stored.
        </p>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={refresh}
            disabled={refreshing}
          >
            <ArrowClockwiseIcon
              className={refreshing ? "animate-spin" : undefined}
            />
            Refresh
          </Button>
          <Button size="sm" disabled={!canManage} onClick={() => setOpen(true)}>
            <PlusIcon />
            New worker
          </Button>
        </div>
      </div>

      {issued ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-4">
          <div className="flex items-center justify-between gap-2">
            <p className="text-sm font-medium">
              Token for {issued.name} — shown once
            </p>
            <Button variant="outline" size="xs" onClick={() => setIssued(null)}>
              Dismiss
            </Button>
          </div>
          <pre className="mt-3 overflow-x-auto rounded-md border border-border bg-background p-3 font-mono text-xs">
            {issued.token}
          </pre>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Button variant="outline" size="sm" onClick={copyToken}>
              <CopyIcon />
              Copy token
            </Button>
            <span className="text-xs text-muted-foreground">
              Store it as NEOSHIELD_WORKER_TOKEN in the Python service.
            </span>
          </div>
        </div>
      ) : null}

      {workers.length === 0 ? (
        <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
          No worker tokens yet. Create one, then run the Python service with
          this token to see it come online.
        </p>
      ) : (
        <div className="rounded-lg border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Worker</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {workers.map((worker) => (
                <TableRow key={worker.id}>
                  <TableCell>
                    <p className="font-medium">{worker.name}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {worker.tokenPrefix}… ·{" "}
                      {worker.scopes.join(", ") || "no scopes"}
                    </p>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`font-mono text-[10px] ${
                        worker.status === "revoked"
                          ? "text-muted-foreground"
                          : worker.isOnline
                            ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                            : "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
                      }`}
                    >
                      {worker.status === "revoked"
                        ? "revoked"
                        : worker.isOnline
                          ? "online"
                          : "offline"}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-muted-foreground">
                    {worker.hostname ?? "—"}
                    <span className="block text-[10px]">
                      {worker.version ?? ""}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {worker.lastSeenAt
                      ? formatDateTime(worker.lastSeenAt)
                      : "never"}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      variant="destructive"
                      size="xs"
                      disabled={
                        !canManage ||
                        worker.status === "revoked" ||
                        revoking === worker.id
                      }
                      onClick={() => revoke(worker.id)}
                    >
                      {revoking === worker.id ? <Spinner /> : null}
                      Revoke
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create a worker token</DialogTitle>
            <DialogDescription>
              The token is displayed once. The workspace is bound server-side
              and the token can be revoked at any time.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={createToken} noValidate>
            <FieldGroup>
              <Field data-invalid={Boolean(createError)}>
                <FieldLabel htmlFor="worker-name">Worker name</FieldLabel>
                <Input
                  id="worker-name"
                  name="name"
                  defaultValue="scan-worker-1"
                  placeholder="scan-worker-1"
                  autoFocus
                  required
                  aria-invalid={Boolean(createError)}
                />
                <FieldDescription>
                  A label for this host, for example “lab-worker” or
                  “prod-vm-worker”.
                </FieldDescription>
                <FieldError>{createError}</FieldError>
              </Field>
            </FieldGroup>
            <DialogFooter className="mt-6">
              <Button
                type="button"
                variant="outline"
                onClick={() => setOpen(false)}
                disabled={creating}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={creating}>
                {creating ? <Spinner /> : null}
                Issue token
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
