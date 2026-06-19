"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { toast } from "sonner"

import { updateIncidentStatusAction } from "@/app/(app)/incidents/actions"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import type { IncidentStatus } from "@/lib/db/schema"
import { incidentStatuses } from "@/lib/validation/schemas"
import { titleCase } from "@/lib/format"

const selectClassName =
  "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

export function IncidentStatusForm({
  incidentId,
  currentStatus,
}: {
  incidentId: string
  currentStatus: IncidentStatus
}) {
  const router = useRouter()
  const [pending, setPending] = React.useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)

    setPending(true)
    const result = await updateIncidentStatusAction(undefined, formData)
    setPending(false)

    if (result?.status === "success") {
      toast.success(result.message ?? "Incident updated.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not update the incident.")
  }

  return (
    <form onSubmit={submit} className="space-y-3">
      <input type="hidden" name="incidentId" value={incidentId} />
      <label className="block space-y-1.5">
        <span className="text-xs font-medium text-muted-foreground">
          Status
        </span>
        <select
          name="status"
          defaultValue={currentStatus}
          className={selectClassName}
        >
          {incidentStatuses.map((status) => (
            <option key={status} value={status}>
              {titleCase(status)}
            </option>
          ))}
        </select>
      </label>
      <label className="block space-y-1.5">
        <span className="text-xs font-medium text-muted-foreground">
          Note (optional)
        </span>
        <Textarea
          name="note"
          rows={2}
          maxLength={1000}
          placeholder="Why is the status changing?"
        />
      </label>
      <Button type="submit" size="sm" disabled={pending}>
        {pending ? <Spinner /> : null}
        Update status
      </Button>
    </form>
  )
}
