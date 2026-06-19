"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { toast } from "sonner"

import { addIncidentNoteAction } from "@/app/(app)/incidents/actions"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"

export function IncidentNoteForm({ incidentId }: { incidentId: string }) {
  const router = useRouter()
  const formRef = React.useRef<HTMLFormElement>(null)
  const [pending, setPending] = React.useState(false)

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)

    setPending(true)
    const result = await addIncidentNoteAction(undefined, formData)
    setPending(false)

    if (result?.status === "success") {
      toast.success(result.message ?? "Note added.")
      formRef.current?.reset()
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not add the note.")
  }

  return (
    <form ref={formRef} onSubmit={submit} className="space-y-3">
      <input type="hidden" name="incidentId" value={incidentId} />
      <Textarea
        name="note"
        rows={3}
        maxLength={1000}
        placeholder="Investigation note: what was checked, what was found, next step."
        aria-label="Investigation note"
      />
      <Button type="submit" size="sm" disabled={pending}>
        {pending ? <Spinner /> : null}
        Add note
      </Button>
    </form>
  )
}
