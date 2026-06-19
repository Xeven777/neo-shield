"use server"

import { revalidatePath } from "next/cache"

import { AuthorizationError, requireWorkspace } from "@/lib/auth/session"
import { addIncidentNote, updateIncidentStatus } from "@/lib/services/incidents"
import {
  incidentNoteSchema,
  incidentStatusUpdateSchema,
} from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

export async function updateIncidentStatusAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()
  const incidentId = String(formData.get("incidentId") ?? "")

  if (!incidentId) {
    return { status: "error", message: "Missing incident id." }
  }

  const parsed = incidentStatusUpdateSchema.safeParse({
    status: formData.get("status"),
    note: formData.get("note") || undefined,
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Choose a valid incident status.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    const updated = await updateIncidentStatus({
      workspaceId: workspace.id,
      incidentId,
      actorUserId: session.user.id,
      actorRole: role,
      status: parsed.data.status,
      note: parsed.data.note,
    })

    if (!updated) {
      return { status: "error", message: "Incident not found." }
    }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[incidents] status update failed", error)
    return { status: "error", message: "Could not update the incident." }
  }

  revalidatePath("/incidents")
  revalidatePath(`/incidents/${incidentId}`)
  revalidatePath("/dashboard")
  return { status: "success", message: "Incident status updated." }
}

export async function addIncidentNoteAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace } = await requireWorkspace()
  const incidentId = String(formData.get("incidentId") ?? "")

  if (!incidentId) {
    return { status: "error", message: "Missing incident id." }
  }

  const parsed = incidentNoteSchema.safeParse({
    note: formData.get("note"),
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Write a note before saving.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    const event = await addIncidentNote({
      workspaceId: workspace.id,
      incidentId,
      actorUserId: session.user.id,
      note: parsed.data.note,
    })

    if (!event) {
      return { status: "error", message: "Incident not found." }
    }
  } catch (error) {
    console.error("[incidents] note failed", error)
    return { status: "error", message: "Could not add the note." }
  }

  revalidatePath(`/incidents/${incidentId}`)
  revalidatePath("/incidents")
  return { status: "success", message: "Note added." }
}
