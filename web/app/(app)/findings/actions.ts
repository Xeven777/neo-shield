"use server"

import { revalidatePath } from "next/cache"

import { AuthorizationError, requireWorkspace } from "@/lib/auth/session"
import { updateFindingStatus } from "@/lib/services/findings"
import { findingStatusUpdateSchema } from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

export async function updateFindingStatusAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()
  const findingId = String(formData.get("findingId") ?? "")

  if (!findingId) {
    return { status: "error", message: "Missing finding id." }
  }

  const parsed = findingStatusUpdateSchema.safeParse({
    status: formData.get("status"),
    note: formData.get("note") || undefined,
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Choose a valid status.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    const updated = await updateFindingStatus({
      workspaceId: workspace.id,
      findingId,
      actorUserId: session.user.id,
      actorRole: role,
      status: parsed.data.status,
      note: parsed.data.note,
    })

    if (!updated) {
      return { status: "error", message: "Finding not found." }
    }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[findings] status update failed", error)
    return { status: "error", message: "Could not update the finding." }
  }

  revalidatePath("/findings")
  revalidatePath(`/findings/${findingId}`)
  revalidatePath("/dashboard")
  return { status: "success", message: "Finding status updated." }
}
