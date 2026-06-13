"use server"

import { redirect } from "next/navigation"
import { revalidatePath } from "next/cache"

import { getActiveWorkspace, requireSession } from "@/lib/auth/session"
import { createWorkspaceForUser } from "@/lib/services/workspaces"
import { workspaceNameSchema } from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

export async function createWorkspaceAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const session = await requireSession()

  const existing = await getActiveWorkspace(session.user.id)
  if (existing) redirect("/dashboard")

  const parsed = workspaceNameSchema.safeParse({
    name: formData.get("name"),
  })

  if (!parsed.success) {
    return {
      status: "error",
      fieldErrors: fieldErrorsFrom(parsed.error),
      message: "Check the workspace name.",
    }
  }

  try {
    await createWorkspaceForUser(session.user.id, parsed.data.name)
  } catch (error) {
    console.error("[onboarding] workspace creation failed", error)
    return {
      status: "error",
      message: "Could not create the workspace. Try again.",
    }
  }

  revalidatePath("/", "layout")
  redirect("/dashboard")
}
