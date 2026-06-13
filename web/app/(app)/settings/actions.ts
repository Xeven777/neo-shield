"use server"

import { revalidatePath } from "next/cache"

import {
  AuthorizationError,
  canManageWorkspace,
  requireWorkspace,
} from "@/lib/auth/session"
import { createWorker, revokeWorker } from "@/lib/services/workers"
import { renameWorkspace } from "@/lib/services/workspaces"
import {
  createWorkerSchema,
  workspaceNameSchema,
} from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

export async function renameWorkspaceAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  if (!canManageWorkspace(role)) {
    return { status: "error", message: "Only workspace admins can rename it." }
  }

  const parsed = workspaceNameSchema.safeParse({ name: formData.get("name") })
  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the workspace name.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    await renameWorkspace({
      workspaceId: workspace.id,
      actorUserId: session.user.id,
      actorRole: role,
      name: parsed.data.name,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[settings] rename failed", error)
    return { status: "error", message: "Could not rename the workspace." }
  }

  revalidatePath("/", "layout")
  return { status: "success", message: "Workspace renamed." }
}

export async function createWorkerAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  if (!canManageWorkspace(role)) {
    return {
      status: "error",
      message: "Only workspace admins can add workers.",
    }
  }

  const parsed = createWorkerSchema.safeParse({ name: formData.get("name") })
  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the worker name.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    const created = await createWorker({
      workspaceId: workspace.id,
      actorUserId: session.user.id,
      name: parsed.data.name,
    })

    revalidatePath("/settings")
    revalidatePath("/dashboard")

    return {
      status: "success",
      message: "Worker token issued.",
      token: created.token,
      tokenPrefix: created.worker.tokenPrefix,
      workerName: created.worker.name,
    }
  } catch (error) {
    console.error("[settings] worker creation failed", error)
    return { status: "error", message: "Could not create the worker token." }
  }
}

export async function revokeWorkerAction(workerId: string): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  if (!canManageWorkspace(role)) {
    return {
      status: "error",
      message: "Only workspace admins can revoke workers.",
    }
  }

  try {
    const revoked = await revokeWorker({
      workspaceId: workspace.id,
      workerId,
      actorUserId: session.user.id,
    })

    if (!revoked) {
      return { status: "error", message: "Worker not found." }
    }
  } catch (error) {
    console.error("[settings] revoke failed", error)
    return { status: "error", message: "Could not revoke the worker." }
  }

  revalidatePath("/settings")
  revalidatePath("/dashboard")
  return { status: "success", message: "Worker revoked." }
}
