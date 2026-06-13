"use server"

import { revalidatePath } from "next/cache"

import { AuthorizationError, requireWorkspace } from "@/lib/auth/session"
import {
  createProject,
  deleteProject,
  ProjectNameTakenError,
  updateProject,
} from "@/lib/services/projects"
import {
  createProjectSchema,
  updateProjectSchema,
} from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

function revalidateProjects(projectId?: string) {
  revalidatePath("/dashboard")
  revalidatePath("/projects")
  if (projectId) revalidatePath(`/projects/${projectId}`)
}

export async function createProjectAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  const parsed = createProjectSchema.safeParse({
    name: formData.get("name"),
    description: formData.get("description"),
    environment: formData.get("environment"),
    criticality: formData.get("criticality"),
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the highlighted fields.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    await createProject({
      workspaceId: workspace.id,
      actorUserId: session.user.id,
      actorRole: role,
      data: parsed.data,
    })
  } catch (error) {
    if (error instanceof ProjectNameTakenError) {
      return {
        status: "error",
        message: error.message,
        fieldErrors: { name: [error.message] },
      }
    }
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[projects] create failed", error)
    return { status: "error", message: "Could not create the project." }
  }

  revalidateProjects()
  return { status: "success", message: "Project created." }
}

export async function updateProjectAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()
  const projectId = String(formData.get("projectId") ?? "")

  if (!projectId) {
    return { status: "error", message: "Missing project id." }
  }

  const parsed = updateProjectSchema.safeParse({
    name: formData.get("name"),
    description: formData.get("description"),
    environment: formData.get("environment"),
    criticality: formData.get("criticality"),
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the highlighted fields.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    const updated = await updateProject({
      workspaceId: workspace.id,
      projectId,
      actorUserId: session.user.id,
      actorRole: role,
      data: parsed.data,
    })

    if (!updated) {
      return { status: "error", message: "Project not found." }
    }
  } catch (error) {
    if (error instanceof ProjectNameTakenError) {
      return {
        status: "error",
        message: error.message,
        fieldErrors: { name: [error.message] },
      }
    }
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[projects] update failed", error)
    return { status: "error", message: "Could not update the project." }
  }

  revalidateProjects(projectId)
  return { status: "success", message: "Project updated." }
}

export async function deleteProjectAction(
  projectId: string
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    const deleted = await deleteProject({
      workspaceId: workspace.id,
      projectId,
      actorUserId: session.user.id,
      actorRole: role,
    })

    if (!deleted) return { status: "error", message: "Project not found." }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[projects] delete failed", error)
    return { status: "error", message: "Could not delete the project." }
  }

  revalidateProjects()
  return { status: "success", message: "Project deleted." }
}
