"use server"

import { revalidatePath } from "next/cache"

import { AuthorizationError, requireWorkspace } from "@/lib/auth/session"
import {
  attachRepositoryToProject,
  detachRepository,
  disconnectGithub,
  syncGithubRepositories,
} from "@/lib/services/github"
import { attachRepositorySchema } from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

function revalidateGithub() {
  revalidatePath("/integrations")
  revalidatePath("/dashboard")
  revalidatePath("/projects")
  revalidatePath("/findings")
}

export async function syncGithubAction(): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    const result = await syncGithubRepositories({
      workspaceId: workspace.id,
      userId: session.user.id,
      role,
    })
    revalidateGithub()
    return {
      status: "success",
      message: `Synced ${result.repositoryCount} repositories.`,
    }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[github] sync failed", error)
    return { status: "error", message: "Could not sync repositories." }
  }
}

export async function disconnectGithubAction(): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    await disconnectGithub({
      workspaceId: workspace.id,
      userId: session.user.id,
      role,
    })
    revalidateGithub()
    return { status: "success", message: "GitHub disconnected." }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[github] disconnect failed", error)
    return { status: "error", message: "Could not disconnect GitHub." }
  }
}

export async function attachRepositoryAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  const parsed = attachRepositorySchema.safeParse({
    repositoryId: formData.get("repositoryId"),
    projectId: formData.get("projectId"),
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Choose a repository and a project.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    await attachRepositoryToProject({
      workspaceId: workspace.id,
      userId: session.user.id,
      role,
      repositoryId: parsed.data.repositoryId,
      projectId: parsed.data.projectId,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[github] attach failed", error)
    return { status: "error", message: "Could not attach the repository." }
  }

  revalidateGithub()
  revalidatePath(`/projects/${parsed.data.projectId}`)
  return { status: "success", message: "Repository attached to the project." }
}

export async function detachRepositoryAction(
  repositoryId: string
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    await detachRepository({
      workspaceId: workspace.id,
      userId: session.user.id,
      role,
      repositoryId,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[github] detach failed", error)
    return { status: "error", message: "Could not detach the repository." }
  }

  revalidateGithub()
  return { status: "success", message: "Repository detached." }
}
