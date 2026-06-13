"use server"

import { revalidatePath } from "next/cache"

import { AuthorizationError, requireWorkspace } from "@/lib/auth/session"
import {
  addDomainAsset,
  DomainRequestError,
  setDomainAssetEnabled,
} from "@/lib/services/domains"
import {
  attachRepositoryToProject,
  detachRepository,
  disconnectGithub,
  syncGithubRepositories,
} from "@/lib/services/github"
import {
  addNetworkAsset,
  NetworkRequestError,
  setNetworkAssetEnabled,
} from "@/lib/services/network"
import { connectWazuh, disconnectWazuh } from "@/lib/services/wazuh"
import {
  attachRepositorySchema,
  connectWazuhSchema,
  createDomainSchema,
  createNetworkSchema,
} from "@/lib/validation/schemas"
import { fieldErrorsFrom, type FormState } from "@/lib/forms"

function revalidateGithub() {
  revalidatePath("/integrations")
  revalidatePath("/dashboard")
  revalidatePath("/projects")
  revalidatePath("/findings")
}

function revalidateDomains(projectId?: string) {
  revalidatePath("/integrations")
  revalidatePath("/dashboard")
  revalidatePath("/projects")
  revalidatePath("/assets")
  revalidatePath("/scans")
  revalidatePath("/findings")
  if (projectId) revalidatePath(`/projects/${projectId}`)
}

function revalidatePhase2() {
  revalidatePath("/integrations")
  revalidatePath("/dashboard")
  revalidatePath("/projects")
  revalidatePath("/assets")
  revalidatePath("/findings")
  revalidatePath("/events")
  revalidatePath("/scans")
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

export async function addDomainAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  const parsed = createDomainSchema.safeParse({
    projectId: formData.get("projectId"),
    domain: formData.get("domain"),
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the highlighted fields.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    await addDomainAsset({
      workspaceId: workspace.id,
      projectId: parsed.data.projectId,
      domain: parsed.data.domain,
      actorUserId: session.user.id,
      actorRole: role,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    if (error instanceof DomainRequestError) {
      return { status: "error", message: error.message }
    }
    console.error("[domains] add failed", error)
    return { status: "error", message: "Could not add the domain." }
  }

  revalidateDomains(parsed.data.projectId)
  return { status: "success", message: `${parsed.data.domain} added.` }
}

export async function setDomainEnabledAction(
  assetId: string,
  enabled: boolean
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    await setDomainAssetEnabled({
      workspaceId: workspace.id,
      assetId,
      enabled,
      actorUserId: session.user.id,
      actorRole: role,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    if (error instanceof DomainRequestError) {
      return { status: "error", message: error.message }
    }
    console.error("[domains] toggle failed", error)
    return { status: "error", message: "Could not update the domain." }
  }

  revalidateDomains()
  return {
    status: "success",
    message: enabled ? "Domain enabled." : "Domain disabled.",
  }
}

export async function connectWazuhAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  const parsed = connectWazuhSchema.safeParse({
    projectId: formData.get("projectId"),
    minLevel: formData.get("minLevel") ?? "5",
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the highlighted fields.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    await connectWazuh({
      workspaceId: workspace.id,
      projectId: parsed.data.projectId,
      minLevel: parsed.data.minLevel,
      actorUserId: session.user.id,
      actorRole: role,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[wazuh] connect failed", error)
    return { status: "error", message: "Could not enable Wazuh ingestion." }
  }

  revalidatePhase2()
  return {
    status: "success",
    message:
      "Wazuh ingestion enabled for this project. Alerts appear after the worker's next sync.",
  }
}

export async function disconnectWazuhAction(): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    await disconnectWazuh({
      workspaceId: workspace.id,
      actorUserId: session.user.id,
      actorRole: role,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    console.error("[wazuh] disconnect failed", error)
    return { status: "error", message: "Could not disable Wazuh ingestion." }
  }

  revalidatePhase2()
  return {
    status: "success",
    message: "Wazuh ingestion disabled. Existing events and findings are kept.",
  }
}

export async function addNetworkAction(
  _previous: FormState,
  formData: FormData
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  const parsed = createNetworkSchema.safeParse({
    projectId: formData.get("projectId"),
    cidr: formData.get("cidr"),
    scanProfile: formData.get("scanProfile") ?? "services",
    authorization:
      formData.get("authorization") === "on" ||
      formData.get("authorization") === "true",
    confirmation: formData.get("confirmation") ?? "",
  })

  if (!parsed.success) {
    return {
      status: "error",
      message: "Check the highlighted fields.",
      fieldErrors: fieldErrorsFrom(parsed.error),
    }
  }

  try {
    await addNetworkAsset({
      workspaceId: workspace.id,
      projectId: parsed.data.projectId,
      cidr: parsed.data.cidr,
      scanProfile: parsed.data.scanProfile,
      authorization: parsed.data.authorization,
      confirmation: parsed.data.confirmation,
      actorUserId: session.user.id,
      actorRole: role,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    if (error instanceof NetworkRequestError) {
      return { status: "error", message: error.message }
    }
    console.error("[network] add failed", error)
    return { status: "error", message: "Could not add the network range." }
  }

  revalidatePhase2()
  revalidatePath(`/projects/${parsed.data.projectId}`)
  return {
    status: "success",
    message: `Authorized range ${parsed.data.cidr} added. Queue a scan to discover hosts.`,
  }
}

export async function setNetworkEnabledAction(
  assetId: string,
  enabled: boolean
): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    await setNetworkAssetEnabled({
      workspaceId: workspace.id,
      assetId,
      enabled,
      actorUserId: session.user.id,
      actorRole: role,
    })
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    if (error instanceof NetworkRequestError) {
      return { status: "error", message: error.message }
    }
    console.error("[network] toggle failed", error)
    return { status: "error", message: "Could not update the network range." }
  }

  revalidatePhase2()
  return {
    status: "success",
    message: enabled ? "Network range enabled." : "Network range disabled.",
  }
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
