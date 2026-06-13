import "server-only"

import { and, count, desc, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import { asset, project, type Project } from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import { recordAudit } from "@/lib/services/audit"
import {
  createProjectSchema,
  updateProjectSchema,
  type CreateProjectInput,
  type UpdateProjectInput,
} from "@/lib/validation/schemas"
import type { WorkspaceRole } from "@/lib/db/schema"

export class ProjectNameTakenError extends Error {
  constructor() {
    super("A project with that name already exists in this workspace.")
    this.name = "ProjectNameTakenError"
  }
}

export type ProjectSummary = Project & { assetCount: number }

export async function listProjects(
  workspaceId: string
): Promise<ProjectSummary[]> {
  const rows = await getDb()
    .select({
      project,
      assetCount: count(asset.id),
    })
    .from(project)
    .leftJoin(asset, eq(asset.projectId, project.id))
    .where(eq(project.workspaceId, workspaceId))
    .groupBy(project.id)
    .orderBy(desc(project.createdAt))

  return rows.map((row) => ({ ...row.project, assetCount: row.assetCount }))
}

export async function getProject(
  workspaceId: string,
  projectId: string
): Promise<Project | null> {
  const [row] = await getDb()
    .select()
    .from(project)
    .where(and(eq(project.workspaceId, workspaceId), eq(project.id, projectId)))
    .limit(1)

  return row ?? null
}

export async function listProjectAssets(projectId: string) {
  return getDb()
    .select()
    .from(asset)
    .where(eq(asset.projectId, projectId))
    .orderBy(desc(asset.createdAt))
}

export async function createProject(input: {
  workspaceId: string
  actorUserId: string
  actorRole: WorkspaceRole
  data: CreateProjectInput
}): Promise<Project> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "You do not have permission to create projects."
    )
  }

  const data = createProjectSchema.parse(input.data)

  try {
    const [created] = await getDb()
      .insert(project)
      .values({
        workspaceId: input.workspaceId,
        name: data.name,
        description: data.description ?? null,
        environment: data.environment,
        criticality: data.criticality,
      })
      .returning()

    await recordAudit({
      workspaceId: input.workspaceId,
      actorUserId: input.actorUserId,
      action: "project.created",
      targetType: "project",
      targetId: created.id,
      metadata: { name: created.name, environment: created.environment },
    })

    return created
  } catch (error) {
    if (isUniqueViolation(error)) throw new ProjectNameTakenError()
    throw error
  }
}

export async function updateProject(input: {
  workspaceId: string
  projectId: string
  actorUserId: string
  actorRole: WorkspaceRole
  data: UpdateProjectInput
}): Promise<Project | null> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "You do not have permission to update projects."
    )
  }

  const existing = await getProject(input.workspaceId, input.projectId)
  if (!existing) return null

  const data = updateProjectSchema.parse(input.data)

  try {
    const [updated] = await getDb()
      .update(project)
      .set({
        ...(data.name !== undefined ? { name: data.name } : {}),
        ...(data.description !== undefined
          ? { description: data.description ?? null }
          : {}),
        ...(data.environment !== undefined
          ? { environment: data.environment }
          : {}),
        ...(data.criticality !== undefined
          ? { criticality: data.criticality }
          : {}),
        updatedAt: new Date(),
      })
      .where(eq(project.id, input.projectId))
      .returning()

    await recordAudit({
      workspaceId: input.workspaceId,
      actorUserId: input.actorUserId,
      action: "project.updated",
      targetType: "project",
      targetId: input.projectId,
    })

    return updated
  } catch (error) {
    if (isUniqueViolation(error)) throw new ProjectNameTakenError()
    throw error
  }
}

export async function deleteProject(input: {
  workspaceId: string
  projectId: string
  actorUserId: string
  actorRole: WorkspaceRole
}): Promise<boolean> {
  if (!canManageWorkspace(input.actorRole)) {
    throw new AuthorizationError(
      "You do not have permission to delete projects."
    )
  }

  const existing = await getProject(input.workspaceId, input.projectId)
  if (!existing) return false

  await getDb().delete(project).where(eq(project.id, input.projectId))

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.actorUserId,
    action: "project.deleted",
    targetType: "project",
    targetId: input.projectId,
    metadata: { name: existing.name },
  })

  return true
}

function isUniqueViolation(error: unknown) {
  if (typeof error !== "object" || error === null) return false
  const candidate = error as { code?: string; cause?: { code?: string } }
  return candidate.code === "23505" || candidate.cause?.code === "23505"
}
