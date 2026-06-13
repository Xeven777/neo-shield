import "server-only"

import { and, asc, eq, notInArray } from "drizzle-orm"

import { getDb } from "@/lib/db"
import {
  asset,
  githubInstallation,
  githubRepository,
  type GithubInstallation,
  type GithubRepository,
} from "@/lib/db/schema"
import { AuthorizationError, canManageWorkspace } from "@/lib/auth/session"
import {
  fetchInstallation,
  listInstallationRepositories,
} from "@/lib/github/app"
import { getProject } from "@/lib/services/projects"
import { recordAudit } from "@/lib/services/audit"
import type { WorkspaceRole } from "@/lib/db/schema"

const MAX_REPOSITORIES = 200

export type GithubConnection = {
  installation: GithubInstallation | null
  repositories: GithubRepository[]
}

export async function getGithubConnection(
  workspaceId: string
): Promise<GithubConnection> {
  const db = getDb()

  const [installation] = await db
    .select()
    .from(githubInstallation)
    .where(eq(githubInstallation.workspaceId, workspaceId))
    .limit(1)

  const repositories = await db
    .select()
    .from(githubRepository)
    .where(eq(githubRepository.workspaceId, workspaceId))
    .orderBy(asc(githubRepository.fullName))

  return { installation: installation ?? null, repositories }
}

async function syncRepositoryRows(workspaceId: string, installationId: string) {
  const db = getDb()
  const repositories = (
    await listInstallationRepositories(installationId)
  ).slice(0, MAX_REPOSITORIES)

  for (const repository of repositories) {
    await db
      .insert(githubRepository)
      .values({
        workspaceId,
        installationId,
        githubId: repository.githubId,
        owner: repository.owner,
        name: repository.name,
        fullName: repository.fullName,
        defaultBranch: repository.defaultBranch,
        private: repository.private,
      })
      .onConflictDoUpdate({
        target: [githubRepository.workspaceId, githubRepository.githubId],
        set: {
          installationId,
          owner: repository.owner,
          name: repository.name,
          fullName: repository.fullName,
          defaultBranch: repository.defaultBranch,
          private: repository.private,
          updatedAt: new Date(),
        },
      })
  }

  // Repositories removed from the installation stop being scannable, but their
  // assets and findings stay intact for history.
  if (repositories.length === 0) {
    await db
      .delete(githubRepository)
      .where(eq(githubRepository.workspaceId, workspaceId))
  } else {
    await db.delete(githubRepository).where(
      and(
        eq(githubRepository.workspaceId, workspaceId),
        notInArray(
          githubRepository.githubId,
          repositories.map((repository) => repository.githubId)
        )
      )
    )
  }

  return repositories.length
}

export async function connectGithubInstallation(input: {
  workspaceId: string
  userId: string
  role: WorkspaceRole
  installationId: string
}) {
  if (!canManageWorkspace(input.role)) {
    throw new AuthorizationError("Only workspace admins can connect GitHub.")
  }

  const installation = await fetchInstallation(input.installationId)
  const db = getDb()

  await db
    .insert(githubInstallation)
    .values({
      workspaceId: input.workspaceId,
      installationId: installation.installationId,
      accountLogin: installation.accountLogin,
      accountType: installation.accountType,
      installedByUserId: input.userId,
    })
    .onConflictDoUpdate({
      target: githubInstallation.workspaceId,
      set: {
        installationId: installation.installationId,
        accountLogin: installation.accountLogin,
        accountType: installation.accountType,
        installedByUserId: input.userId,
        updatedAt: new Date(),
      },
    })

  const repositoryCount = await syncRepositoryRows(
    input.workspaceId,
    installation.installationId
  )

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.userId,
    action: "github.connected",
    targetType: "github_installation",
    targetId: installation.installationId,
    metadata: {
      accountLogin: installation.accountLogin,
      repositories: repositoryCount,
    },
  })

  return { installation, repositoryCount }
}

export async function syncGithubRepositories(input: {
  workspaceId: string
  userId: string
  role: WorkspaceRole
}) {
  if (!canManageWorkspace(input.role)) {
    throw new AuthorizationError("Only workspace admins can sync GitHub.")
  }

  const [installation] = await getDb()
    .select()
    .from(githubInstallation)
    .where(eq(githubInstallation.workspaceId, input.workspaceId))
    .limit(1)

  if (!installation) {
    throw new Error("GitHub is not connected for this workspace.")
  }

  const repositoryCount = await syncRepositoryRows(
    input.workspaceId,
    installation.installationId
  )

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.userId,
    action: "github.synced",
    targetType: "github_installation",
    targetId: installation.installationId,
    metadata: { repositories: repositoryCount },
  })

  return { repositoryCount }
}

export async function attachRepositoryToProject(input: {
  workspaceId: string
  userId: string
  role: WorkspaceRole
  repositoryId: string
  projectId: string
}) {
  if (!canManageWorkspace(input.role)) {
    throw new AuthorizationError(
      "Only workspace admins can attach repositories."
    )
  }

  const db = getDb()

  const [repository] = await db
    .select()
    .from(githubRepository)
    .where(
      and(
        eq(githubRepository.workspaceId, input.workspaceId),
        eq(githubRepository.id, input.repositoryId)
      )
    )
    .limit(1)

  if (!repository) {
    throw new Error("Repository not found in this workspace.")
  }

  const project = await getProject(input.workspaceId, input.projectId)
  if (!project) {
    throw new Error("Project not found in this workspace.")
  }

  const identifier = `github:${repository.fullName}`
  const config = {
    provider: "github",
    githubId: repository.githubId,
    installationId: repository.installationId,
    owner: repository.owner,
    name: repository.name,
    fullName: repository.fullName,
    defaultBranch: repository.defaultBranch,
    private: repository.private,
  }

  const [linkedAsset] = await db
    .insert(asset)
    .values({
      projectId: project.id,
      type: "repository",
      displayName: repository.fullName,
      identifier,
      config,
    })
    .onConflictDoUpdate({
      target: [asset.projectId, asset.type, asset.identifier],
      set: {
        displayName: repository.fullName,
        config,
        enabled: true,
        updatedAt: new Date(),
      },
    })
    .returning()

  // Moving a repository between projects disables the previous asset instead of
  // deleting it, so its finding history is preserved.
  if (repository.assetId && repository.assetId !== linkedAsset.id) {
    await db
      .update(asset)
      .set({ enabled: false, updatedAt: new Date() })
      .where(eq(asset.id, repository.assetId))
  }

  await db
    .update(githubRepository)
    .set({
      projectId: project.id,
      assetId: linkedAsset.id,
      selected: true,
      updatedAt: new Date(),
    })
    .where(eq(githubRepository.id, repository.id))

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.userId,
    action: "github.repository_attached",
    targetType: "asset",
    targetId: linkedAsset.id,
    metadata: {
      repository: repository.fullName,
      project: project.name,
    },
  })

  return linkedAsset
}

export async function detachRepository(input: {
  workspaceId: string
  userId: string
  role: WorkspaceRole
  repositoryId: string
}) {
  if (!canManageWorkspace(input.role)) {
    throw new AuthorizationError(
      "Only workspace admins can detach repositories."
    )
  }

  const db = getDb()

  const [repository] = await db
    .select()
    .from(githubRepository)
    .where(
      and(
        eq(githubRepository.workspaceId, input.workspaceId),
        eq(githubRepository.id, input.repositoryId)
      )
    )
    .limit(1)

  if (!repository) {
    throw new Error("Repository not found in this workspace.")
  }

  if (repository.assetId) {
    await db
      .update(asset)
      .set({ enabled: false, updatedAt: new Date() })
      .where(eq(asset.id, repository.assetId))
  }

  await db
    .update(githubRepository)
    .set({
      projectId: null,
      assetId: null,
      selected: false,
      updatedAt: new Date(),
    })
    .where(eq(githubRepository.id, repository.id))

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.userId,
    action: "github.repository_detached",
    targetType: "github_repository",
    targetId: repository.id,
    metadata: { repository: repository.fullName },
  })
}

export async function disconnectGithub(input: {
  workspaceId: string
  userId: string
  role: WorkspaceRole
}) {
  if (!canManageWorkspace(input.role)) {
    throw new AuthorizationError("Only workspace admins can disconnect GitHub.")
  }

  const db = getDb()
  const repositories = await db
    .select()
    .from(githubRepository)
    .where(eq(githubRepository.workspaceId, input.workspaceId))

  const assetIds = repositories
    .map((repository) => repository.assetId)
    .filter((assetId): assetId is string => Boolean(assetId))

  for (const assetId of assetIds) {
    await db
      .update(asset)
      .set({ enabled: false, updatedAt: new Date() })
      .where(eq(asset.id, assetId))
  }

  await db
    .delete(githubRepository)
    .where(eq(githubRepository.workspaceId, input.workspaceId))

  await db
    .delete(githubInstallation)
    .where(eq(githubInstallation.workspaceId, input.workspaceId))

  await recordAudit({
    workspaceId: input.workspaceId,
    actorUserId: input.userId,
    action: "github.disconnected",
    targetType: "github_installation",
    metadata: { repositories: repositories.length },
  })
}
