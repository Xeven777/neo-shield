import "server-only"

import { desc, eq } from "drizzle-orm"

import { getDb } from "@/lib/db"
import { asset, project } from "@/lib/db/schema"

export async function listWorkspaceAssets(workspaceId: string) {
  return getDb()
    .select({
      asset,
      projectName: project.name,
      projectId: project.id,
    })
    .from(asset)
    .innerJoin(project, eq(project.id, asset.projectId))
    .where(eq(project.workspaceId, workspaceId))
    .orderBy(desc(asset.createdAt))
}
