import { json, withApiContext } from "@/lib/api/http"
import { isGithubAppConfigured } from "@/lib/env"
import { getGithubConnection } from "@/lib/services/github"
import { isWorkerOnline, listWorkers } from "@/lib/services/workers"

export const dynamic = "force-dynamic"

export async function GET() {
  return withApiContext(async ({ workspaceId }) => {
    const [github, workers] = await Promise.all([
      getGithubConnection(workspaceId),
      listWorkers(workspaceId),
    ])

    return json({
      data: {
        github: {
          configured: isGithubAppConfigured(),
          connected: Boolean(github.installation),
          accountLogin: github.installation?.accountLogin ?? null,
          repositories: github.repositories.length,
          linkedRepositories: github.repositories.filter(
            (repository) => repository.assetId
          ).length,
        },
        workers: workers.map((worker) => ({
          id: worker.id,
          name: worker.name,
          status: worker.status,
          online: isWorkerOnline(worker),
          lastSeenAt: worker.lastSeenAt,
          version: worker.version,
        })),
      },
    })
  })
}
