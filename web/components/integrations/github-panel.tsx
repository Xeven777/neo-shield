import {
  ArrowSquareOutIcon,
  GithubLogoIcon,
} from "@phosphor-icons/react/dist/ssr"

import { GithubActions } from "@/components/integrations/github-actions"
import { RepositoryManager } from "@/components/integrations/repository-manager"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import type { GithubConnection } from "@/lib/services/github"

export function GithubPanel({
  connection,
  projects,
  canManage,
  configured,
}: {
  connection: GithubConnection
  projects: Array<{ id: string; name: string; assetCount: number }>
  canManage: boolean
  configured: boolean
}) {
  const { installation, repositories } = connection
  const linked = repositories.filter((repository) => repository.assetId).length

  return (
    <Card>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <CardTitle className="flex flex-wrap items-center gap-2">
            <GithubLogoIcon className="size-5 text-muted-foreground" />
            GitHub
            <Badge
              variant="outline"
              className={`font-mono text-[10px] ${
                installation
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                  : ""
              }`}
            >
              {installation ? "connected" : "not connected"}
            </Badge>
            {installation ? (
              <span className="font-mono text-[11px] font-normal text-muted-foreground">
                {installation.accountLogin}
              </span>
            ) : null}
          </CardTitle>
          <CardDescription className="mt-1 max-w-2xl">
            Read-only GitHub App access with short-lived installation tokens.
            NeoShield never stores a GitHub password, personal access token or
            installation token.
          </CardDescription>
        </div>

        {installation ? (
          canManage ? (
            <GithubActions accountLogin={installation.accountLogin} />
          ) : (
            <Badge variant="secondary" className="font-mono text-[10px]">
              admin required
            </Badge>
          )
        ) : configured ? (
          <Button
            size="sm"
            disabled={!canManage}
            render={<a href="/api/integrations/github/install" />}
          >
            <ArrowSquareOutIcon />
            Install GitHub App
          </Button>
        ) : null}
      </CardHeader>

      <CardContent className="space-y-4">
        {!configured ? (
          <Alert>
            <AlertTitle>GitHub App credentials are missing</AlertTitle>
            <AlertDescription>
              Set{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                GITHUB_APP_ID
              </code>
              ,{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                GITHUB_APP_SLUG
              </code>{" "}
              and{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">
                GITHUB_APP_PRIVATE_KEY
              </code>{" "}
              on the server, then reload this page. Installation callback URL:{" "}
              <code className="font-mono text-xs">
                /api/integrations/github/callback
              </code>
              .
            </AlertDescription>
          </Alert>
        ) : null}

        {!installation ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            Install the GitHub App on the account or organisation you want to
            scan. Only repositories granted to that installation are listed, and
            every token is scoped to it.
          </p>
        ) : repositories.length === 0 ? (
          <p className="rounded-md border border-dashed border-border p-4 text-sm text-muted-foreground">
            The installation has no accessible repositories. Grant repository
            access on GitHub, then sync.
          </p>
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-muted-foreground">
              <span>{repositories.length} repositories visible</span>
              <span aria-hidden>·</span>
              <span>{linked} linked to projects</span>
              <span aria-hidden>·</span>
              <span>installation {installation.installationId}</span>
            </div>
            {repositories.length > 100 ? (
              <p className="text-xs text-muted-foreground">
                Showing the first 100 of {repositories.length} repositories.
                Sync after narrowing the installation if you need more.
              </p>
            ) : null}
            <RepositoryManager
              projects={projects.map((project) => ({
                id: project.id,
                name: project.name,
                assetCount: project.assetCount,
              }))}
              canManage={canManage}
              repositories={repositories.slice(0, 100).map((repository) => ({
                id: repository.id,
                fullName: repository.fullName,
                defaultBranch: repository.defaultBranch,
                private: repository.private,
                projectId: repository.projectId,
                assetId: repository.assetId,
              }))}
            />
          </>
        )}
      </CardContent>
    </Card>
  )
}
