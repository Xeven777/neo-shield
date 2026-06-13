import "server-only"

import { createSign } from "node:crypto"

import { isGithubAppConfigured, serverEnv } from "@/lib/env"

const GITHUB_API = "https://api.github.com"
const GITHUB_API_VERSION = "2022-11-28"
const REQUEST_TIMEOUT_MS = 15_000

export class GithubAppError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "GithubAppError"
  }
}

type InstallationToken = { token: string; expiresAt: number }

const tokenCache = new Map<string, InstallationToken>()

function base64url(value: string) {
  return Buffer.from(value, "utf8").toString("base64url")
}

function appPrivateKey() {
  const key = serverEnv().GITHUB_APP_PRIVATE_KEY
  if (!key) throw new GithubAppError("GitHub App private key is not configured.")
  // Supports PEMs pasted as a single line with escaped newlines.
  return key.replace(/\\n/g, "\n")
}

/** RS256 JWT accepted by the GitHub App API. Valid for at most 10 minutes. */
export function createAppJwt(now = Math.floor(Date.now() / 1000)) {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }))
  const payload = base64url(
    JSON.stringify({
      iat: now - 60,
      exp: now + 540,
      iss: serverEnv().GITHUB_APP_ID,
    })
  )

  const signer = createSign("RSA-SHA256")
  signer.update(`${header}.${payload}`)
  const signature = signer.sign(appPrivateKey()).toString("base64url")

  return `${header}.${payload}.${signature}`
}

async function githubRequest<T>(
  path: string,
  token: string,
  init: RequestInit = {}
): Promise<T> {
  const response = await fetch(`${GITHUB_API}${path}`, {
    ...init,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "x-github-api-version": GITHUB_API_VERSION,
      "user-agent": "neoshield",
      ...init.headers,
    },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    cache: "no-store",
  })

  if (!response.ok) {
    // Never include the response body: it can echo request details.
    console.error(
      `[github] ${init.method ?? "GET"} ${path} failed with ${response.status}`
    )
    throw new GithubAppError(`GitHub API request failed (${response.status})`)
  }

  return (await response.json()) as T
}

export async function getInstallationToken(installationId: string) {
  const cached = tokenCache.get(installationId)
  if (cached && cached.expiresAt - Date.now() > 120_000) {
    return cached.token
  }

  const data = await githubRequest<{
    token: string
    expires_at: string
  }>(`/app/installations/${encodeURIComponent(installationId)}/access_tokens`, createAppJwt(), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({}),
  })

  const expiresAt = Date.parse(data.expires_at)
  tokenCache.set(installationId, {
    token: data.token,
    expiresAt: Number.isNaN(expiresAt) ? Date.now() + 300_000 : expiresAt,
  })

  return data.token
}

export type GithubInstallationInfo = {
  installationId: string
  accountLogin: string
  accountType: string
}

export async function fetchInstallation(
  installationId: string
): Promise<GithubInstallationInfo> {
  const data = await githubRequest<{
    id: number
    account: { login: string; type: string }
  }>(`/app/installations/${encodeURIComponent(installationId)}`, createAppJwt())

  return {
    installationId: String(data.id),
    accountLogin: data.account.login,
    accountType: data.account.type,
  }
}

export type GithubRepositoryInfo = {
  githubId: string
  owner: string
  name: string
  fullName: string
  defaultBranch: string
  private: boolean
}

const MAX_REPOSITORY_PAGES = 5

export async function listInstallationRepositories(
  installationId: string
): Promise<GithubRepositoryInfo[]> {
  const token = await getInstallationToken(installationId)
  const repositories: GithubRepositoryInfo[] = []

  for (let page = 1; page <= MAX_REPOSITORY_PAGES; page += 1) {
    const data = await githubRequest<{
      total_count: number
      repositories: Array<{
        id: number
        name: string
        full_name: string
        private: boolean
        default_branch: string
        owner: { login: string }
      }>
    }>(
      `/installation/repositories?per_page=100&page=${page}`,
      token
    )

    for (const repository of data.repositories) {
      repositories.push({
        githubId: String(repository.id),
        owner: repository.owner.login,
        name: repository.name,
        fullName: repository.full_name,
        defaultBranch: repository.default_branch || "main",
        private: repository.private,
      })
    }

    if (data.repositories.length < 100) break
  }

  return repositories
}

/** Resolves a branch to a commit SHA so scans are reproducible. */
export async function resolveCommitSha(
  installationId: string,
  fullName: string,
  ref: string
) {
  const token = await getInstallationToken(installationId)
  const data = await githubRequest<{ sha: string }>(
    `/repos/${fullName}/commits/${encodeURIComponent(ref)}`,
    token
  )
  return data.sha
}

export function githubInstallUrl(state: string) {
  const slug = serverEnv().GITHUB_APP_SLUG
  if (!slug) throw new GithubAppError("GitHub App slug is not configured.")
  return `https://github.com/apps/${encodeURIComponent(slug)}/installations/new?state=${encodeURIComponent(state)}`
}

export { isGithubAppConfigured }
