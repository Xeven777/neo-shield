import { z } from "zod"

export const projectEnvironments = [
  "development",
  "staging",
  "production",
  "lab",
] as const

export const projectCriticalities = ["low", "medium", "high"] as const

const optionalText = (max: number) =>
  z.preprocess(
    (value) =>
      typeof value === "string" && value.trim() === "" ? undefined : value,
    z.string().trim().max(max).optional()
  )

export const createProjectSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Project name is required.")
    .max(80, "Keep the name under 80 characters."),
  description: optionalText(500),
  environment: z.enum(projectEnvironments).default("development"),
  criticality: z.enum(projectCriticalities).default("medium"),
})

export const updateProjectSchema = createProjectSchema.partial().refine(
  (value) => Object.keys(value).length > 0,
  "Provide at least one field to update."
)

export const workspaceNameSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "Workspace name must be at least 2 characters.")
    .max(80, "Keep the workspace name under 80 characters."),
})

export const createWorkerSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Worker name is required.")
    .max(80, "Keep the worker name under 80 characters."),
})

export const attachRepositorySchema = z.object({
  repositoryId: z.uuid("Select a repository."),
  projectId: z.uuid("Select a project."),
})

export const queueScanSchema = z.object({
  assetId: z.uuid("Invalid asset id."),
})

export const findingSeverities = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const

export const findingStatuses = [
  "open",
  "acknowledged",
  "in_progress",
  "resolved",
  "accepted_risk",
  "false_positive",
] as const

export const findingSources = [
  "github",
  "domain",
  "wazuh",
  "network",
  "aws",
] as const

export const findingFilterSchema = z.object({
  severity: z.enum(findingSeverities).optional(),
  status: z.enum(findingStatuses).optional(),
  source: z.enum(findingSources).optional(),
  projectId: z.uuid().optional(),
  q: z.string().trim().max(120).optional(),
})

export const findingStatusUpdateSchema = z.object({
  status: z.enum(findingStatuses),
  note: z.string().trim().max(500).optional(),
})

export type CreateProjectInput = z.infer<typeof createProjectSchema>
export type UpdateProjectInput = z.infer<typeof updateProjectSchema>
export type FindingFilter = z.infer<typeof findingFilterSchema>
export type FindingStatusUpdateInput = z.infer<
  typeof findingStatusUpdateSchema
>
