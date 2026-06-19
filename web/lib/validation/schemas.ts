import { z } from "zod"

import { parseNetworkScope } from "@/lib/validation/network"

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

export const updateProjectSchema = createProjectSchema
  .partial()
  .refine(
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

const DOMAIN_PATTERN =
  /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$/

/**
 * Accepts a bare hostname or a pasted URL and returns the hostname in the exact
 * form the worker will scan (lowercase, no scheme, path, port or trailing dot).
 */
export function normalizeDomainInput(value: string): string {
  let candidate = value.trim().toLowerCase()

  if (!candidate) return candidate

  candidate = candidate.replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
  candidate = candidate.split(/[/?#]/)[0] ?? candidate
  candidate = candidate.replace(/:\d+$/, "")
  candidate = candidate.replace(/\.$/, "")

  return candidate
}

export const createDomainSchema = z.object({
  projectId: z.uuid("Select a project."),
  domain: z
    .string()
    .trim()
    .min(1, "Enter a domain name.")
    .max(253, "Domains are at most 253 characters.")
    .transform(normalizeDomainInput)
    .pipe(
      z
        .string()
        .regex(DOMAIN_PATTERN, "Enter a valid domain, for example example.com.")
    ),
})

export const queueScanSchema = z.object({
  assetId: z.uuid("Invalid asset id."),
})

/* -------------------------------------------------------------------------- */
/* Phase 2: endpoint monitoring and authorized network discovery              */
/* -------------------------------------------------------------------------- */

export const networkScanProfiles = ["discovery", "services"] as const

export const connectWazuhSchema = z.object({
  projectId: z.uuid("Select a project."),
  minLevel: z.coerce
    .number()
    .int()
    .min(0, "Level must be at least 0.")
    .max(16, "Level must be at most 16.")
    .default(5),
})

export const createNetworkSchema = z
  .object({
    projectId: z.uuid("Select a project."),
    cidr: z
      .string()
      .trim()
      .min(1, "Enter the exact CIDR range you are authorized to scan.")
      .max(32, "Keep the CIDR under 32 characters."),
    scanProfile: z.enum(networkScanProfiles).default("services"),
    authorization: z.boolean(),
    confirmation: z.string().trim().max(32),
  })
  .superRefine((value, context) => {
    let scope: ReturnType<typeof parseNetworkScope> | null = null

    try {
      scope = parseNetworkScope(value.cidr)
    } catch (error) {
      context.addIssue({
        code: "custom",
        path: ["cidr"],
        message:
          error instanceof Error ? error.message : "Enter a valid CIDR range.",
      })
    }

    if (!value.authorization) {
      context.addIssue({
        code: "custom",
        path: ["authorization"],
        message:
          "Confirm that you own or are explicitly authorized to scan this range.",
      })
    }

    if (scope && value.confirmation !== scope.cidr) {
      context.addIssue({
        code: "custom",
        path: ["confirmation"],
        message: `Type ${scope.cidr} exactly to confirm the scope.`,
      })
    }
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

export const eventFilterSchema = z.object({
  severity: z.enum(findingSeverities).optional(),
  source: z.enum(findingSources).optional(),
  projectId: z.uuid().optional(),
  q: z.string().trim().max(120).optional(),
})

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

export const findingNoteSchema = z.object({
  note: z
    .string()
    .trim()
    .min(1, "Write a note before saving.")
    .max(2000, "Keep notes under 2000 characters."),
})

const optionalOwner = z.preprocess(
  (value) => (value === "" || value === null ? null : value),
  z.uuid("Select a workspace member.").nullable().optional()
)

export const ownerUpdateSchema = z.object({
  ownerUserId: optionalOwner,
})

/* -------------------------------------------------------------------------- */
/* Phase 3: remediation tracking                                              */
/* -------------------------------------------------------------------------- */

export const remediationStatuses = [
  "planned",
  "in_progress",
  "fixed",
  "verified",
] as const

export const createRemediationSchema = z.object({
  findingId: z.uuid("Invalid finding id."),
  recommendation: z
    .string()
    .trim()
    .min(1, "Describe the remediation step.")
    .max(1000, "Keep the recommendation under 1000 characters."),
  ownerUserId: optionalOwner,
})

export const remediationStatusUpdateSchema = z.object({
  remediationId: z.uuid("Invalid remediation id."),
  status: z.enum(remediationStatuses),
  note: z.string().trim().max(1000).optional(),
})

/* -------------------------------------------------------------------------- */
/* Phase 3: incidents                                                         */
/* -------------------------------------------------------------------------- */

export const incidentStatuses = [
  "new",
  "investigating",
  "contained",
  "resolved",
  "closed",
] as const

export const incidentFilterSchema = z.object({
  status: z.enum(incidentStatuses).optional(),
  severity: z.enum(findingSeverities).optional(),
  projectId: z.uuid().optional(),
  q: z.string().trim().max(120).optional(),
})

export const incidentStatusUpdateSchema = z.object({
  status: z.enum(incidentStatuses),
  note: z.string().trim().max(1000).optional(),
})

export const incidentNoteSchema = z.object({
  note: z
    .string()
    .trim()
    .min(1, "Write a note before saving.")
    .max(1000, "Keep notes under 1000 characters."),
})

export type CreateProjectInput = z.infer<typeof createProjectSchema>
export type UpdateProjectInput = z.infer<typeof updateProjectSchema>
export type EventFilter = z.infer<typeof eventFilterSchema>
export type FindingFilter = z.infer<typeof findingFilterSchema>
export type FindingStatusUpdateInput = z.infer<typeof findingStatusUpdateSchema>
export type FindingNoteInput = z.infer<typeof findingNoteSchema>
export type OwnerUpdateInput = z.infer<typeof ownerUpdateSchema>
export type CreateRemediationInput = z.infer<typeof createRemediationSchema>
export type RemediationStatusUpdateInput = z.infer<
  typeof remediationStatusUpdateSchema
>
export type IncidentFilter = z.infer<typeof incidentFilterSchema>
export type IncidentStatusUpdateInput = z.infer<
  typeof incidentStatusUpdateSchema
>
export type IncidentNoteInput = z.infer<typeof incidentNoteSchema>
