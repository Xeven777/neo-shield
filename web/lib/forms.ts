import type { ZodError } from "zod"

export type FormState =
  | {
      status: "error" | "success"
      message?: string
      fieldErrors?: Record<string, string[] | undefined>
      /** Plaintext worker token, returned exactly once after creation. */
      token?: string
      tokenPrefix?: string
      workerName?: string
    }
  | undefined

export function fieldErrorsFrom(error: ZodError) {
  return error.flatten().fieldErrors
}

export function firstError(state: FormState) {
  if (!state?.message) return undefined
  return state.message
}
