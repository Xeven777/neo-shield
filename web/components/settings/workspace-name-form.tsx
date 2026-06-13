"use client"

import { useActionState, useEffect } from "react"
import { toast } from "sonner"

import { renameWorkspaceAction } from "@/app/(app)/settings/actions"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"

export function WorkspaceNameForm({
  defaultName,
  disabled,
}: {
  defaultName: string
  disabled?: boolean
}) {
  const [state, action, pending] = useActionState(
    renameWorkspaceAction,
    undefined
  )

  useEffect(() => {
    if (state?.status === "success") toast.success(state.message ?? "Saved.")
    if (state?.status === "error" && state.message) toast.error(state.message)
  }, [state])

  return (
    <form action={action} noValidate>
      <FieldGroup className="gap-4">
        <Field data-invalid={Boolean(state?.fieldErrors?.name)}>
          <FieldLabel htmlFor="workspace-name-settings">Workspace name</FieldLabel>
          <Input
            id="workspace-name-settings"
            name="name"
            defaultValue={defaultName}
            disabled={disabled}
            required
            aria-invalid={Boolean(state?.fieldErrors?.name)}
          />
          <FieldError
            errors={state?.fieldErrors?.name?.map((message) => ({ message }))}
          />
        </Field>
        <Button
          type="submit"
          size="sm"
          className="w-fit"
          disabled={pending || disabled}
        >
          {pending ? <Spinner /> : null}
          Save name
        </Button>
      </FieldGroup>
    </form>
  )
}
