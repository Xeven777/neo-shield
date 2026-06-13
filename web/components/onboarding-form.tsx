"use client"

import { useActionState } from "react"
import { ArrowRightIcon } from "@phosphor-icons/react"

import { createWorkspaceAction } from "@/app/onboarding/actions"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"

export function WorkspaceOnboardingForm() {
  const [state, action, pending] = useActionState(createWorkspaceAction, undefined)

  return (
    <form action={action} noValidate>
      <FieldGroup>
        <Field data-invalid={Boolean(state?.fieldErrors?.name)}>
          <FieldLabel htmlFor="workspace-name">Workspace name</FieldLabel>
          <Input
            id="workspace-name"
            name="name"
            placeholder="Acme Security Lab"
            autoComplete="organization"
            autoFocus
            required
            aria-invalid={Boolean(state?.fieldErrors?.name)}
          />
          <FieldDescription>
            Usually your team or lab name. Projects live inside it.
          </FieldDescription>
          <FieldError
            errors={state?.fieldErrors?.name?.map((message) => ({ message }))}
          />
        </Field>

        {state?.status === "error" && !state.fieldErrors?.name ? (
          <FieldError>{state.message}</FieldError>
        ) : null}

        <Button type="submit" disabled={pending} className="w-full">
          {pending ? <Spinner /> : null}
          Create workspace
          <ArrowRightIcon data-icon="inline-end" />
        </Button>
      </FieldGroup>
    </form>
  )
}
