"use client"

import * as React from "react"
import { PencilSimpleIcon, PlusIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  createProjectAction,
  updateProjectAction,
} from "@/app/(app)/projects/actions"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Spinner } from "@/components/ui/spinner"
import { Textarea } from "@/components/ui/textarea"
import {
  projectCriticalities,
  projectEnvironments,
} from "@/lib/validation/schemas"

type ProjectDefaults = {
  id: string
  name: string
  description: string | null
  environment: string
  criticality: string
}

const selectClassName =
  "h-9 w-full rounded-md border border-input bg-transparent px-2.5 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"

export function ProjectDialog({
  mode,
  project,
}: {
  mode: "create" | "edit"
  project?: ProjectDefaults
}) {
  const [open, setOpen] = React.useState(false)
  const [pending, setPending] = React.useState(false)
  const [message, setMessage] = React.useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = React.useState<
    Record<string, string[] | undefined>
  >({})

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formData = new FormData(event.currentTarget)

    setPending(true)
    setMessage(null)
    setFieldErrors({})

    const result =
      mode === "create"
        ? await createProjectAction(undefined, formData)
        : await updateProjectAction(undefined, formData)

    setPending(false)

    if (result?.status === "success") {
      setOpen(false)
      toast.success(result.message ?? "Saved.")
      return
    }

    setFieldErrors(result?.fieldErrors ?? {})
    setMessage(result?.message ?? "Could not save the project.")
    toast.error(result?.message ?? "Could not save the project.")
  }

  return (
    <>
      <Button
        variant={mode === "create" ? "default" : "outline"}
        size={mode === "create" ? "default" : "sm"}
        onClick={() => {
          setOpen(true)
          setMessage(null)
          setFieldErrors({})
        }}
      >
        {mode === "create" ? <PlusIcon /> : <PencilSimpleIcon />}
        {mode === "create" ? "New project" : "Edit"}
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>
              {mode === "create" ? "Create a project" : "Edit project"}
            </DialogTitle>
            <DialogDescription>
              Projects group the repositories, domains and endpoints you assess
              together.
            </DialogDescription>
          </DialogHeader>

          <form onSubmit={submit} noValidate className="mt-2">
            {project ? (
              <input type="hidden" name="projectId" value={project.id} />
            ) : null}

            <FieldGroup>
              <Field data-invalid={Boolean(fieldErrors.name)}>
                <FieldLabel htmlFor={`project-name-${mode}`}>Name</FieldLabel>
                <Input
                  id={`project-name-${mode}`}
                  name="name"
                  defaultValue={project?.name}
                  placeholder="Payments API"
                  autoFocus
                  required
                  aria-invalid={Boolean(fieldErrors.name)}
                />
                <FieldError
                  errors={fieldErrors.name?.map((text) => ({ message: text }))}
                />
              </Field>

              <Field>
                <FieldLabel htmlFor={`project-description-${mode}`}>
                  Description{" "}
                  <span className="text-muted-foreground">(optional)</span>
                </FieldLabel>
                <Textarea
                  id={`project-description-${mode}`}
                  name="description"
                  defaultValue={project?.description ?? ""}
                  placeholder="What this project covers and who owns it."
                  rows={3}
                />
                <FieldError
                  errors={fieldErrors.description?.map((text) => ({
                    message: text,
                  }))}
                />
              </Field>

              <div className="grid gap-4 sm:grid-cols-2">
                <Field>
                  <FieldLabel htmlFor={`project-environment-${mode}`}>
                    Environment
                  </FieldLabel>
                  <select
                    id={`project-environment-${mode}`}
                    name="environment"
                    defaultValue={project?.environment ?? "development"}
                    className={selectClassName}
                  >
                    {projectEnvironments.map((environment) => (
                      <option key={environment} value={environment}>
                        {environment}
                      </option>
                    ))}
                  </select>
                </Field>

                <Field>
                  <FieldLabel htmlFor={`project-criticality-${mode}`}>
                    Business criticality
                  </FieldLabel>
                  <select
                    id={`project-criticality-${mode}`}
                    name="criticality"
                    defaultValue={project?.criticality ?? "medium"}
                    className={selectClassName}
                  >
                    {projectCriticalities.map((criticality) => (
                      <option key={criticality} value={criticality}>
                        {criticality}
                      </option>
                    ))}
                  </select>
                </Field>
              </div>

              {message ? <FieldError>{message}</FieldError> : null}
            </FieldGroup>

            <DialogFooter className="mt-6">
              <Button
                type="button"
                variant="outline"
                onClick={() => setOpen(false)}
                disabled={pending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={pending}>
                {pending ? <Spinner /> : null}
                {mode === "create" ? "Create project" : "Save changes"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}
