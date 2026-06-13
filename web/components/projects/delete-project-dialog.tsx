"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { TrashIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import { deleteProjectAction } from "@/app/(app)/projects/actions"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"

export function DeleteProjectDialog({
  projectId,
  projectName,
}: {
  projectId: string
  projectName: string
}) {
  const router = useRouter()
  const [open, setOpen] = React.useState(false)
  const [pending, setPending] = React.useState(false)

  async function remove() {
    setPending(true)
    const result = await deleteProjectAction(projectId)
    setPending(false)

    if (result?.status === "success") {
      setOpen(false)
      toast.success(result.message ?? "Project deleted.")
      router.push("/projects")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not delete the project.")
  }

  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <TrashIcon />
        Delete
      </Button>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete {projectName}?</DialogTitle>
            <DialogDescription>
              This removes the project and its assets. Historical findings and
              incidents are not deleted silently once scanning exists — that
              behaviour is added with the Phase 1 data model.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={pending}
            >
              Cancel
            </Button>
            <Button variant="destructive" onClick={remove} disabled={pending}>
              {pending ? <Spinner /> : <TrashIcon />}
              Delete project
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
