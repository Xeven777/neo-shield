"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { ArrowsClockwiseIcon, PlugsIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import {
  disconnectGithubAction,
  syncGithubAction,
} from "@/app/(app)/integrations/actions"
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

export function GithubActions({ accountLogin }: { accountLogin: string }) {
  const router = useRouter()
  const [pending, setPending] = React.useState<"sync" | "disconnect" | null>(
    null
  )
  const [open, setOpen] = React.useState(false)

  async function sync() {
    setPending("sync")
    const result = await syncGithubAction()
    setPending(null)

    if (result?.status === "success") {
      toast.success(result.message ?? "Repositories synced.")
      router.refresh()
    } else {
      toast.error(result?.message ?? "Could not sync repositories.")
    }
  }

  async function disconnect() {
    setPending("disconnect")
    const result = await disconnectGithubAction()
    setPending(null)

    if (result?.status === "success") {
      setOpen(false)
      toast.success(result.message ?? "GitHub disconnected.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not disconnect GitHub.")
  }

  return (
    <>
      <div className="flex items-center gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={sync}
          disabled={pending !== null}
        >
          {pending === "sync" ? <Spinner /> : <ArrowsClockwiseIcon />}
          Sync repositories
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setOpen(true)}
          disabled={pending !== null}
        >
          <PlugsIcon />
          Disconnect
        </Button>
      </div>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Disconnect {accountLogin}?</DialogTitle>
            <DialogDescription>
              NeoShield forgets the installation and stops scanning linked
              repositories. Existing findings and scan history are kept. You can
              also uninstall the app from GitHub at any time.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={pending !== null}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={disconnect}
              disabled={pending !== null}
            >
              {pending === "disconnect" ? <Spinner /> : null}
              Disconnect
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
