"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { PlayIcon } from "@phosphor-icons/react"
import { toast } from "sonner"

import { queueScanAction } from "@/app/(app)/scans/actions"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"

export function ScanNowButton({
  assetId,
  disabled,
  label = "Scan now",
}: {
  assetId: string
  disabled?: boolean
  label?: string
}) {
  const router = useRouter()
  const [pending, setPending] = React.useState(false)

  async function queue() {
    setPending(true)
    const result = await queueScanAction(assetId)
    setPending(false)

    if (result?.status === "success") {
      toast.success(result.message ?? "Scan queued.")
      router.refresh()
      return
    }

    toast.error(result?.message ?? "Could not queue the scan.")
  }

  return (
    <Button
      size="sm"
      variant="outline"
      onClick={queue}
      disabled={disabled || pending}
    >
      {pending ? <Spinner /> : <PlayIcon />}
      {label}
    </Button>
  )
}
