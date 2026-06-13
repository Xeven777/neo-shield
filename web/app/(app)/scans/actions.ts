"use server"

import { revalidatePath } from "next/cache"

import { AuthorizationError, requireWorkspace } from "@/lib/auth/session"
import { queueAssetScan, ScanRequestError } from "@/lib/services/scans"
import type { FormState } from "@/lib/forms"

export async function queueScanAction(assetId: string): Promise<FormState> {
  const { session, workspace, role } = await requireWorkspace()

  try {
    const result = await queueAssetScan({
      workspaceId: workspace.id,
      assetId,
      actorUserId: session.user.id,
      actorRole: role,
    })

    revalidatePath("/scans")
    revalidatePath("/findings")
    revalidatePath("/dashboard")

    return {
      status: "success",
      message: result.reused
        ? "A scan is already queued for this asset."
        : "Scan queued. A worker will claim it shortly.",
    }
  } catch (error) {
    if (error instanceof AuthorizationError) {
      return { status: "error", message: error.message }
    }
    if (error instanceof ScanRequestError) {
      return { status: "error", message: error.message }
    }
    console.error("[scans] queue failed", error)
    return { status: "error", message: "Could not queue the scan." }
  }
}
