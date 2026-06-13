import Link from "next/link"

import { cn } from "@/lib/utils"

export function WorkerPill({
  online,
  total,
}: {
  online: number
  total: number
}) {
  const online_ = online > 0

  return (
    <Link
      href="/settings"
      className="flex items-center justify-between rounded-md border border-sidebar-border bg-sidebar-accent/40 px-2.5 py-2 text-xs transition-colors hover:bg-sidebar-accent"
    >
      <span className="flex items-center gap-2">
        <span
          className={cn(
            "size-1.5 rounded-full",
            online_
              ? "bg-emerald-500 shadow-[0_0_0_3px] shadow-emerald-500/20"
              : "bg-muted-foreground/50"
          )}
        />
        <span className="text-muted-foreground">Worker</span>
      </span>
      <span
        className={cn(
          "font-mono text-[10px] tracking-wide uppercase",
          online_
            ? "text-emerald-600 dark:text-emerald-400"
            : "text-muted-foreground"
        )}
      >
        {total === 0
          ? "none"
          : online_
            ? `${online}/${total} online`
            : "offline"}
      </span>
    </Link>
  )
}
