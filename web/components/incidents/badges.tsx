import { Badge } from "@/components/ui/badge"
import type { IncidentStatus } from "@/lib/db/schema"
import { titleCase } from "@/lib/format"

const statusStyles: Record<IncidentStatus, string> = {
  new: "border-rose-600/40 bg-rose-600/10 text-rose-700 dark:text-rose-300",
  investigating:
    "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  contained: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  resolved:
    "border-emerald-600/40 bg-emerald-600/10 text-emerald-700 dark:text-emerald-300",
  closed: "border-border bg-muted/40 text-muted-foreground",
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <Badge
      variant="outline"
      className={`font-mono text-[10px] uppercase ${statusStyles[status]}`}
    >
      {titleCase(status)}
    </Badge>
  )
}
