import { Badge } from "@/components/ui/badge"
import type { FindingSeverity, FindingStatus } from "@/lib/db/schema"
import { titleCase } from "@/lib/format"

const severityStyles: Record<FindingSeverity, string> = {
  critical:
    "border-rose-600/40 bg-rose-600/10 text-rose-700 dark:text-rose-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-700 dark:text-orange-300",
  medium:
    "border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  low: "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  informational: "border-border bg-muted/40 text-muted-foreground",
}

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <Badge
      variant="outline"
      className={`font-mono text-[10px] uppercase ${severityStyles[severity]}`}
    >
      {severity}
    </Badge>
  )
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <Badge variant="secondary" className="font-mono text-[10px]">
      {titleCase(status)}
    </Badge>
  )
}
