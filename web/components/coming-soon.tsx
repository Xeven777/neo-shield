import { ClockCounterClockwiseIcon } from "@phosphor-icons/react/dist/ssr"

import { Badge } from "@/components/ui/badge"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"

export function ComingSoon({
  title,
  phase,
  description,
  children,
}: {
  title: string
  phase: string
  description: string
  children?: React.ReactNode
}) {
  return (
    <Empty className="border border-border bg-card/40">
      <EmptyHeader>
        <EmptyMedia variant="icon">
          <ClockCounterClockwiseIcon />
        </EmptyMedia>
        <EmptyTitle>{title}</EmptyTitle>
        <EmptyDescription>{description}</EmptyDescription>
      </EmptyHeader>
      <Badge variant="outline" className="font-mono text-[10px]">
        {phase}
      </Badge>
      {children}
    </Empty>
  )
}
