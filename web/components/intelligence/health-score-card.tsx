import type { HealthScoreView } from "@/lib/services/scores"
import type { FindingSeverity } from "@/lib/db/schema"
import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"

const severityOrder: FindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
]

function scoreTone(score: number) {
  if (score >= 75) return "text-emerald-600 dark:text-emerald-400"
  if (score >= 50) return "text-amber-600 dark:text-amber-400"
  return "text-rose-600 dark:text-rose-400"
}

function barTone(score: number) {
  if (score >= 75) return "bg-emerald-500"
  if (score >= 50) return "bg-amber-500"
  return "bg-rose-500"
}

function Sparkline({ history }: { history: HealthScoreView["history"] }) {
  const points = history.slice(-12)
  if (points.length < 2) {
    return (
      <p className="text-[11px] text-muted-foreground">
        History appears after the score changes or a day passes.
      </p>
    )
  }

  return (
    <div className="flex h-10 items-end gap-1" aria-label="Score history">
      {points.map((point) => (
        <div
          key={point.computedAt.toISOString()}
          title={`${point.score}/100 · ${point.openFindingCount} open findings`}
          className={`min-h-1 w-full rounded-sm ${barTone(point.score)} opacity-80`}
          style={{ height: `${Math.max(point.score, 4)}%` }}
        />
      ))}
    </div>
  )
}

export function HealthScoreCard({
  health,
  title = "Workspace health",
}: {
  health: HealthScoreView
  title?: string
}) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{title}</CardDescription>
        <div className="flex items-baseline gap-2">
          <CardTitle
            className={`font-mono text-3xl ${health.scanned ? scoreTone(health.score) : ""}`}
          >
            {health.scanned ? health.score : "—"}
          </CardTitle>
          <Badge variant="outline" className="font-mono text-[10px]">
            {health.scanned ? `${health.algorithmVersion}` : "not scanned"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="gap-3">
        {!health.scanned ? (
          <p className="text-xs text-muted-foreground">
            Score starts after the first completed scan. It is computed from
            open findings only and is not a compliance certification.
          </p>
        ) : (
          <>
            <div className="space-y-1">
              <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                <div
                  className={`h-full rounded-full ${barTone(health.score)}`}
                  style={{ width: `${health.score}%` }}
                />
              </div>
              <div className="flex items-center justify-between font-mono text-[10px] text-muted-foreground">
                <span>
                  {health.openFindingCount} open finding
                  {health.openFindingCount === 1 ? "" : "s"}
                </span>
                <span>{health.riskPoints} risk points</span>
              </div>
            </div>

            <div className="space-y-1.5">
              {severityOrder.map((severity) => {
                const bucket = health.breakdown.bySeverity[severity]
                if (bucket.count === 0) return null
                return (
                  <div
                    key={severity}
                    className="flex items-center justify-between text-xs"
                  >
                    <span className="text-muted-foreground capitalize">
                      {severity}
                    </span>
                    <span className="font-mono text-[11px] text-muted-foreground">
                      {bucket.count} · {bucket.points} pts
                    </span>
                  </div>
                )
              })}
            </div>

            <div className="border-t border-border pt-2">
              <p className="mb-1.5 font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
                Trend
              </p>
              <Sparkline history={health.history} />
            </div>
          </>
        )}

        <details className="text-[11px] text-muted-foreground">
          <summary className="cursor-pointer select-none hover:text-foreground">
            How this score is calculated
          </summary>
          <div className="mt-2 space-y-1 leading-relaxed">
            <p>
              Base points: critical 25, high 15, medium 8, low 3, informational
              0 — one point score per finding row, so the same rule on the same
              asset counts once across repeated scans.
            </p>
            <p>
              Multipliers: exposure internet ×1.25, cloud ×1.1, internal ×1.0,
              source ×0.85; project criticality high ×1.2, medium ×1.0, low
              ×0.85.
            </p>
            <p>
              score = 100 − min(100, total risk points). Resolved, accepted-risk
              and false-positive findings do not count.
            </p>
          </div>
        </details>
      </CardContent>
    </Card>
  )
}
