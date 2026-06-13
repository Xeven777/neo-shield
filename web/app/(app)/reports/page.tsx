import type { Metadata } from "next"

import { ComingSoon } from "@/components/coming-soon"
import { PageHeader } from "@/components/page-header"

export const metadata: Metadata = { title: "Reports" }

export default function ReportsPage() {
  return (
    <>
      <PageHeader
        title="Reports"
        description="Project security summaries with score breakdown, open findings and remediation history. Exports start with CSV/JSON."
      />

      <ComingSoon
        title="Reports are generated from findings"
        phase="Phase 3 / 5"
        description="A report needs completed scans and an explainable score before it is meaningful. Once Phase 1 lands, summaries will show per-project severity breakdown and score provenance."
      />
    </>
  )
}
