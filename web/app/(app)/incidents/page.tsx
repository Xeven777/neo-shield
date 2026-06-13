import type { Metadata } from "next"

import { ComingSoon } from "@/components/coming-soon"
import { PageHeader } from "@/components/page-header"

export const metadata: Metadata = { title: "Incidents" }

export default function IncidentsPage() {
  return (
    <>
      <PageHeader
        title="Incidents"
        description="Deterministic correlation rules group related findings. Incidents always show why signals were associated — correlation never claims to prove an attack."
      />

      <ComingSoon
        title="No correlated incidents"
        phase="Phase 3"
        description="Incidents appear once findings from GitHub, domains, Wazuh and Nmap flow through the intelligence layer. Each incident will carry its correlation rule, timeline, evidence and status history."
      />
    </>
  )
}
