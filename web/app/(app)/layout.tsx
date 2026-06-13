import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/app-sidebar"
import { NavUser } from "@/components/nav-user"
import { ThemeToggle } from "@/components/theme-toggle"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { requireWorkspace } from "@/lib/auth/session"
import { listWorkers, isWorkerOnline } from "@/lib/services/workers"

// Every screen in this segment depends on the signed-in session.
export const dynamic = "force-dynamic"

export default async function AppLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { session, workspace, role } = await requireWorkspace()
  const workers = await listWorkers(workspace.id)
  const onlineWorkers = workers.filter((worker) => isWorkerOnline(worker)).length

  return (
    <SidebarProvider>
      <AppSidebar
        workspaceName={workspace.name}
        workspaceSlug={workspace.slug}
        onlineWorkers={onlineWorkers}
        totalWorkers={workers.filter((worker) => worker.status === "active").length}
      />
      <SidebarInset>
        <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background/85 px-3 backdrop-blur-sm">
          <SidebarTrigger />
          <Separator orientation="vertical" className="mr-1 h-4" />
          <div className="flex min-w-0 items-center gap-2">
            <span className="truncate text-sm font-medium">{workspace.name}</span>
            <Badge variant="outline" className="font-mono text-[10px]">
              {role}
            </Badge>
            <Badge
              variant="outline"
              className="hidden font-mono text-[10px] text-muted-foreground sm:inline-flex"
            >
              phase 1
            </Badge>
          </div>
          <div className="ml-auto flex items-center gap-1.5">
            <ThemeToggle />
            <NavUser
              user={{
                name: session.user.name,
                email: session.user.email,
                image: session.user.image,
              }}
              role={role}
            />
          </div>
        </header>
        <div className="flex min-w-0 flex-1 flex-col px-4 py-6 md:px-8 md:py-8">
          {children}
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
