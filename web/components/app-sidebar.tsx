"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import {
  FileTextIcon,
  FolderSimpleIcon,
  GearSixIcon,
  PlugsConnectedIcon,
  PulseIcon,
  ShieldCheckIcon,
  ShieldWarningIcon,
  SirenIcon,
  SquaresFourIcon,
  StackIcon,
} from "@phosphor-icons/react"

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
} from "@/components/ui/sidebar"
import { WorkerPill } from "@/components/worker-pill"

const navigation = [
  {
    label: "Monitor",
    items: [
      { title: "Overview", href: "/dashboard", icon: SquaresFourIcon },
      { title: "Assets", href: "/assets", icon: StackIcon },
      { title: "Scans", href: "/scans", icon: PulseIcon },
    ],
  },
  {
    label: "Security",
    items: [
      { title: "Findings", href: "/findings", icon: ShieldWarningIcon },
      { title: "Incidents", href: "/incidents", icon: SirenIcon },
      { title: "Reports", href: "/reports", icon: FileTextIcon },
    ],
  },
  {
    label: "Configure",
    items: [
      { title: "Projects", href: "/projects", icon: FolderSimpleIcon },
      {
        title: "Integrations",
        href: "/integrations",
        icon: PlugsConnectedIcon,
      },
      { title: "Settings", href: "/settings", icon: GearSixIcon },
    ],
  },
] as const

export function AppSidebar({
  workspaceName,
  workspaceSlug,
  onlineWorkers,
  totalWorkers,
}: {
  workspaceName: string
  workspaceSlug: string
  onlineWorkers: number
  totalWorkers: number
}) {
  const pathname = usePathname()

  const isActive = (href: string) =>
    pathname === href || pathname.startsWith(`${href}/`)

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              tooltip="NeoShield"
              render={<Link href="/dashboard" />}
            >
              <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <ShieldCheckIcon weight="fill" className="size-4.5" />
              </span>
              <span className="flex min-w-0 flex-col">
                <span className="truncate font-heading text-sm font-semibold">
                  NeoShield
                </span>
                <span className="truncate font-mono text-[10px] text-muted-foreground">
                  {workspaceSlug}
                </span>
              </span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {navigation.map((group) => (
          <SidebarGroup key={group.label}>
            <SidebarGroupLabel className="font-mono text-[10px] tracking-widest uppercase">
              {group.label}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {group.items.map((item) => (
                  <SidebarMenuItem key={item.href}>
                    <SidebarMenuButton
                      isActive={isActive(item.href)}
                      tooltip={item.title}
                      render={<Link href={item.href} />}
                    >
                      <item.icon />
                      <span>{item.title}</span>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>

      <SidebarFooter>
        <div className="px-2 pb-1 group-data-[collapsible=icon]:hidden">
          <WorkerPill online={onlineWorkers} total={totalWorkers} />
        </div>
        <div className="px-2 pb-2 group-data-[collapsible=icon]:hidden">
          <p className="truncate text-xs text-muted-foreground">
            {workspaceName}
          </p>
        </div>
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  )
}
