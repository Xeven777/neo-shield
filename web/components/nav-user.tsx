"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import {
  CaretUpDownIcon,
  GearSixIcon,
  SignOutIcon,
} from "@phosphor-icons/react"
import { toast } from "sonner"

import { authClient } from "@/lib/auth/auth-client"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

function initials(name: string) {
  return name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("")
}

export function NavUser({
  user,
  role,
}: {
  user: { name: string; email: string; image?: string | null }
  role: string
}) {
  const router = useRouter()
  const [signingOut, setSigningOut] = useState(false)

  async function signOut() {
    setSigningOut(true)
    const { error } = await authClient.signOut()
    if (error) {
      setSigningOut(false)
      toast.error(error.message ?? "Could not sign out.")
      return
    }
    router.push("/sign-in")
    router.refresh()
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={<Button variant="ghost" size="sm" className="gap-2 px-1.5" />}
      >
        <Avatar className="size-6">
          {user.image ? <AvatarImage src={user.image} alt="" /> : null}
          <AvatarFallback className="text-[10px]">
            {initials(user.name) || "NS"}
          </AvatarFallback>
        </Avatar>
        <span className="hidden max-w-32 truncate text-sm sm:inline">
          {user.name}
        </span>
        <CaretUpDownIcon className="size-3.5 text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="flex flex-col">
            <span className="truncate text-sm font-medium">{user.name}</span>
            <span className="truncate text-xs font-normal text-muted-foreground">
              {user.email}
            </span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem render={<a href="/settings" />}>
            <GearSixIcon />
            Workspace settings
          </DropdownMenuItem>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <div className="px-2 pb-1 font-mono text-[10px] tracking-wider text-muted-foreground uppercase">
          role: {role}
        </div>
        <DropdownMenuItem
          variant="destructive"
          disabled={signingOut}
          onClick={signOut}
        >
          <SignOutIcon />
          {signingOut ? "Signing out…" : "Sign out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
