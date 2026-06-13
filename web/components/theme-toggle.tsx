"use client"

import { useTheme } from "next-themes"
import { MoonIcon, SunIcon } from "@phosphor-icons/react"

import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"

export function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Toggle theme"
            onClick={() =>
              setTheme(resolvedTheme === "dark" ? "light" : "dark")
            }
          />
        }
      >
        {/* CSS-only switching avoids a hydration mismatch and a mount effect. */}
        <SunIcon className="hidden dark:block" />
        <MoonIcon className="block dark:hidden" />
      </TooltipTrigger>
      <TooltipContent>Toggle theme (d)</TooltipContent>
    </Tooltip>
  )
}
