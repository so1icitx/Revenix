"use client"

import { useState, useEffect, useRef } from "react"
import { useRouter } from "next/navigation"
import {
  LayoutDashboard,
  Activity,
  Globe,
  Shield,
  GitBranch,
  ShieldCheck,
  Bell,
  Brain,
  Laptop,
  Heart,
  Settings,
  Search,
} from "lucide-react"
import { useAppShell } from "./app-shell"

const commands = [
  { id: "dashboard", label: "Dashboard", href: "/", icon: LayoutDashboard, section: "Navigation" },
  { id: "live-traffic", label: "Live Traffic", href: "/live-traffic", icon: Activity, section: "Navigation" },
  { id: "threat-map", label: "Threat Map", href: "/threat-map", icon: Globe, section: "Navigation" },
  { id: "threats", label: "Threats", href: "/threats", icon: Shield, section: "Navigation" },
  { id: "flows", label: "Flows", href: "/flows", icon: GitBranch, section: "Navigation" },
  { id: "ip-management", label: "IP Management", href: "/ip-management", icon: ShieldCheck, section: "Navigation" },
  { id: "alerting", label: "Alerting", href: "/alerting", icon: Bell, section: "Navigation" },
  { id: "ai-decisions", label: "AI Decisions", href: "/ai-decisions", icon: Brain, section: "Navigation" },
  { id: "endpoints", label: "Endpoints", href: "/endpoints", icon: Laptop, section: "Navigation" },
  { id: "system-health", label: "System Health", href: "/system-health", icon: Heart, section: "Navigation" },
  { id: "settings", label: "Settings", href: "/settings", icon: Settings, section: "Navigation" },
]

export function CommandPalette() {
  const { commandPaletteOpen, setCommandPaletteOpen } = useAppShell()
  const [query, setQuery] = useState("")
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const router = useRouter()

  const filteredCommands = commands.filter((cmd) =>
    cmd.label.toLowerCase().includes(query.toLowerCase())
  )

  useEffect(() => {
    if (commandPaletteOpen) {
      setQuery("")
      setSelectedIndex(0)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [commandPaletteOpen])

  useEffect(() => {
    setSelectedIndex(0)
  }, [query])

  const handleSelect = (href: string) => {
    setCommandPaletteOpen(false)
    router.push(href)
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault()
      setSelectedIndex((prev) => Math.min(prev + 1, filteredCommands.length - 1))
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      setSelectedIndex((prev) => Math.max(prev - 1, 0))
    } else if (e.key === "Enter" && filteredCommands[selectedIndex]) {
      handleSelect(filteredCommands[selectedIndex].href)
    }
  }

  if (!commandPaletteOpen) return null

  return (
    <div
      className="fixed inset-0 bg-black/60 z-50 flex items-start justify-center pt-[20vh]"
      onClick={() => setCommandPaletteOpen(false)}
    >
      <div
        className="w-full max-w-lg bg-card border border-border rounded-xl shadow-2xl shadow-black/50 overflow-hidden animate-fadeIn"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
          <Search className="w-4 h-4 text-muted-foreground flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search pages..."
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
          />
        </div>

        {/* Results */}
        <div className="max-h-80 overflow-y-auto py-2">
          {filteredCommands.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No results found
            </div>
          ) : (
            filteredCommands.map((cmd, idx) => {
              const Icon = cmd.icon
              return (
                <button
                  key={cmd.id}
                  onClick={() => handleSelect(cmd.href)}
                  className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
                    idx === selectedIndex
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-muted hover:text-foreground"
                  }`}
                >
                  <Icon className="w-4 h-4 flex-shrink-0" />
                  <span className="text-sm font-medium">{cmd.label}</span>
                </button>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
