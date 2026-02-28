"use client"

import Link from "next/link"
import Image from "next/image"
import { usePathname } from "next/navigation"
import { useState } from "react"
import {
  LayoutDashboard,
  Activity,
  GitBranch,
  Shield,
  Laptop,
  Settings,
  Heart,
  ShieldCheck,
  Bell,
  Globe,
  PanelLeftClose,
  PanelLeft,
} from "lucide-react"
import { useAppShell } from "./app-shell"

const navSections = [
  {
    label: "Overview",
    items: [
      { href: "/", label: "Dashboard", icon: LayoutDashboard },
      { href: "/live-traffic", label: "Live Traffic", icon: Activity },
      { href: "/threat-map", label: "Threat Intelligence", icon: Globe },
    ],
  },
  {
    label: "Security",
    items: [
      { href: "/threats", label: "Threats", icon: Shield },
      { href: "/flows", label: "Flows", icon: GitBranch },
      { href: "/ip-management", label: "IP Management", icon: ShieldCheck },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/alerting", label: "Alerting", icon: Bell },
      { href: "/endpoints", label: "Endpoints", icon: Laptop },
      { href: "/system-health", label: "System Health", icon: Heart },
    ],
  },
]

export function Sidebar() {
  const pathname = usePathname()
  const { sidebarCollapsed, setSidebarCollapsed } = useAppShell()
  const [imageError, setImageError] = useState(false)

  return (
    <aside
      className={`fixed left-0 top-0 h-screen bg-card border-r border-border flex flex-col z-30 transition-all duration-300 ease-in-out ${
        sidebarCollapsed ? "w-[72px]" : "w-[260px]"
      }`}
    >
      {/* Logo */}
      <div
        className={`h-20 flex items-center border-b border-border ${
          sidebarCollapsed ? "justify-center px-2 relative" : "justify-between px-4"
        }`}
      >
        <div className={`flex items-center min-w-0 ${sidebarCollapsed ? "gap-0" : "gap-3"}`}>
          {imageError ? (
            <div className="w-12 h-12 rounded-lg flex-shrink-0 bg-primary flex items-center justify-center">
              <Shield className="w-6 h-6 text-primary-foreground" />
            </div>
          ) : (
            <div className="w-12 h-12 flex-shrink-0 overflow-hidden rounded-lg">
              <Image
                src="/revenix.png"
                alt="Revenix Logo"
                width={48}
                height={48}
                className="w-full h-full object-cover scale-[1.25]"
                priority
                onError={() => setImageError(true)}
              />
            </div>
          )}
          {!sidebarCollapsed && (
            <div className="min-w-0">
              <h1 className="text-sm font-semibold text-foreground truncate">Revenix</h1>
              <p className="text-[10px] text-muted-foreground">AI Firewall</p>
            </div>
          )}
        </div>
        <button
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          className={`p-1.5 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground transition-colors flex-shrink-0 ${
            sidebarCollapsed ? "absolute right-2 top-1/2 -translate-y-1/2" : ""
          }`}
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? (
            <PanelLeft className="w-4 h-4" />
          ) : (
            <PanelLeftClose className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-3">
        {navSections.map((section) => (
          <div key={section.label} className="mb-4">
            {!sidebarCollapsed && (
              <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-widest px-3 mb-1.5">
                {section.label}
              </p>
            )}
            <div className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon
                const isActive = pathname === item.href

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    title={sidebarCollapsed ? item.label : undefined}
                    className={`flex items-center gap-3 rounded-lg transition-all duration-150 ${
                      sidebarCollapsed ? "justify-center px-0 py-2.5" : "px-3 py-2"
                    } ${
                      isActive
                        ? "bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-muted hover:text-foreground"
                    }`}
                  >
                    <Icon className={`w-[18px] h-[18px] flex-shrink-0 ${isActive ? "text-primary" : ""}`} />
                    {!sidebarCollapsed && (
                      <span className="text-[13px] font-medium">{item.label}</span>
                    )}
                  </Link>
                )
              })}
            </div>
          </div>
        ))}
      </nav>

      {/* Settings at bottom */}
      <div className="border-t border-border p-3">
        <Link
          href="/settings"
          title={sidebarCollapsed ? "Settings" : undefined}
          className={`flex items-center gap-3 rounded-lg transition-all duration-150 ${
            sidebarCollapsed ? "justify-center px-0 py-2.5" : "px-3 py-2"
          } ${
            pathname === "/settings"
              ? "bg-primary/10 text-primary"
              : "text-muted-foreground hover:bg-muted hover:text-foreground"
          }`}
        >
          <Settings className={`w-[18px] h-[18px] flex-shrink-0 ${pathname === "/settings" ? "text-primary" : ""}`} />
          {!sidebarCollapsed && <span className="text-[13px] font-medium">Settings</span>}
        </Link>
      </div>
    </aside>
  )
}
