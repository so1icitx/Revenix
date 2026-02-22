"use client"

import { API_URL } from "../lib/api-config"
import { useEffect, useState, useRef } from "react"
import { usePathname } from "next/navigation"
import {
  Bell,
  AlertCircle,
  ChevronDown,
  LogOut,
  Settings,
  Search,
  Command,
  Clock3,
} from "lucide-react"
import { formatSofiaTime } from "../lib/time"
import { getCurrentUser, logout } from "../lib/auth"
import { useAppShell } from "./app-shell"

const CLEARED_ALERTS_STORAGE_KEY = "revenix_alerts_cleared_before"

export function TopBar() {
  const [lastSync, setLastSync] = useState<Date>(new Date())
  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [alerts, setAlerts] = useState<any[]>([])
  const [user, setUser] = useState<{ username: string; email: string } | null>(null)
  const [clearedAlertsBefore, setClearedAlertsBefore] = useState<number>(0)
  const notificationRef = useRef<HTMLDivElement>(null)
  const userMenuRef = useRef<HTMLDivElement>(null)
  const pathname = usePathname()
  const isAuthPage = pathname?.startsWith("/auth")
  const { setCommandPaletteOpen } = useAppShell()

  useEffect(() => {
    const interval = setInterval(() => setLastSync(new Date()), 1000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const stored = window.localStorage.getItem(CLEARED_ALERTS_STORAGE_KEY)
    if (!stored) return
    const parsed = Number(stored)
    if (!Number.isFinite(parsed) || parsed <= 0) return
    setClearedAlertsBefore(parsed)
  }, [])

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (notificationRef.current && !notificationRef.current.contains(event.target as Node)) {
        setShowNotifications(false)
      }
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false)
      }
    }
    document.addEventListener("mousedown", handleClickOutside)
    return () => document.removeEventListener("mousedown", handleClickOutside)
  }, [])

  useEffect(() => {
    const updateUser = () => {
      const currentUser = getCurrentUser()
      setUser(currentUser)
    }
    updateUser()
    window.addEventListener("storage", updateUser)
    const interval = setInterval(updateUser, 1000)
    return () => {
      window.removeEventListener("storage", updateUser)
      clearInterval(interval)
    }
  }, [pathname])

  useEffect(() => {
    if (!user || isAuthPage) return
    const fetchAlerts = async () => {
      try {
        const response = await fetch(`${API_URL}/alerts/recent?limit=25`)
        if (response.ok) {
          const data = await response.json()
          const filtered = data.filter((alert: any) => {
            const ts = Number(alert?.timestamp || 0)
            return clearedAlertsBefore === 0 || ts > clearedAlertsBefore
          })
          setAlerts(filtered.slice(0, 5))
        }
      } catch (error) {
        // Silent fail
      }
    }
    fetchAlerts()
    const interval = setInterval(fetchAlerts, 10000)
    return () => clearInterval(interval)
  }, [user, isAuthPage, clearedAlertsBefore])

  const handleLogout = () => {
    logout()
    setUser(null)
    window.location.href = "/auth/login"
  }

  const handleClearNotifications = () => {
    const clearTs = Math.floor(Date.now() / 1000)
    setClearedAlertsBefore(clearTs)
    setAlerts([])
    window.localStorage.setItem(CLEARED_ALERTS_STORAGE_KEY, String(clearTs))
  }

  const getSeverityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case "critical": return "text-severity-critical"
      case "high": return "text-severity-high"
      case "medium": return "text-severity-medium"
      case "low": return "text-severity-low"
      default: return "text-muted-foreground"
    }
  }

  if (isAuthPage) return null

  return (
    <header className="h-14 bg-card border-b border-border flex items-center justify-between px-5 flex-shrink-0 gap-4">
      {/* Left side */}
      <div className="flex-1 min-w-0">
        <button
          onClick={() => setCommandPaletteOpen(true)}
          className="w-full max-w-[560px] flex items-center justify-between gap-3 px-4 py-2 bg-muted hover:bg-border-hover rounded-lg text-muted-foreground hover:text-foreground transition-colors text-sm"
        >
          <div className="flex items-center gap-2 min-w-0">
            <Search className="w-4 h-4 flex-shrink-0" />
            <span className="truncate text-left">Search pages, threats, flows...</span>
          </div>
          <kbd className="hidden lg:flex items-center gap-0.5 px-1.5 py-0.5 bg-background rounded text-[10px] text-muted-foreground border border-border flex-shrink-0">
            <Command className="w-2.5 h-2.5" />K
          </kbd>
        </button>
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2">
        <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 bg-muted rounded-lg text-xs text-muted-foreground font-mono">
          <Clock3 className="w-3.5 h-3.5" />
          <span>{formatSofiaTime(lastSync)}</span>
        </div>

        {/* Notifications */}
        {user && (
          <div className="relative" ref={notificationRef}>
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="relative p-2 hover:bg-muted rounded-lg transition-colors text-muted-foreground hover:text-foreground"
            >
              <Bell className="w-4 h-4" />
              {alerts.length > 0 && (
                <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 bg-danger rounded-full" />
              )}
            </button>

            {showNotifications && (
              <div className="absolute top-full right-0 mt-2 w-80 bg-card border border-border rounded-xl shadow-2xl shadow-black/50 overflow-hidden z-50 animate-fadeIn">
                <div className="p-4 border-b border-border flex items-center justify-between gap-2">
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">Alerts</h3>
                    <p className="text-[11px] text-muted-foreground">{alerts.length} recent</p>
                  </div>
                  <button
                    onClick={handleClearNotifications}
                    disabled={alerts.length === 0}
                    className="px-2.5 py-1 text-[11px] font-medium bg-muted hover:bg-border-hover text-muted-foreground hover:text-foreground rounded-md transition-colors disabled:opacity-50"
                  >
                    Clear
                  </button>
                </div>
                {alerts.length === 0 ? (
                  <div className="p-8 text-center text-muted-foreground text-sm">No alerts</div>
                ) : (
                  <div className="max-h-80 overflow-y-auto">
                    {alerts.map((alert: any) => (
                      <div key={alert.id} className="p-3 border-b border-border hover:bg-muted/50 transition-colors">
                        <div className="flex items-start gap-2.5">
                          <AlertCircle className={`w-4 h-4 ${getSeverityColor(alert.severity)} flex-shrink-0 mt-0.5`} />
                          <div className="flex-1 min-w-0">
                            <p className="text-xs font-medium text-foreground">
                              {alert.severity?.toUpperCase()} - {alert.src_ip}
                            </p>
                            <p className="text-[11px] text-muted-foreground line-clamp-2 mt-0.5">{alert.reason}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
                <div className="p-2.5 border-t border-border text-center">
                  <a href="/threats" className="text-xs text-primary hover:text-primary/80 font-medium">
                    View All
                  </a>
                </div>
              </div>
            )}
          </div>
        )}

        {/* User menu */}
        {user && (
          <div className="relative" ref={userMenuRef}>
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center gap-2 hover:bg-muted rounded-lg px-2 py-1.5 transition-colors"
            >
              <div className="w-7 h-7 bg-primary rounded-full flex items-center justify-center">
                <span className="text-xs font-semibold text-primary-foreground">
                  {user.username.charAt(0).toUpperCase()}
                </span>
              </div>
              <ChevronDown className={`w-3 h-3 text-muted-foreground transition-transform ${showUserMenu ? "rotate-180" : ""}`} />
            </button>

            {showUserMenu && (
              <div className="absolute top-full right-0 mt-2 w-48 bg-card border border-border rounded-xl shadow-2xl shadow-black/50 overflow-hidden z-50 animate-fadeIn">
                <div className="p-3 border-b border-border">
                  <p className="text-sm font-medium text-foreground">{user.username}</p>
                  <p className="text-[11px] text-muted-foreground">{user.email}</p>
                </div>
                <div className="py-1">
                  <a href="/settings" className="flex items-center gap-2 px-3 py-2 text-sm text-muted-foreground hover:bg-muted hover:text-foreground transition-colors">
                    <Settings className="w-3.5 h-3.5" />
                    Settings
                  </a>
                  <button
                    onClick={handleLogout}
                    className="flex items-center gap-2 px-3 py-2 text-sm text-danger hover:bg-muted transition-colors w-full"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </header>
  )
}
