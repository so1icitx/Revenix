"use client"

import { API_URL } from "../lib/api-config"
import { useEffect, useState, useRef } from "react"
import { usePathname } from "next/navigation"
import {
  Bell,
  Shield,
  AlertCircle,
  ChevronDown,
  LogOut,
  Settings,
  Play,
  Square,
  CheckCircle,
  Search,
  Command,
} from "lucide-react"
import { formatSofiaTime } from "../lib/time"
import { getCurrentUser, logout } from "../lib/auth"
import { useAppShell } from "./app-shell"

interface SystemStatus {
  learning_phase: "idle" | "learning" | "active"
  flows_collected: number
  training_threshold: number
  is_trained: boolean
}

export function TopBar() {
  const [lastSync, setLastSync] = useState<Date>(new Date())
  const [showNotifications, setShowNotifications] = useState(false)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [alerts, setAlerts] = useState<any[]>([])
  const [user, setUser] = useState<{ username: string; email: string } | null>(null)
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    learning_phase: "idle",
    flows_collected: 0,
    training_threshold: 200,
    is_trained: false,
  })
  const [isToggling, setIsToggling] = useState(false)
  const notificationRef = useRef<HTMLDivElement>(null)
  const userMenuRef = useRef<HTMLDivElement>(null)
  const pathname = usePathname()
  const isAuthPage = pathname?.startsWith("/auth")
  const { setCommandPaletteOpen } = useAppShell()

  useEffect(() => {
    const interval = setInterval(() => setLastSync(new Date()), 2000)
    return () => clearInterval(interval)
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
    const fetchSystemStatus = async () => {
      try {
        const response = await fetch(`${API_URL}/system/learning-status`)
        if (response.ok) setSystemStatus(await response.json())
      } catch (error) {
        // Silent fail
      }
    }
    fetchSystemStatus()
    const interval = setInterval(fetchSystemStatus, 3000)
    return () => clearInterval(interval)
  }, [user, isAuthPage])

  useEffect(() => {
    if (!user || isAuthPage) return
    const fetchAlerts = async () => {
      try {
        const response = await fetch(`${API_URL}/alerts/recent`)
        if (response.ok) {
          const data = await response.json()
          setAlerts(data.slice(0, 5))
        }
      } catch (error) {
        // Silent fail
      }
    }
    fetchAlerts()
    const interval = setInterval(fetchAlerts, 10000)
    return () => clearInterval(interval)
  }, [user, isAuthPage])

  const handleToggleLearning = async () => {
    if (isToggling) return
    setIsToggling(true)
    try {
      if (systemStatus.learning_phase === "idle") {
        const response = await fetch(`${API_URL}/system/start-learning`, { method: "POST" })
        if (response.ok) setSystemStatus((prev) => ({ ...prev, learning_phase: "learning" }))
      } else if (systemStatus.learning_phase === "learning") {
        const response = await fetch(`${API_URL}/system/stop-learning`, { method: "POST" })
        if (response.ok) setSystemStatus((prev) => ({ ...prev, learning_phase: "active", is_trained: true }))
      }
    } catch (error) {
      console.error("Failed to toggle learning:", error)
    } finally {
      setIsToggling(false)
    }
  }

  const handleLogout = () => {
    logout()
    setUser(null)
    window.location.href = "/auth/login"
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

  const getStatusIndicator = () => {
    switch (systemStatus.learning_phase) {
      case "idle": return { color: "bg-muted-foreground", label: "Idle" }
      case "learning": return { color: "bg-warning", label: `Learning (${systemStatus.flows_collected}/${systemStatus.training_threshold})` }
      case "active": return { color: "bg-safe", label: "Protected" }
      default: return { color: "bg-muted-foreground", label: "Unknown" }
    }
  }

  if (isAuthPage) return null
  const status = getStatusIndicator()

  return (
    <header className="h-14 bg-card border-b border-border flex items-center justify-between px-5 flex-shrink-0">
      {/* Left side */}
      <div className="flex items-center gap-4">
        {user && (
          <div className="flex items-center gap-2.5 px-3 py-1.5 bg-muted rounded-lg">
            <div className={`w-1.5 h-1.5 rounded-full ${status.color}`} />
            <span className="text-xs text-muted-foreground">{status.label}</span>

            {systemStatus.learning_phase === "idle" && (
              <button
                onClick={handleToggleLearning}
                disabled={isToggling}
                className="flex items-center gap-1 px-2 py-0.5 bg-primary hover:bg-primary/90 text-primary-foreground rounded text-[11px] font-medium transition disabled:opacity-50 ml-1"
              >
                <Play className="w-2.5 h-2.5" />
                Start
              </button>
            )}
            {systemStatus.learning_phase === "learning" && (
              <button
                onClick={handleToggleLearning}
                disabled={isToggling}
                className="flex items-center gap-1 px-2 py-0.5 bg-safe hover:bg-safe/90 text-background rounded text-[11px] font-medium transition disabled:opacity-50 ml-1"
              >
                <Square className="w-2.5 h-2.5" />
                Activate
              </button>
            )}
            {systemStatus.learning_phase === "active" && (
              <span className="flex items-center gap-1 px-2 py-0.5 bg-safe/10 rounded text-[11px] text-safe font-medium ml-1">
                <CheckCircle className="w-2.5 h-2.5" />
                Active
              </span>
            )}
          </div>
        )}
      </div>

      {/* Right side */}
      <div className="flex items-center gap-2">
        {/* Command palette trigger */}
        <button
          onClick={() => setCommandPaletteOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-muted hover:bg-border-hover rounded-lg text-muted-foreground hover:text-foreground transition-colors text-xs"
        >
          <Search className="w-3.5 h-3.5" />
          <span className="hidden lg:inline">Search</span>
          <kbd className="hidden lg:flex items-center gap-0.5 px-1.5 py-0.5 bg-background rounded text-[10px] text-muted-foreground border border-border">
            <Command className="w-2.5 h-2.5" />K
          </kbd>
        </button>

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
                <div className="p-4 border-b border-border">
                  <h3 className="text-sm font-semibold text-foreground">Alerts</h3>
                  <p className="text-[11px] text-muted-foreground">{alerts.length} recent</p>
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
