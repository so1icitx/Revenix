"use client"

import type React from "react"
import { useState, useEffect, createContext, useContext } from "react"
import { usePathname } from "next/navigation"
import { Sidebar } from "./sidebar"
import { TopBar } from "./top-bar"
import AuthGuard from "./auth-guard"
import { ErrorBoundary } from "./error-boundary"
import { CommandPalette } from "./command-palette"
import { API_URL } from "../lib/api-config"

interface AppShellContextType {
  sidebarCollapsed: boolean
  setSidebarCollapsed: (collapsed: boolean) => void
  commandPaletteOpen: boolean
  setCommandPaletteOpen: (open: boolean) => void
}

const AppShellContext = createContext<AppShellContextType>({
  sidebarCollapsed: false,
  setSidebarCollapsed: () => {},
  commandPaletteOpen: false,
  setCommandPaletteOpen: () => {},
})

export const useAppShell = () => useContext(AppShellContext)

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname()
  const isAuthPage = pathname?.startsWith("/auth")
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)

  useEffect(() => {
    const saved = localStorage.getItem("revenix_sidebar_collapsed")
    if (saved === "true") setSidebarCollapsed(true)
  }, [])

  useEffect(() => {
    const existingFetch = window.fetch.bind(window)
    const brainApiUrl = API_URL.replace(":8000", ":8001")

    const patchedFetch = async (input: RequestInfo | URL, init?: RequestInit) => {
      try {
        const requestUrl =
          typeof input === "string"
            ? input
            : input instanceof URL
              ? input.toString()
              : input.url

        const isInternalApiRequest =
          requestUrl.startsWith(API_URL) || requestUrl.startsWith(brainApiUrl)

        if (!isInternalApiRequest) {
          return existingFetch(input, init)
        }

        const token = sessionStorage.getItem("revenix_token")
        if (!token) {
          return existingFetch(input, init)
        }

        const headers = new Headers(init?.headers)
        if (!headers.has("Authorization")) {
          headers.set("Authorization", `Bearer ${token}`)
        }

        return existingFetch(input, { ...init, headers })
      } catch {
        return existingFetch(input, init)
      }
    }

    window.fetch = patchedFetch
    return () => {
      window.fetch = existingFetch
    }
  }, [])

  useEffect(() => {
    localStorage.setItem("revenix_sidebar_collapsed", String(sidebarCollapsed))
  }, [sidebarCollapsed])

  // Global keyboard shortcut for command palette
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        setCommandPaletteOpen((prev) => !prev)
      }
      if (e.key === "Escape") {
        setCommandPaletteOpen(false)
      }
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [])

  if (isAuthPage) {
    return (
      <ErrorBoundary>
        {children}
      </ErrorBoundary>
    )
  }

  return (
    <AppShellContext.Provider
      value={{ sidebarCollapsed, setSidebarCollapsed, commandPaletteOpen, setCommandPaletteOpen }}
    >
      <ErrorBoundary>
        <AuthGuard>
          <div className="flex h-screen overflow-hidden">
            <Sidebar />
            <div
              className={`flex-1 flex flex-col min-w-0 transition-all duration-300 ease-in-out ${
                sidebarCollapsed ? "ml-[72px]" : "ml-[260px]"
              }`}
            >
              <TopBar />
              <main className="flex-1 overflow-y-auto">
                <ErrorBoundary>{children}</ErrorBoundary>
              </main>
            </div>
          </div>
          <CommandPalette />
        </AuthGuard>
      </ErrorBoundary>
    </AppShellContext.Provider>
  )
}
