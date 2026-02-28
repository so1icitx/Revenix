"use client"

import { API_URL } from '../../../lib/api-config'
import type React from "react"
import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { Shield, AlertCircle, Loader2 } from "lucide-react"
import { setCurrentUser } from "../../../lib/auth"
import Image from "next/image"

export default function LoginPage() {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [retryAfter, setRetryAfter] = useState(0)
  const [imageError, setImageError] = useState(false)
  const [canCreateFirstAccount, setCanCreateFirstAccount] = useState(false)
  const router = useRouter()

  useEffect(() => {
    let cancelled = false

    if (typeof window !== "undefined") {
      sessionStorage.removeItem("revenix_user")
      sessionStorage.removeItem("revenix_token")
    }

    const fetchSignupAvailability = async () => {
      try {
        const response = await fetch(`${API_URL}/auth/check-users`, {
          method: "GET",
          cache: "no-store",
        })
        if (!response.ok) return

        const data = await response.json()
        if (!cancelled) {
          setCanCreateFirstAccount((data.user_count || 0) === 0)
        }
      } catch {
        // Keep signup hidden when availability check fails.
      }
    }

    fetchSignupAvailability()
    return () => {
      cancelled = true
    }
  }, [])

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      })
      if (response.ok) {
        const data = await response.json()
        setCurrentUser(
          { username: data.user.username, email: data.user.email || `${data.user.username}@revenix.local`, full_name: data.user.full_name || data.user.username },
          data.access_token,
        )
        router.push("/")
      } else if (response.status === 429) {
        const retryHeader = response.headers.get("Retry-After")
        const seconds = retryHeader ? Number.parseInt(retryHeader) : 30
        setRetryAfter(seconds)
        setError(`Too many attempts. Please wait ${seconds} seconds.`)
        const interval = setInterval(() => {
          setRetryAfter((prev) => { if (prev <= 1) { clearInterval(interval); setError(""); return 0 } return prev - 1 })
        }, 1000)
      } else {
        const errorData = await response.json()
        setError(errorData.detail || "Login failed")
      }
    } catch (err) {
      setError("Connection error. Make sure the API server is running.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="w-full max-w-sm p-6">
        <div className="text-center mb-8">
          {imageError ? (
            <div className="inline-flex w-16 h-16 items-center justify-center bg-card rounded-xl mb-4 border border-border">
              <Shield className="w-9 h-9 text-primary" />
            </div>
          ) : (
            <div className="inline-block mb-4">
              <div className="relative w-16 h-16 rounded-xl overflow-hidden">
              <Image
                src="/revenix.png"
                alt="Revenix Logo"
                fill
                sizes="64px"
                className="object-cover scale-[1.25]"
                priority
                onError={() => setImageError(true)}
              />
              </div>
            </div>
          )}
          <h1 className="text-2xl font-semibold text-foreground">Revenix</h1>
          <p className="text-sm text-muted-foreground mt-1">AI Firewall System</p>
        </div>

        <div className="card-surface p-6">
          <h2 className="text-lg font-semibold text-foreground mb-5">Sign In</h2>

          {error && (
            <div className="mb-4 p-3 bg-danger/10 border border-danger/20 rounded-lg text-sm text-danger flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span className="flex-1">{error}</span>
              {retryAfter > 0 && (
                <span className="font-mono text-xs bg-danger/20 px-2 py-0.5 rounded">{retryAfter}s</span>
              )}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-foreground focus:outline-none focus:border-primary transition-colors"
                required
                disabled={loading || retryAfter > 0}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-foreground focus:outline-none focus:border-primary transition-colors"
                required
                disabled={loading || retryAfter > 0}
              />
            </div>
            <button
              type="submit"
              disabled={loading || retryAfter > 0}
              className="w-full py-2.5 bg-primary text-primary-foreground font-medium rounded-lg hover:bg-primary/90 transition disabled:opacity-50 flex items-center justify-center gap-2 text-sm"
            >
              {loading ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Signing in...</>
              ) : retryAfter > 0 ? (
                `Wait ${retryAfter}s`
              ) : (
                "Sign In"
              )}
            </button>
          </form>

          {canCreateFirstAccount && (
            <div className="mt-5 text-center">
              <p className="text-xs text-muted-foreground">
                First-time setup:{" "}
                <a href="/auth/signup" className="text-primary hover:underline font-medium">
                  Create Admin Account
                </a>
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
