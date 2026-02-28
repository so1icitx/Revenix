"use client"

import { API_URL } from '../../../lib/api-config'
import type React from "react"
import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { Shield, CheckCircle, Loader2 } from "lucide-react"
import { setCurrentUser } from "../../../lib/auth"
import Image from "next/image"

export default function SignupPage() {
  const [formData, setFormData] = useState({ username: "", email: "", password: "", full_name: "" })
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [success, setSuccess] = useState(false)
  const [imageError, setImageError] = useState(false)
  const [checkingSignup, setCheckingSignup] = useState(true)
  const [signupEnabled, setSignupEnabled] = useState(false)
  const router = useRouter()

  useEffect(() => {
    let cancelled = false

    if (typeof window !== "undefined") {
      sessionStorage.removeItem("revenix_user")
      sessionStorage.removeItem("revenix_token")
    }

    const verifySignupAvailability = async () => {
      try {
        const response = await fetch(`${API_URL}/auth/check-users`, {
          method: "GET",
          cache: "no-store",
        })

        if (!response.ok) {
          throw new Error("Failed to verify account setup state")
        }

        const data = await response.json()
        const hasUsers = (data.user_count || 0) > 0
        if (cancelled) return

        if (hasUsers) {
          setSignupEnabled(false)
          router.replace("/auth/login")
          return
        }

        setSignupEnabled(true)
      } catch {
        if (!cancelled) {
          setSignupEnabled(false)
          setError("Signup is unavailable. Please sign in.")
        }
      } finally {
        if (!cancelled) {
          setCheckingSignup(false)
        }
      }
    }

    verifySignupAvailability()
    return () => {
      cancelled = true
    }
  }, [router])

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!signupEnabled) {
      setError("Signup is disabled after initial setup. Please sign in.")
      return
    }
    setError("")
    setLoading(true)
    try {
      const response = await fetch(`${API_URL}/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(formData),
      })
      if (response.ok) {
        const data = await response.json()
        setCurrentUser({ username: data.user.username, email: formData.email, full_name: formData.full_name }, data.access_token)
        setSuccess(true)
        setTimeout(() => router.push("/"), 1500)
      } else {
        const errorData = await response.json()
        setError(errorData.detail || "Signup failed")
      }
    } catch (err) {
      setError("Connection error. Make sure the API server is running.")
    } finally {
      setLoading(false)
    }
  }

  if (checkingSignup) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-full max-w-sm p-6 text-center">
          <Loader2 className="w-6 h-6 animate-spin mx-auto text-primary mb-3" />
          <p className="text-sm text-muted-foreground">Checking setup status...</p>
        </div>
      </div>
    )
  }

  if (!signupEnabled) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-full max-w-sm p-6 text-center card-surface">
          <h1 className="text-lg font-semibold text-foreground mb-2">Signup Disabled</h1>
          <p className="text-sm text-muted-foreground mb-4">
            An admin account already exists. Use sign in to access the dashboard.
          </p>
          <a
            href="/auth/login"
            className="inline-block px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-medium hover:bg-primary/90 transition"
          >
            Go to Sign In
          </a>
        </div>
      </div>
    )
  }

  if (success) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="w-full max-w-sm p-6 text-center">
          <div className="inline-block p-3 bg-safe/10 rounded-full mb-5">
            <CheckCircle className="w-12 h-12 text-safe" />
          </div>
          <h1 className="text-xl font-semibold text-foreground mb-1">Account Created</h1>
          <p className="text-sm text-muted-foreground mb-3">Welcome to Revenix, {formData.full_name}!</p>
          <p className="text-xs text-muted-foreground">Redirecting to dashboard...</p>
          <div className="mt-4 w-full bg-muted rounded-full h-0.5 overflow-hidden">
            <div className="h-full bg-primary rounded-full" style={{ width: "100%", animation: "fadeIn 1.5s ease-out" }} />
          </div>
        </div>
      </div>
    )
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
                <Image src="/revenix.png" alt="Revenix Logo" fill sizes="64px" className="object-cover scale-[1.25]" priority onError={() => setImageError(true)} />
              </div>
            </div>
          )}
          <h1 className="text-2xl font-semibold text-foreground">Revenix</h1>
          <p className="text-sm text-muted-foreground mt-1">Create Admin Account</p>
        </div>

        <div className="card-surface p-6">
          <h2 className="text-lg font-semibold text-foreground mb-5">First Time Setup</h2>

          {error && (
            <div className="mb-4 p-3 bg-danger/10 border border-danger/20 rounded-lg text-sm text-danger">{error}</div>
          )}

          <form onSubmit={handleSignup} className="space-y-4">
            {[
              { label: "Username", type: "text", key: "username" },
              { label: "Email", type: "email", key: "email" },
              { label: "Full Name", type: "text", key: "full_name" },
              { label: "Password", type: "password", key: "password" },
            ].map((field) => (
              <div key={field.key}>
                <label className="block text-xs font-medium text-muted-foreground mb-1.5 uppercase tracking-wider">{field.label}</label>
                <input
                  type={field.type}
                  value={formData[field.key as keyof typeof formData]}
                  onChange={(e) => setFormData({ ...formData, [field.key]: e.target.value })}
                  className="w-full px-3 py-2 bg-muted border border-border rounded-lg text-foreground focus:outline-none focus:border-primary transition-colors"
                  required
                  disabled={loading}
                  minLength={field.key === "password" ? 6 : undefined}
                />
              </div>
            ))}
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 bg-primary text-primary-foreground font-medium rounded-lg hover:bg-primary/90 transition disabled:opacity-50 flex items-center justify-center gap-2 text-sm"
            >
              {loading ? <><Loader2 className="w-4 h-4 animate-spin" /> Creating...</> : "Create Admin Account"}
            </button>
          </form>

          <div className="mt-5 text-center">
            <p className="text-xs text-muted-foreground">
              Already have an account?{" "}
              <a href="/auth/login" className="text-primary hover:underline font-medium">
                Sign In
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}
