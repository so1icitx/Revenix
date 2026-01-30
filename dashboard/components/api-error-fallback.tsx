"use client"

import { AlertCircle, RefreshCw, WifiOff } from "lucide-react"

interface ApiErrorFallbackProps { error: Error | string; onRetry?: () => void; title?: string }

export function ApiErrorFallback({ error, onRetry, title = "Failed to load data" }: ApiErrorFallbackProps) {
  const errorMessage = typeof error === "string" ? error : error.message
  const isNetworkError = errorMessage.toLowerCase().includes("network") || errorMessage.toLowerCase().includes("fetch") || errorMessage.toLowerCase().includes("connection")

  return (
    <div className="bg-card border border-danger/20 rounded-xl p-5">
      <div className="flex items-start gap-3">
        <div className="p-2 bg-danger/10 rounded-lg shrink-0">
          {isNetworkError ? <WifiOff className="h-4 w-4 text-danger" /> : <AlertCircle className="h-4 w-4 text-danger" />}
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-medium text-foreground mb-0.5">{title}</h3>
          <p className="text-xs text-muted-foreground mb-3 break-words">
            {isNetworkError ? "Unable to connect to the API. Please check if the backend services are running." : errorMessage}
          </p>
          {onRetry && (
            <button onClick={onRetry} className="flex items-center gap-1.5 px-3 py-1.5 bg-primary/10 hover:bg-primary/20 text-primary text-xs rounded-lg transition-colors font-medium">
              <RefreshCw className="h-3 w-3" /> Retry
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

export function DataLoadingSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-3 animate-pulse">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="bg-card rounded-xl p-4">
          <div className="h-4 bg-muted rounded w-3/4 mb-2" />
          <div className="h-3 bg-muted rounded w-1/2" />
        </div>
      ))}
    </div>
  )
}
