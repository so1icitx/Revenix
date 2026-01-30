"use client"

import type React from "react"
import { Component, type ErrorInfo, type ReactNode } from "react"
import { AlertTriangle, RefreshCw, Home } from "lucide-react"

interface Props { children: ReactNode; fallback?: ReactNode }
interface State { hasError: boolean; error: Error | null; errorInfo: ErrorInfo | null }

export class ErrorBoundary extends Component<Props, State> {
  public state: State = { hasError: false, error: null, errorInfo: null }

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[ErrorBoundary] Uncaught error:", error, errorInfo)
    this.setState({ errorInfo })
  }

  private handleRetry = () => { this.setState({ hasError: false, error: null, errorInfo: null }) }
  private handleGoHome = () => { window.location.href = "/" }

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback

      return (
        <div className="min-h-[400px] flex items-center justify-center p-8">
          <div className="bg-card border border-danger/20 rounded-xl p-8 max-w-lg w-full text-center">
            <div className="flex justify-center mb-4">
              <div className="p-3 bg-danger/10 rounded-full">
                <AlertTriangle className="h-6 w-6 text-danger" />
              </div>
            </div>
            <h2 className="text-lg font-semibold text-foreground mb-2">Something went wrong</h2>
            <p className="text-sm text-muted-foreground mb-6">An unexpected error occurred. Please try again or return to the dashboard.</p>
            {process.env.NODE_ENV === "development" && this.state.error && (
              <div className="bg-background rounded-lg p-4 mb-6 text-left overflow-auto max-h-40">
                <p className="text-danger text-sm font-mono">{this.state.error.toString()}</p>
                {this.state.errorInfo && <pre className="text-muted-foreground text-xs mt-2 whitespace-pre-wrap">{this.state.errorInfo.componentStack}</pre>}
              </div>
            )}
            <div className="flex gap-3 justify-center">
              <button onClick={this.handleRetry} className="flex items-center gap-2 px-4 py-2 bg-primary/10 hover:bg-primary/20 text-primary rounded-lg transition-colors text-sm font-medium">
                <RefreshCw className="h-4 w-4" /> Try Again
              </button>
              <button onClick={this.handleGoHome} className="flex items-center gap-2 px-4 py-2 bg-muted hover:bg-border-hover text-foreground rounded-lg transition-colors text-sm font-medium">
                <Home className="h-4 w-4" /> Dashboard
              </button>
            </div>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}

export function withErrorBoundary<P extends object>(WrappedComponent: React.ComponentType<P>, fallback?: ReactNode) {
  return function WithErrorBoundaryWrapper(props: P) {
    return <ErrorBoundary fallback={fallback}><WrappedComponent {...props} /></ErrorBoundary>
  }
}
