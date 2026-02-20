/**
 * Tests for ErrorBoundary component
 */

import { render, screen, fireEvent } from "@testing-library/react"
import { ErrorBoundary } from "../components/error-boundary"

// Component that throws an error
function ThrowError({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) {
    throw new Error("Test error message")
  }
  return <div>No error</div>
}

describe("ErrorBoundary", () => {
  // Suppress console.error for cleaner test output
  const originalError = console.error
  beforeAll(() => {
    console.error = jest.fn()
  })
  afterAll(() => {
    console.error = originalError
  })

  it("renders children when no error", () => {
    render(
      <ErrorBoundary>
        <div>Test content</div>
      </ErrorBoundary>,
    )

    expect(screen.getByText("Test content")).toBeInTheDocument()
  })

  it("renders error UI when child throws", () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>,
    )

    expect(screen.getByText("Something went wrong")).toBeInTheDocument()
    expect(screen.getByText("Try Again")).toBeInTheDocument()
    expect(screen.getByText("Dashboard")).toBeInTheDocument()
  })

  it("renders custom fallback when provided", () => {
    render(
      <ErrorBoundary fallback={<div>Custom error UI</div>}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>,
    )

    expect(screen.getByText("Custom error UI")).toBeInTheDocument()
  })

  it("resets error state on retry", () => {
    const { rerender } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>,
    )

    // Should show error UI
    expect(screen.getByText("Something went wrong")).toBeInTheDocument()

    // Rerender without throwing
    rerender(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>,
    )

    // Click retry after the child is safe again
    fireEvent.click(screen.getByText("Try Again"))

    // Should show normal content
    expect(screen.getByText("No error")).toBeInTheDocument()
  })
})
