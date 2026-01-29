/**
 * Time utilities with configurable timezone support
 * Timezone setting persists in localStorage and applies to all displays
 */

export type DateInput = Date | number | string | null | undefined

// Available timezone options
export const TIMEZONE_OPTIONS = [
  { value: 'local', label: 'Local Time (Browser)', zone: Intl.DateTimeFormat().resolvedOptions().timeZone },
  { value: 'UTC', label: 'UTC', zone: 'UTC' },
  { value: 'Europe/Sofia', label: 'Sofia (EET/EEST)', zone: 'Europe/Sofia' },
  { value: 'Europe/London', label: 'London (GMT/BST)', zone: 'Europe/London' },
  { value: 'America/New_York', label: 'New York (EST/EDT)', zone: 'America/New_York' },
  { value: 'America/Los_Angeles', label: 'Los Angeles (PST/PDT)', zone: 'America/Los_Angeles' },
  { value: 'Asia/Tokyo', label: 'Tokyo (JST)', zone: 'Asia/Tokyo' },
  { value: 'Asia/Singapore', label: 'Singapore (SGT)', zone: 'Asia/Singapore' },
] as const

export type TimezoneOption = typeof TIMEZONE_OPTIONS[number]['value']

const TIMEZONE_STORAGE_KEY = 'revenix_timezone'
const DEFAULT_TIMEZONE = 'local'
const DEFAULT_LOCALE = 'en-GB'

/**
 * Get the current timezone setting from localStorage
 */
export const getTimezone = (): string => {
  if (typeof window === 'undefined') return 'UTC'
  const saved = localStorage.getItem(TIMEZONE_STORAGE_KEY)
  if (!saved || saved === 'local') {
    return Intl.DateTimeFormat().resolvedOptions().timeZone
  }
  return saved
}

/**
 * Get the timezone setting value (including 'local')
 */
export const getTimezoneValue = (): TimezoneOption => {
  if (typeof window === 'undefined') return 'UTC'
  const saved = localStorage.getItem(TIMEZONE_STORAGE_KEY) as TimezoneOption
  return saved || DEFAULT_TIMEZONE
}

/**
 * Set the timezone preference
 */
export const setTimezone = (timezone: TimezoneOption): void => {
  if (typeof window === 'undefined') return
  localStorage.setItem(TIMEZONE_STORAGE_KEY, timezone)
  // Dispatch event so components can react to change
  window.dispatchEvent(new CustomEvent('timezone-changed', { detail: timezone }))
}

const normalizeDate = (value: DateInput): Date | null => {
  if (value === undefined || value === null) return null

  if (value instanceof Date) {
    return isNaN(value.getTime()) ? null : value
  }

  if (typeof value === 'number') {
    const timestampMs = value > 1e12 ? value : value * 1000
    const date = new Date(timestampMs)
    return isNaN(date.getTime()) ? null : date
  }

  const trimmed = String(value).trim()
  if (!trimmed) return null

  if (/^\d+(\.\d+)?$/.test(trimmed)) {
    const numeric = parseFloat(trimmed)
    if (!isFinite(numeric)) return null
    const timestampMs = numeric > 1e12 ? numeric : numeric * 1000
    const date = new Date(timestampMs)
    return isNaN(date.getTime()) ? null : date
  }

  const date = new Date(trimmed)
  return isNaN(date.getTime()) ? null : date
}

const formatWithOptions = (
  value: DateInput,
  baseOptions: Intl.DateTimeFormatOptions
): string => {
  const date = normalizeDate(value)
  if (!date) return 'Invalid date'

  const timezone = getTimezone()

  return new Intl.DateTimeFormat(DEFAULT_LOCALE, {
    timeZone: timezone,
    ...baseOptions
  }).format(date)
}

export const parseEpochSeconds = (value: DateInput): number | null => {
  const date = normalizeDate(value)
  if (!date) return null
  return date.getTime() / 1000
}

export const formatSofiaDateTime = (
  value: DateInput,
  options: Intl.DateTimeFormatOptions = {}
): string =>
  formatWithOptions(value, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    ...options
  })

export const formatSofiaTime = (
  value: DateInput,
  options: Intl.DateTimeFormatOptions = {}
): string =>
  formatWithOptions(value, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
    ...options
  })

export const formatSofiaDate = (
  value: DateInput,
  options: Intl.DateTimeFormatOptions = {}
): string =>
  formatWithOptions(value, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    ...options
  })

// Legacy export for compatibility
export const SOFIA_TIME_OPTIONS = {
  locale: DEFAULT_LOCALE,
  get timeZone() { return getTimezone() }
} as const

/**
 * Get current timezone label for display
 */
export const getCurrentTimezoneLabel = (): string => {
  const value = getTimezoneValue()
  const option = TIMEZONE_OPTIONS.find(o => o.value === value)
  return option?.label || value
}
