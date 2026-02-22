'use client'

import { API_URL } from '../../lib/api-config'
import { useEffect, useMemo, useState } from 'react'
import { RefreshCw, Globe2 } from 'lucide-react'
import { formatSofiaDateTime } from '../../lib/time'

interface CountryThreat {
  country: string
  country_code: string
  count: number
  critical: number
  high: number
  medium: number
  low: number
  top_categories: [string, number][]
  example_ips: string[]
}

interface TopCountriesResponse {
  generated_at: string
  lookback_hours: number
  sampled_alerts: number
  countries: CountryThreat[]
  error?: string
}

const LOOKBACK_OPTIONS = [1, 6, 24, 72]

export default function ThreatMapPage() {
  const [data, setData] = useState<TopCountriesResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [lookbackHours, setLookbackHours] = useState(24)

  const fetchTopCountries = async () => {
    setLoading(true)
    try {
      const response = await fetch(
        `${API_URL}/threats/top-countries?lookback_hours=${lookbackHours}&limit=15&sample_size=400`
      )
      if (!response.ok) throw new Error('Failed to fetch threat countries')
      const payload = await response.json()
      setData(payload)
    } catch (error) {
      console.error('[ThreatCountries] Fetch error:', error)
      setData({
        generated_at: new Date().toISOString(),
        lookback_hours: lookbackHours,
        sampled_alerts: 0,
        countries: [],
        error: String(error),
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void fetchTopCountries()
  }, [lookbackHours])

  const summary = useMemo(() => {
    const countries = data?.countries ?? []
    return countries.reduce(
      (acc, row) => {
        acc.total += row.count
        acc.critical += row.critical
        acc.high += row.high
        return acc
      },
      { total: 0, critical: 0, high: 0 }
    )
  }, [data])

  const maxCount = useMemo(() => {
    if (!data?.countries?.length) return 1
    return Math.max(...data.countries.map((row) => row.count), 1)
  }, [data])

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Threat Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Country distribution of recent source threats</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1">
            {LOOKBACK_OPTIONS.map((hours) => (
              <button
                key={hours}
                onClick={() => setLookbackHours(hours)}
                className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  lookbackHours === hours
                    ? 'bg-primary/15 text-primary border border-primary/30'
                    : 'bg-muted text-muted-foreground border border-border hover:border-border-hover'
                }`}
              >
                {hours}h
              </button>
            ))}
          </div>
          <button
            onClick={fetchTopCountries}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium bg-card text-muted-foreground border border-border hover:border-border-hover disabled:opacity-60"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="card-surface p-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Threat Events</p>
          <p className="text-2xl font-semibold text-foreground mt-1">{summary.total.toLocaleString()}</p>
        </div>
        <div className="card-surface p-4">
          <p className="text-xs text-muted-foreground uppercase tracking-wider">Countries</p>
          <p className="text-2xl font-semibold text-primary mt-1">{(data?.countries.length || 0).toLocaleString()}</p>
        </div>
        <div className="card-surface p-4">
          <p className="text-xs text-severity-critical uppercase tracking-wider">Critical</p>
          <p className="text-2xl font-semibold text-severity-critical mt-1">{summary.critical.toLocaleString()}</p>
        </div>
        <div className="card-surface p-4">
          <p className="text-xs text-severity-high uppercase tracking-wider">High</p>
          <p className="text-2xl font-semibold text-severity-high mt-1">{summary.high.toLocaleString()}</p>
        </div>
      </div>

      <div className="card-surface p-4 flex items-center justify-between text-xs text-muted-foreground">
        <span>
          {data ? `Sampled ${data.sampled_alerts} alerts over last ${data.lookback_hours}h` : 'Loading alert sample...'}
        </span>
        <span>
          {data?.generated_at ? `Updated ${formatSofiaDateTime(data.generated_at, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}` : 'Not updated yet'}
        </span>
      </div>

      <div className="card-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Country</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Threat Volume</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Severity Mix</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Top Categories</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Sample IPs</th>
              </tr>
            </thead>
            <tbody>
              {!data?.countries?.length ? (
                <tr>
                  <td colSpan={5} className="px-4 py-10 text-center text-sm text-muted-foreground">
                    <div className="flex flex-col items-center gap-2">
                      <Globe2 className="w-6 h-6" />
                      <span>{loading ? 'Loading country threat data...' : 'No threat country data available'}</span>
                      {data?.error && <span className="text-danger text-xs">{data.error}</span>}
                    </div>
                  </td>
                </tr>
              ) : (
                data.countries.map((row) => (
                  <tr key={row.country} className="border-b border-border last:border-0 hover:bg-muted/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex flex-col">
                        <span className="text-sm font-medium text-foreground">{row.country}</span>
                        <span className="text-xs text-muted-foreground">{row.country_code}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="space-y-1">
                        <div className="w-full max-w-[220px] h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary rounded-full"
                            style={{ width: `${Math.max(5, (row.count / maxCount) * 100)}%` }}
                          />
                        </div>
                        <p className="text-xs text-foreground">{row.count.toLocaleString()} alerts</p>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1.5">
                        <span className="px-2 py-0.5 bg-severity-critical/10 text-severity-critical rounded text-[11px]">C {row.critical}</span>
                        <span className="px-2 py-0.5 bg-severity-high/10 text-severity-high rounded text-[11px]">H {row.high}</span>
                        <span className="px-2 py-0.5 bg-severity-medium/10 text-severity-medium rounded text-[11px]">M {row.medium}</span>
                        <span className="px-2 py-0.5 bg-severity-low/10 text-severity-low rounded text-[11px]">L {row.low}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1.5">
                        {row.top_categories.length ? (
                          row.top_categories.map(([category, count]) => (
                            <span key={`${row.country}-${category}`} className="px-2 py-0.5 bg-muted rounded text-[11px] text-muted-foreground">
                              {category} ({count})
                            </span>
                          ))
                        ) : (
                          <span className="text-xs text-muted-foreground">No categories</span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-col gap-1">
                        {row.example_ips.length ? (
                          row.example_ips.map((ip) => (
                            <span key={`${row.country}-${ip}`} className="text-xs font-mono text-muted-foreground">{ip}</span>
                          ))
                        ) : (
                          <span className="text-xs text-muted-foreground">No IP samples</span>
                        )}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
