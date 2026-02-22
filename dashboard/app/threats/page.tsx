"use client"

import { API_URL } from '../../lib/api-config'
import { useEffect, useState } from "react"
import { Shield, XCircle, ChevronRight, Trash2 } from "lucide-react"
import { formatSofiaDateTime } from "../../lib/time"
import { ThreatAnalysis } from "../../components/threat-analysis"

const getSeverityColor = (severity: string): string => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'text-severity-critical'
    case 'high': return 'text-severity-high'
    case 'medium': return 'text-severity-medium'
    case 'low': return 'text-severity-low'
    default: return 'text-muted-foreground'
  }
}

const getSeverityBorder = (severity: string): string => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'border-l-2 border-l-severity-critical'
    case 'high': return 'border-l-2 border-l-severity-high'
    case 'medium': return 'border-l-2 border-l-severity-medium'
    case 'low': return 'border-l-2 border-l-severity-low'
    default: return 'border-l-2 border-l-muted'
  }
}

const getSeverityBg = (severity: string): string => {
  switch (severity?.toLowerCase()) {
    case 'critical': return 'bg-severity-critical/10'
    case 'high': return 'bg-severity-high/10'
    case 'medium': return 'bg-severity-medium/10'
    case 'low': return 'bg-severity-low/10'
    default: return 'bg-muted'
  }
}

interface Alert {
  id: number
  hostname: string
  risk_score: number
  severity: string
  reason: string
  src_ip: string
  dst_ip: string
  src_port?: number
  dst_port?: number
  protocol?: string
  threat_category?: string
  timestamp?: number | string
  created_at?: string
}

const timeRanges = [
  { label: "15m", minutes: 15 },
  { label: "1h", minutes: 60 },
  { label: "6h", minutes: 360 },
  { label: "24h", minutes: 1440 },
  { label: "All", minutes: null },
]

const severityFilters = ["all", "critical", "high", "medium", "low"]

export default function ThreatsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [blockingIP, setBlockingIP] = useState<string | null>(null)
  const [blockStatus, setBlockStatus] = useState<{ [key: string]: "success" | "error" | null }>({})
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  const [severityFilter, setSeverityFilter] = useState<string>("all")
  const [timeFilter, setTimeFilter] = useState(timeRanges[2])
  const [searchQuery, setSearchQuery] = useState("")
  const [selectedAlertIds, setSelectedAlertIds] = useState<number[]>([])
  const [deletingAlertId, setDeletingAlertId] = useState<number | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch(`${API_URL}/alerts/recent`)
        if (!response.ok) throw new Error("Failed to fetch")
        setAlerts(await response.json())
      } catch (error) {
        console.error("[Threats] Fetch error:", error)
      }
    }
    fetchAlerts()
    const interval = setInterval(fetchAlerts, 5000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    setSelectedAlertIds((prev) => prev.filter((id) => alerts.some((a) => a.id === id)))
  }, [alerts])

  const filteredAlerts = alerts.filter((alert) => {
    const severityMatch = severityFilter === "all" || alert.severity?.toLowerCase() === severityFilter
    const search = searchQuery.toLowerCase()
    const matchesSearch = !search || [alert.hostname, alert.src_ip, alert.reason, alert.threat_category].some((f) => f?.toLowerCase().includes(search))
    const timestampSeconds = (() => {
      const raw = alert.timestamp ?? alert.created_at ?? ""
      if (typeof raw === "number") return raw
      const date = Date.parse(String(raw))
      return isNaN(date) ? 0 : date / 1000
    })()
    const minutes = timeFilter.minutes
    const matchesTime = minutes === null || Date.now() / 1000 - timestampSeconds <= minutes * 60
    return severityMatch && matchesSearch && matchesTime
  })

  const handleBlockIP = async (ip: string, alertId: number) => {
    setBlockingIP(ip)
    try {
      const response = await fetch(`${API_URL}/policies/block`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, block_reason: `Manually blocked from threat alert #${alertId}`, confidence: 1.0, expires_hours: 24, threat_category: "MANUAL_BLOCK", manual_override: true }),
      })
      if (response.ok) {
        setBlockStatus({ ...blockStatus, [ip]: "success" })
        setTimeout(() => setBlockStatus({ ...blockStatus, [ip]: null }), 3000)
      } else {
        setBlockStatus({ ...blockStatus, [ip]: "error" })
      }
    } catch (error) {
      setBlockStatus({ ...blockStatus, [ip]: "error" })
    } finally {
      setBlockingIP(null)
    }
  }

  const toggleSelectAlert = (alertId: number) => {
    setSelectedAlertIds((prev) => (
      prev.includes(alertId)
        ? prev.filter((id) => id !== alertId)
        : [...prev, alertId]
    ))
  }

  const filteredAlertIds = filteredAlerts.map((alert) => alert.id)
  const selectedFilteredCount = filteredAlertIds.filter((id) => selectedAlertIds.includes(id)).length
  const allFilteredSelected = filteredAlertIds.length > 0 && selectedFilteredCount === filteredAlertIds.length

  const toggleSelectFiltered = () => {
    if (allFilteredSelected) {
      setSelectedAlertIds((prev) => prev.filter((id) => !filteredAlertIds.includes(id)))
      return
    }
    setSelectedAlertIds((prev) => {
      const merged = new Set(prev)
      filteredAlertIds.forEach((id) => merged.add(id))
      return Array.from(merged)
    })
  }

  const handleDeleteSingleAlert = async (alertId: number) => {
    const confirmed = window.confirm(`Delete alert #${alertId}?`)
    if (!confirmed) return

    setDeleteError(null)
    setDeletingAlertId(alertId)
    try {
      const response = await fetch(`${API_URL}/alerts/${alertId}`, { method: "DELETE" })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)

      setAlerts((prev) => prev.filter((alert) => alert.id !== alertId))
      setSelectedAlertIds((prev) => prev.filter((id) => id !== alertId))
      if (selectedAlert?.id === alertId) setSelectedAlert(null)
    } catch (error: any) {
      setDeleteError(`Failed to delete alert #${alertId}`)
    } finally {
      setDeletingAlertId(null)
    }
  }

  const handleDeleteSelected = async () => {
    if (selectedAlertIds.length === 0) return
    const confirmed = window.confirm(`Delete ${selectedAlertIds.length} selected alerts?`)
    if (!confirmed) return

    setDeleteError(null)
    setDeletingAlertId(-1)
    try {
      const response = await fetch(`${API_URL}/alerts/delete-batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_ids: selectedAlertIds }),
      })
      if (!response.ok) throw new Error(`HTTP ${response.status}`)
      const data = await response.json().catch(() => ({}))
      const deletedIds = Array.isArray(data?.deleted_ids) ? data.deleted_ids : selectedAlertIds
      const deletedSet = new Set<number>(deletedIds.map((id: any) => Number(id)))

      setAlerts((prev) => prev.filter((alert) => !deletedSet.has(alert.id)))
      setSelectedAlertIds([])
      if (selectedAlert && deletedSet.has(selectedAlert.id)) setSelectedAlert(null)
    } catch (error: any) {
      setDeleteError("Failed to delete selected alerts")
    } finally {
      setDeletingAlertId(null)
    }
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-card rounded-xl flex items-center justify-center border border-border">
          <Shield className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Threat Detection</h1>
          <p className="text-sm text-muted-foreground">AI-powered security threat analysis</p>
        </div>
      </div>

      {/* Severity Stats */}
      <div className="grid grid-cols-4 gap-3">
        {(["critical", "high", "medium", "low"] as const).map((severity) => {
          const count = alerts.filter((a) => a.severity?.toLowerCase() === severity).length
          return (
            <div key={severity} className={`card-surface p-4 ${getSeverityBorder(severity)}`}>
              <p className="text-xs text-muted-foreground capitalize mb-1">{severity}</p>
              <p className={`text-2xl font-semibold ${getSeverityColor(severity)}`}>{count}</p>
            </div>
          )
        })}
      </div>

      {/* Filters */}
      <div className="card-surface p-4">
        <div className="flex flex-wrap gap-5 items-center">
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Severity</span>
            <div className="flex gap-1">
              {severityFilters.map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    severityFilter === sev
                      ? 'bg-primary/15 text-primary border border-primary/30'
                      : 'bg-muted text-muted-foreground border border-border hover:border-border-hover'
                  }`}
                >
                  {sev.charAt(0).toUpperCase() + sev.slice(1)}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-[10px] text-muted-foreground uppercase tracking-wider">Time</span>
            <div className="flex gap-1">
              {timeRanges.map((range) => (
                <button
                  key={range.label}
                  onClick={() => setTimeFilter(range)}
                  className={`px-2.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
                    timeFilter.label === range.label
                      ? 'bg-primary/15 text-primary border border-primary/30'
                      : 'bg-muted text-muted-foreground border border-border hover:border-border-hover'
                  }`}
                >
                  {range.label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex-1 min-w-[200px]">
            <input
              type="text"
              placeholder="Search threats..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full px-4 py-2 bg-muted border border-border rounded-lg text-sm text-foreground placeholder-muted-foreground focus:outline-none focus:border-primary transition-colors"
            />
          </div>
          <div className="flex items-center gap-2 ml-auto">
            <button
              onClick={toggleSelectFiltered}
              disabled={filteredAlerts.length === 0}
              className="px-3 py-2 bg-muted hover:bg-border border border-border text-muted-foreground hover:text-foreground text-xs rounded-lg transition disabled:opacity-50"
            >
              {allFilteredSelected ? "Unselect Filtered" : "Select Filtered"}
            </button>
            <button
              onClick={handleDeleteSelected}
              disabled={selectedAlertIds.length === 0 || deletingAlertId === -1}
              className="px-3 py-2 bg-danger/10 hover:bg-danger/20 border border-danger/30 text-danger text-xs rounded-lg transition disabled:opacity-50 flex items-center gap-1.5"
            >
              <Trash2 className="w-3.5 h-3.5" />
              {deletingAlertId === -1 ? "Deleting..." : `Delete Selected (${selectedAlertIds.length})`}
            </button>
          </div>
        </div>
        {deleteError && (
          <p className="mt-3 text-xs text-danger">{deleteError}</p>
        )}
      </div>

      {/* Threats List */}
      <div className="space-y-2">
        {filteredAlerts.length === 0 ? (
          <div className="card-surface p-12 text-center">
            <Shield className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
            <p className="text-muted-foreground text-sm">No threats detected in the selected time range</p>
          </div>
        ) : (
          filteredAlerts.map((alert) => {
            const blockState = blockStatus[alert.src_ip]
            return (
              <div
                key={alert.id}
                className={`card-surface-hover ${getSeverityBorder(alert.severity)} p-4 cursor-pointer`}
                onClick={() => setSelectedAlert(alert)}
              >
                <div className="flex items-center gap-4">
                  <div className="flex items-center" onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={selectedAlertIds.includes(alert.id)}
                      onChange={() => toggleSelectAlert(alert.id)}
                      className="w-4 h-4 rounded border-border bg-muted text-primary focus:ring-primary/30"
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2.5 mb-1">
                      <span className={`text-xs font-semibold uppercase ${getSeverityColor(alert.severity)}`}>{alert.severity}</span>
                      <span className="text-xs text-muted-foreground">{(alert.risk_score * 100).toFixed(0)}% risk</span>
                      {alert.threat_category && (
                        <span className="text-[10px] px-2 py-0.5 bg-muted rounded text-muted-foreground">{alert.threat_category.replace(/_/g, " ")}</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="font-mono text-primary">{alert.src_ip}</span>
                      <span className="text-muted-foreground">{">"}</span>
                      <span className="font-mono text-muted-foreground">{alert.dst_ip}</span>
                      {alert.protocol && <span className="text-[10px] px-1.5 py-0.5 bg-muted/50 rounded text-muted-foreground ml-1">{alert.protocol}</span>}
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-[11px] text-muted-foreground">{formatSofiaDateTime(alert.timestamp ?? alert.created_at ?? "")}</p>
                    <p className="text-[11px] text-muted-foreground">{alert.hostname}</p>
                  </div>
                  <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => handleDeleteSingleAlert(alert.id)}
                      disabled={deletingAlertId === alert.id}
                      className="px-2.5 py-1.5 bg-muted hover:bg-danger/10 text-muted-foreground hover:text-danger text-xs rounded-lg transition border border-border disabled:opacity-50"
                      title="Delete alert"
                    >
                      {deletingAlertId === alert.id ? "..." : "Delete"}
                    </button>
                    {blockState === "success" ? (
                      <span className="text-safe text-xs px-3 py-1.5 font-medium">Blocked</span>
                    ) : blockState === "error" ? (
                      <span className="text-danger text-xs px-3 py-1.5">Failed</span>
                    ) : (
                      <button
                        onClick={() => handleBlockIP(alert.src_ip, alert.id)}
                        disabled={blockingIP === alert.src_ip}
                        className="px-3 py-1.5 bg-danger/10 hover:bg-danger/20 text-danger text-xs rounded-lg transition border border-danger/20 disabled:opacity-50 font-medium"
                      >
                        {blockingIP === alert.src_ip ? "..." : "Block"}
                      </button>
                    )}
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </div>
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setSelectedAlert(null)}>
          <div className="bg-card border border-border rounded-xl max-w-2xl w-full max-h-[85vh] overflow-hidden flex flex-col animate-fadeIn" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between p-5 border-b border-border">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-muted">
                  <Shield className="w-4 h-4 text-primary" />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-foreground">Threat Analysis</h2>
                  <p className="text-xs text-muted-foreground">Alert #{selectedAlert.id}</p>
                </div>
              </div>
              <button onClick={() => setSelectedAlert(null)} className="p-1.5 hover:bg-muted rounded-lg transition">
                <XCircle className="w-4 h-4 text-muted-foreground" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto p-5">
              <ThreatAnalysis
                reason={selectedAlert.reason}
                srcIp={selectedAlert.src_ip}
                dstIp={selectedAlert.dst_ip}
                protocol={selectedAlert.protocol}
                srcPort={selectedAlert.src_port}
                dstPort={selectedAlert.dst_port}
                riskScore={selectedAlert.risk_score}
                severity={selectedAlert.severity}
                threatCategory={selectedAlert.threat_category}
              />
            </div>
            <div className="p-4 border-t border-border flex justify-between items-center">
              <p className="text-[11px] text-muted-foreground">
                Detected: {formatSofiaDateTime(selectedAlert.timestamp ?? selectedAlert.created_at ?? "")}
              </p>
              <div className="flex gap-2">
                <button onClick={() => setSelectedAlert(null)} className="px-4 py-2 bg-muted hover:bg-border text-foreground text-sm rounded-lg transition font-medium">Close</button>
                <button
                  onClick={() => handleDeleteSingleAlert(selectedAlert.id)}
                  disabled={deletingAlertId === selectedAlert.id}
                  className="px-4 py-2 bg-danger/10 hover:bg-danger/20 text-danger text-sm rounded-lg transition border border-danger/30 disabled:opacity-50 font-medium"
                >
                  {deletingAlertId === selectedAlert.id ? "Deleting..." : "Delete Alert"}
                </button>
                {blockStatus[selectedAlert.src_ip] !== "success" && (
                  <button
                    onClick={() => handleBlockIP(selectedAlert.src_ip, selectedAlert.id)}
                    disabled={blockingIP === selectedAlert.src_ip}
                    className="px-4 py-2 bg-danger hover:bg-danger/90 text-white text-sm rounded-lg transition disabled:opacity-50 font-medium"
                  >
                    {blockingIP === selectedAlert.src_ip ? "Blocking..." : "Block IP"}
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
