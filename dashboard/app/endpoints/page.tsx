"use client"

import { API_URL } from '../../lib/api-config'
import { useEffect, useState } from "react"
import { Laptop, Activity, Brain, CheckCircle, Clock, Server, Shield, RefreshCw, Play, Square } from "lucide-react"

interface DeviceProfile {
  hostname: string
  trained: boolean
  flow_count: number
  training_progress?: {
    isolation_forest: { current_flows: number; required_flows: number; trained: boolean }
    autoencoder: { current_flows: number; required_flows: number; trained: boolean; status: string }
    lstm_sequential?: { status: string; trained: boolean }
  }
  baseline?: {
    avg_bytes_per_flow: number
    avg_packets_per_flow: number
    common_destinations_count: number
    common_ports_count: number
  }
}

interface SystemStatus {
  learning_phase: "idle" | "learning" | "active"
  flows_collected: number
  training_threshold: number
  is_trained: boolean
}

export default function EndpointsPage() {
  const [devices, setDevices] = useState<DeviceProfile[]>([])
  const [totalFlows, setTotalFlows] = useState<number>(0)
  const [dbFlowCounts, setDbFlowCounts] = useState<Record<string, number>>({})
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    learning_phase: "idle",
    flows_collected: 0,
    training_threshold: 200,
    is_trained: false,
  })
  const [isTogglingLearning, setIsTogglingLearning] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchDevices = async () => {
      try {
        setError(null)
        const [profilesRes, dbRes, statusRes] = await Promise.all([
          fetch(`${API_URL}/devices/profiles`),
          fetch(`${API_URL}/flows/count-by-device`),
          fetch(`${API_URL}/system/learning-status`),
        ])
        if (profilesRes.ok) {
          const data = await profilesRes.json()
          setDevices(data.profiles || [])
          setTotalFlows(data.totalFlows || 0)
        } else {
          setError(`API returned ${profilesRes.status}`)
        }
        if (dbRes.ok) setDbFlowCounts(await dbRes.json() || {})
        if (statusRes.ok) setSystemStatus(await statusRes.json())
      } catch (err) {
        setError("Unable to connect to API")
      } finally {
        setLoading(false)
      }
    }
    fetchDevices()
    const interval = setInterval(fetchDevices, 2000)
    return () => clearInterval(interval)
  }, [])

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  const handleToggleLearning = async () => {
    if (isTogglingLearning) return
    setIsTogglingLearning(true)
    try {
      if (systemStatus.learning_phase === "idle") {
        const response = await fetch(`${API_URL}/system/start-learning`, { method: "POST" })
        if (response.ok) setSystemStatus((prev) => ({ ...prev, learning_phase: "learning" }))
      } else if (systemStatus.learning_phase === "learning") {
        const response = await fetch(`${API_URL}/system/stop-learning`, { method: "POST" })
        if (response.ok) setSystemStatus((prev) => ({ ...prev, learning_phase: "active", is_trained: true }))
      }
    } catch (toggleErr) {
      // Silent fail
    } finally {
      setIsTogglingLearning(false)
    }
  }

  const getStatusIndicator = () => {
    switch (systemStatus.learning_phase) {
      case "idle":
        return { color: "bg-muted-foreground", label: "Idle" }
      case "learning":
        return { color: "bg-warning", label: `Learning (${systemStatus.flows_collected}/${systemStatus.training_threshold})` }
      case "active":
        return { color: "bg-safe", label: "Protected" }
      default:
        return { color: "bg-muted-foreground", label: "Unknown" }
    }
  }

  const status = getStatusIndicator()

  if (loading) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <RefreshCw className="w-6 h-6 text-primary animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6 flex items-center justify-center h-64">
        <p className="text-danger text-sm">{error}</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-primary/10 rounded-xl flex items-center justify-center">
            <Laptop className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold text-foreground">Endpoints</h1>
            <p className="text-sm text-muted-foreground">Connected devices with AI behavioral analysis</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="card-surface px-4 py-2 min-w-[260px]">
            <div className="flex items-center gap-2">
              <div className={`w-1.5 h-1.5 rounded-full ${status.color}`} />
              <span className="text-xs text-muted-foreground">{status.label}</span>
              {systemStatus.learning_phase === "idle" && (
                <button
                  onClick={handleToggleLearning}
                  disabled={isTogglingLearning}
                  className="flex items-center gap-1 px-2 py-0.5 bg-primary hover:bg-primary/90 text-primary-foreground rounded text-[11px] font-medium transition disabled:opacity-50 ml-1"
                >
                  <Play className="w-2.5 h-2.5" />
                  Start
                </button>
              )}
              {systemStatus.learning_phase === "learning" && (
                <button
                  onClick={handleToggleLearning}
                  disabled={isTogglingLearning}
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
          </div>
          <div className="card-surface px-4 py-2">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Flows</p>
            <p className="text-lg font-semibold text-foreground">{totalFlows.toLocaleString()}</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {devices.map((device, idx) => {
          const allTrained = device.training_progress?.isolation_forest.trained && device.training_progress?.autoencoder.trained
          const ifProgress = Math.min(((device.training_progress?.isolation_forest.current_flows || 0) / (device.training_progress?.isolation_forest.required_flows || 500)) * 100, 100)

          return (
            <div key={idx} className="card-surface-hover p-5">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2.5">
                  <div className="w-9 h-9 bg-muted rounded-lg flex items-center justify-center">
                    <Server className="w-4 h-4 text-primary" />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">{device.hostname}</h3>
                    <p className="text-[11px] text-muted-foreground">
                      {device.flow_count.toLocaleString()} ML / {(dbFlowCounts[device.hostname] || 0).toLocaleString()} stored
                    </p>
                  </div>
                </div>
                <div className={`w-2 h-2 rounded-full ${allTrained ? "bg-safe" : "bg-warning"}`} />
              </div>

              <div className="space-y-2.5 pt-3 border-t border-border">
                <div className="flex justify-between text-sm items-center">
                  <span className="text-muted-foreground text-xs">Isolation Forest</span>
                  {device.training_progress?.isolation_forest.trained ? (
                    <div className="flex items-center gap-1">
                      <CheckCircle className="w-3.5 h-3.5 text-safe" />
                      <span className="text-safe text-[11px] font-medium">Trained</span>
                    </div>
                  ) : (
                    <span className="text-warning text-[11px] font-mono">
                      {device.training_progress?.isolation_forest.current_flows || 0}/{device.training_progress?.isolation_forest.required_flows || 500}
                    </span>
                  )}
                </div>
                {!device.training_progress?.isolation_forest.trained && (
                  <div className="w-full bg-muted rounded-full h-1">
                    <div className="h-1 rounded-full bg-primary transition-all" style={{ width: `${ifProgress}%` }} />
                  </div>
                )}

                <div className="flex justify-between text-sm items-center">
                  <span className="text-muted-foreground text-xs flex items-center gap-1">
                    <Brain className="w-3 h-3" /> Autoencoder
                  </span>
                  {device.training_progress?.autoencoder.trained ? (
                    <div className="flex items-center gap-1">
                      <CheckCircle className="w-3.5 h-3.5 text-safe" />
                      <span className="text-safe text-[11px] font-medium">Active</span>
                    </div>
                  ) : device.training_progress?.autoencoder.status === "training" ? (
                    <div className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5 text-warning" />
                      <span className="text-warning text-[11px]">Training...</span>
                    </div>
                  ) : (
                    <span className="text-muted-foreground text-[11px]">Waiting</span>
                  )}
                </div>

                {device.training_progress?.lstm_sequential && (
                  <div className="flex justify-between text-sm items-center">
                    <span className="text-muted-foreground text-xs">LSTM</span>
                    <div className="flex items-center gap-1">
                      <CheckCircle className="w-3.5 h-3.5 text-accent" />
                      <span className="text-accent text-[11px] font-medium">Active</span>
                    </div>
                  </div>
                )}

                {device.baseline && (
                  <div className="pt-2 border-t border-border space-y-1.5">
                    <div className="flex items-center gap-2 text-xs">
                      <Activity className="w-3 h-3 text-primary" />
                      <span className="text-muted-foreground">Avg Flow</span>
                      <span className="ml-auto text-foreground font-mono">{formatBytes(device.baseline.avg_bytes_per_flow)}</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs">
                      <Activity className="w-3 h-3 text-primary" />
                      <span className="text-muted-foreground">Avg Packets</span>
                      <span className="ml-auto text-foreground font-mono">{device.baseline.avg_packets_per_flow.toFixed(1)}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {devices.length === 0 && (
        <div className="text-center py-16">
          <Shield className="w-12 h-12 text-muted-foreground mx-auto mb-3" />
          <p className="text-foreground font-medium">No devices detected yet</p>
          <p className="text-sm text-muted-foreground mt-1">Waiting for network traffic...</p>
        </div>
      )}
    </div>
  )
}
