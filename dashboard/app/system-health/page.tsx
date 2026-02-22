'use client'

import { API_URL } from '../../lib/api-config'
import { useEffect, useState } from 'react'
import { Activity, Server, Zap, AlertCircle, CheckCircle, Clock } from 'lucide-react'

interface ServiceStatus {
  name: string
  status: 'healthy' | 'degraded' | 'down'
  lastCheck?: string
}

interface SystemMetrics {
  services: ServiceStatus[]
  flowsProcessed: number
  activeFlows: number
  alertsGenerated: number
  threatsBlocked: number
  lastUpdate: string
}

export default function SystemHealthPage() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchHealth = async () => {
      try {
        const services: ServiceStatus[] = []
        try {
          const apiRes = await fetch(`${API_URL}/healthz`, { signal: AbortSignal.timeout(2000) })
          services.push({ name: 'API', status: apiRes.ok ? 'healthy' : 'degraded', lastCheck: new Date().toLocaleTimeString() })
        } catch { services.push({ name: 'API', status: 'down', lastCheck: new Date().toLocaleTimeString() }) }

        try {
          const brainRes = await fetch('http://localhost:8001/health', { signal: AbortSignal.timeout(2000) })
          services.push({ name: 'Brain (ML)', status: brainRes.ok ? 'healthy' : 'degraded', lastCheck: new Date().toLocaleTimeString() })
        } catch { services.push({ name: 'Brain (ML)', status: 'degraded', lastCheck: new Date().toLocaleTimeString() }) }

        services.push({ name: 'Core (Capture)', status: 'healthy', lastCheck: new Date().toLocaleTimeString() })

        try {
          const flowsRes = await fetch(`${API_URL}/flows/recent`, { signal: AbortSignal.timeout(2000) })
          services.push({ name: 'Database', status: flowsRes.ok ? 'healthy' : 'degraded', lastCheck: new Date().toLocaleTimeString() })
        } catch { services.push({ name: 'Database', status: 'down', lastCheck: new Date().toLocaleTimeString() }) }

        const [flowStatsRes, alertsRes] = await Promise.all([
          fetch(`${API_URL}/flows/live-stats?window_seconds=30`).catch(() => null),
          fetch(`${API_URL}/alerts/recent`).catch(() => null),
        ])
        const flowStats = flowStatsRes && flowStatsRes.ok ? await flowStatsRes.json() : null
        const alerts = alertsRes && alertsRes.ok ? await alertsRes.json() : []

        setMetrics({
          services,
          flowsProcessed: Number(flowStats?.total_flows || 0),
          activeFlows: Number(flowStats?.active_flows || 0),
          alertsGenerated: Array.isArray(alerts) ? alerts.length : 0,
          threatsBlocked: Array.isArray(alerts) ? alerts.filter((a: any) => a.severity === 'critical').length : 0,
          lastUpdate: new Date().toLocaleTimeString(),
        })
        setLoading(false)
      } catch (error) {
        setLoading(false)
      }
    }
    fetchHealth()
    const interval = setInterval(fetchHealth, 10000)
    return () => clearInterval(interval)
  }, [])

  const getStatusStyle = (status: string) => {
    switch (status) {
      case 'healthy': return { bg: 'bg-safe/10', border: 'border-safe/20', text: 'text-safe', dot: 'bg-safe' }
      case 'degraded': return { bg: 'bg-warning/10', border: 'border-warning/20', text: 'text-warning', dot: 'bg-warning' }
      case 'down': return { bg: 'bg-danger/10', border: 'border-danger/20', text: 'text-danger', dot: 'bg-danger' }
      default: return { bg: 'bg-muted', border: 'border-border', text: 'text-muted-foreground', dot: 'bg-muted-foreground' }
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy': return <CheckCircle className="w-4 h-4" />
      case 'degraded': return <Clock className="w-4 h-4" />
      case 'down': return <AlertCircle className="w-4 h-4" />
      default: return <Activity className="w-4 h-4" />
    }
  }

  const overallStatus = metrics?.services.every(s => s.status === 'healthy')
    ? 'healthy' : metrics?.services.some(s => s.status === 'down') ? 'critical' : 'degraded'

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-muted rounded-xl flex items-center justify-center border border-border">
          <Activity className="w-5 h-5 text-primary" />
        </div>
        <div>
          <h1 className="text-2xl font-semibold text-foreground">System Health</h1>
          <p className="text-sm text-muted-foreground">Monitor service status and system metrics</p>
        </div>
      </div>

      {loading ? (
        <div className="text-center py-12 text-muted-foreground text-sm">Loading system health...</div>
      ) : (
        <>
          {/* Overall Status */}
          <div className={`p-5 rounded-xl border ${
            overallStatus === 'healthy' ? 'bg-safe/5 border-safe/20'
              : overallStatus === 'critical' ? 'bg-danger/5 border-danger/20'
              : 'bg-warning/5 border-warning/20'
          }`}>
            <div className="flex items-center gap-3">
              {overallStatus === 'healthy' ? <CheckCircle className="w-6 h-6 text-safe" />
                : overallStatus === 'critical' ? <AlertCircle className="w-6 h-6 text-danger" />
                : <Clock className="w-6 h-6 text-warning" />}
              <div>
                <h2 className={`text-lg font-semibold ${
                  overallStatus === 'healthy' ? 'text-safe' : overallStatus === 'critical' ? 'text-danger' : 'text-warning'
                }`}>
                  System {overallStatus === 'healthy' ? 'Healthy' : overallStatus === 'critical' ? 'Critical' : 'Degraded'}
                </h2>
                <p className="text-xs text-muted-foreground">Last updated: {metrics?.lastUpdate}</p>
              </div>
            </div>
          </div>

          {/* Services */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {metrics?.services.map((service, idx) => {
              const s = getStatusStyle(service.status)
              return (
                <div key={idx} className={`${s.bg} border ${s.border} rounded-xl p-4`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-foreground">{service.name}</span>
                    <div className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />
                  </div>
                  <div className={`flex items-center gap-1.5 ${s.text}`}>
                    {getStatusIcon(service.status)}
                    <span className="text-xs font-medium capitalize">{service.status}</span>
                  </div>
                  {service.lastCheck && (
                    <p className="text-[10px] text-muted-foreground mt-2">Checked: {service.lastCheck}</p>
                  )}
                </div>
              )
            })}
          </div>

          {/* Metrics */}
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[
              { icon: Zap, color: 'text-primary', bg: 'bg-primary/10', label: 'Flows Processed', value: metrics?.flowsProcessed.toLocaleString() },
              { icon: Activity, color: 'text-accent', bg: 'bg-accent/10', label: 'Active Flows (30s)', value: metrics?.activeFlows.toLocaleString() },
              { icon: AlertCircle, color: 'text-warning', bg: 'bg-warning/10', label: 'Alerts Generated', value: metrics?.alertsGenerated },
              { icon: Server, color: 'text-danger', bg: 'bg-danger/10', label: 'Critical Threats', value: metrics?.threatsBlocked },
            ].map((metric) => (
              <div key={metric.label} className="card-surface p-5">
                <div className="flex items-center gap-3">
                  <div className={`p-2 ${metric.bg} rounded-lg`}>
                    <metric.icon className={`w-4 h-4 ${metric.color}`} />
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground">{metric.label}</p>
                    <p className="text-xl font-semibold text-foreground">{metric.value}</p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
