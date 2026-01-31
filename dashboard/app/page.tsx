'use client'

import { API_URL } from '../lib/api-config'
import { useEffect, useRef, useState } from 'react'
import {
  Activity,
  Shield,
  Laptop,
  Heart,
  TrendingUp,
  TrendingDown,
  GripVertical,
  Plus,
  X,
  ChevronRight,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import { formatSofiaTime, parseEpochSeconds } from '../lib/time'

// --- Types ---
interface Stats {
  currentPacketsPerSec: number
  totalFlows: number
  blockedThreats: number
  activeEndpoints: number
  systemHealth: number
  threatBreakdown: { critical: number; high: number; medium: number; low: number }
  trafficTrend: Array<{ time: string; packets: number; threats: number }>
  threatDistribution: Array<{ name: string; value: number; color: string }>
}

type FlowRecord = { flow_id?: string; hostname?: string; src_ip?: string; dst_ip?: string; dst_port?: number; packets?: number; end_ts: number; start_ts?: number; [key: string]: any }
type AlertRecord = { id?: string | number; severity?: string; __epoch: number; [key: string]: any }

type WidgetType = 'traffic-chart' | 'threat-distribution' | 'threat-bar' | 'quick-actions'

interface DashboardWidget {
  id: string
  type: WidgetType
  title: string
  size: 'half' | 'full'
}

const DEFAULT_WIDGETS: DashboardWidget[] = [
  { id: 'traffic', type: 'traffic-chart', title: 'Network Activity', size: 'full' },
  { id: 'threat-dist', type: 'threat-distribution', title: 'Threat Distribution', size: 'half' },
  { id: 'threat-bar', type: 'threat-bar', title: 'Threats by Severity', size: 'half' },
  { id: 'quick-actions', type: 'quick-actions', title: 'Quick Actions', size: 'full' },
]

const AVAILABLE_WIDGETS: { type: WidgetType; title: string; size: 'half' | 'full' }[] = [
  { type: 'traffic-chart', title: 'Network Activity', size: 'full' },
  { type: 'threat-distribution', title: 'Threat Distribution', size: 'half' },
  { type: 'threat-bar', title: 'Threats by Severity', size: 'half' },
  { type: 'quick-actions', title: 'Quick Actions', size: 'full' },
]

// --- Helpers ---
const MAX_HISTORY_SECONDS = 24 * 60 * 60

const normalizeFlowRecord = (flow: any): FlowRecord | null => {
  if (!flow) return null
  const endTs = parseEpochSeconds(flow.end_ts ?? flow.timestamp ?? flow.endTime ?? flow.last_seen)
  if (endTs === null) return null
  return { ...flow, end_ts: endTs }
}

const normalizeAlertRecord = (alert: any): AlertRecord | null => {
  if (!alert) return null
  const epoch = parseEpochSeconds(alert.timestamp ?? alert.created_at ?? alert.time ?? alert.detected_at)
  if (epoch === null) return null
  return { ...alert, __epoch: epoch }
}

const mergeFlowHistory = (existing: FlowRecord[], incoming: FlowRecord[], now: number): FlowRecord[] => {
  const cutoff = now - MAX_HISTORY_SECONDS
  const map = new Map<string, FlowRecord>()
  const upsert = (flow?: FlowRecord | null) => {
    if (!flow || flow.end_ts < cutoff) return
    const key = flow.flow_id || `${flow.hostname ?? ''}-${flow.src_ip ?? ''}-${flow.dst_ip ?? ''}-${flow.dst_port ?? ''}-${Math.round(flow.end_ts)}`
    const current = map.get(key)
    if (!current || flow.end_ts >= current.end_ts) map.set(key, flow)
  }
  existing.forEach(upsert)
  incoming.forEach(upsert)
  return Array.from(map.values()).sort((a, b) => a.end_ts - b.end_ts)
}

const mergeAlertHistory = (existing: AlertRecord[], incoming: AlertRecord[], now: number): AlertRecord[] => {
  const cutoff = now - MAX_HISTORY_SECONDS
  const map = new Map<string | number, AlertRecord>()
  const upsert = (alert?: AlertRecord | null) => {
    if (!alert || alert.__epoch < cutoff) return
    const key = alert.id ?? `${alert.severity ?? 'alert'}-${alert.hostname ?? alert.src_ip ?? ''}-${Math.round(alert.__epoch)}`
    const current = map.get(key)
    if (!current || alert.__epoch >= current.__epoch) map.set(key, alert)
  }
  existing.forEach(upsert)
  incoming.forEach(upsert)
  return Array.from(map.values()).sort((a, b) => a.__epoch - b.__epoch)
}

const getTimeRangeSeconds = (range: string): number => {
  switch (range) {
    case '1m': return 60
    case '5m': return 300
    case '15m': return 900
    case '1h': return 3600
    case '6h': return 21600
    case '24h': return 86400
    default: return 3600
  }
}

const tooltipStyle = {
  contentStyle: {
    backgroundColor: '#0F0F12',
    border: '1px solid #1E1E23',
    borderRadius: '8px',
    fontSize: '12px',
    color: '#FAFAFA',
    boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
  },
  labelStyle: { color: '#FAFAFA' },
  itemStyle: { color: '#FAFAFA' },
}

// --- Component ---
export default function Page() {
  const [stats, setStats] = useState<Stats>({
    currentPacketsPerSec: 0,
    totalFlows: 0,
    blockedThreats: 0,
    activeEndpoints: 0,
    systemHealth: 98,
    threatBreakdown: { critical: 0, high: 0, medium: 0, low: 0 },
    trafficTrend: [],
    threatDistribution: [],
  })
  const [timeRange, setTimeRange] = useState('1h')
  const [widgets, setWidgets] = useState<DashboardWidget[]>(DEFAULT_WIDGETS)
  const [showAddWidget, setShowAddWidget] = useState(false)
  const [draggedWidget, setDraggedWidget] = useState<string | null>(null)
  const flowHistoryRef = useRef<FlowRecord[]>([])
  const alertHistoryRef = useRef<AlertRecord[]>([])

  // Load saved layout
  useEffect(() => {
    const saved = localStorage.getItem('timeRange')
    if (saved) setTimeRange(saved)
    const savedWidgets = localStorage.getItem('revenix_dashboard_widgets')
    if (savedWidgets) {
      try { setWidgets(JSON.parse(savedWidgets)) } catch {}
    }
  }, [])

  useEffect(() => { localStorage.setItem('timeRange', timeRange) }, [timeRange])
  useEffect(() => { localStorage.setItem('revenix_dashboard_widgets', JSON.stringify(widgets)) }, [widgets])

  // Fetch data
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const fetchRangeSeconds = getTimeRangeSeconds(timeRange)
        const flowLimit = Math.max(500, Math.ceil(fetchRangeSeconds / 6))
        const [flowsRes, alertsRes, healthRes] = await Promise.all([
          fetch(`${API_URL}/flows/recent?limit=${flowLimit}`),
          fetch(`${API_URL}/alerts/recent`),
          fetch(`${API_URL}/system/health`).catch(() => null),
        ])
        const allFlows = await flowsRes.json()
        const alerts = await alertsRes.json()
        const healthData = healthRes ? await healthRes.json() : null
        const now = Date.now() / 1000
        const normalizedFlows = (Array.isArray(allFlows) ? allFlows : []).map(normalizeFlowRecord).filter((f): f is FlowRecord => Boolean(f))
        const normalizedAlerts = (Array.isArray(alerts) ? alerts : []).map(normalizeAlertRecord).filter((a): a is AlertRecord => Boolean(a))
        const updatedFlowHistory = mergeFlowHistory(flowHistoryRef.current, normalizedFlows, now)
        const updatedAlertHistory = mergeAlertHistory(alertHistoryRef.current, normalizedAlerts, now)
        flowHistoryRef.current = updatedFlowHistory
        alertHistoryRef.current = updatedAlertHistory
        const rangeSeconds = getTimeRangeSeconds(timeRange)
        const rangeStart = now - rangeSeconds
        const thirtySecondsAgo = now - 30
        const flowsInRange = updatedFlowHistory.filter((f) => f.end_ts >= rangeStart)
        const alertsInRange = updatedAlertHistory.filter((a) => a.__epoch >= rangeStart)
        const recentFlows = updatedFlowHistory.filter((f) => f.end_ts >= thirtySecondsAgo)
        const totalPackets = recentFlows.reduce((sum, f) => sum + (f.packets || 0), 0)
        const packetsPerSec = Math.round(totalPackets / 30)
        const uniqueDevices = new Set(flowsInRange.map((f) => f.hostname || f.src_ip || f.dst_ip).filter(Boolean)).size
        const threatBreakdown = alertsInRange.reduce(
          (acc, a) => {
            const sev = (a.severity || '').toLowerCase()
            if (sev in acc) acc[sev as keyof typeof acc] += 1
            return acc
          },
          { critical: 0, high: 0, medium: 0, low: 0 }
        )
        const dataPoints = 20
        const windowSize = rangeSeconds / dataPoints
        const trafficTrend: Array<{ time: string; packets: number; threats: number }> = []
        for (let i = 0; i < dataPoints; i++) {
          const windowStart = rangeStart + i * windowSize
          const windowEnd = windowStart + windowSize
          const windowMid = windowStart + windowSize / 2
          const windowFlows = flowsInRange.filter((f) => { const t = f.start_ts || f.end_ts; return t >= windowStart && t < windowEnd })
          const windowPackets = windowFlows.reduce((sum, f) => sum + (f.packets || 0), 0)
          const windowThreats = alertsInRange.filter((a) => a.__epoch >= windowStart && a.__epoch < windowEnd).length
          trafficTrend.push({
            time: formatSofiaTime(windowMid * 1000, { hour: '2-digit', minute: '2-digit', second: rangeSeconds <= 300 ? '2-digit' : undefined, hour12: false }),
            packets: windowPackets,
            threats: windowThreats,
          })
        }
        const threatDistribution = [
          { name: 'Critical', value: threatBreakdown.critical, color: '#EF4444' },
          { name: 'High', value: threatBreakdown.high, color: '#F97316' },
          { name: 'Medium', value: threatBreakdown.medium, color: '#FBBF24' },
          { name: 'Low', value: threatBreakdown.low, color: '#3B82F6' },
        ].filter((item) => item.value > 0)
        // Use fresh API count for flow total (history is only for chart smoothing)
        const freshFlowCount = normalizedFlows.length
        setStats({
          currentPacketsPerSec: packetsPerSec,
          totalFlows: freshFlowCount,
          blockedThreats: alertsInRange.length,
          activeEndpoints: uniqueDevices,
          systemHealth: healthData?.statistics?.health_score?.overall_score || 98,
          threatBreakdown,
          trafficTrend,
          threatDistribution,
        })
      } catch (error) {
        console.error('[Dashboard] Failed to fetch stats:', error)
      }
    }
    fetchStats()
    const interval = setInterval(fetchStats, 5000)
    return () => clearInterval(interval)
  }, [timeRange])

  // Widget management
  const removeWidget = (id: string) => setWidgets((w) => w.filter((widget) => widget.id !== id))
  const addWidget = (type: WidgetType, title: string, size: 'half' | 'full') => {
    const id = `${type}-${Date.now()}`
    setWidgets((w) => [...w, { id, type, title, size }])
    setShowAddWidget(false)
  }

  // Drag and drop reorder
  const handleDragStart = (id: string) => setDraggedWidget(id)
  const handleDragOver = (e: React.DragEvent, targetId: string) => {
    e.preventDefault()
    if (!draggedWidget || draggedWidget === targetId) return
    setWidgets((prev) => {
      const items = [...prev]
      const dragIdx = items.findIndex((w) => w.id === draggedWidget)
      const targetIdx = items.findIndex((w) => w.id === targetId)
      if (dragIdx === -1 || targetIdx === -1) return prev
      const [removed] = items.splice(dragIdx, 1)
      items.splice(targetIdx, 0, removed)
      return items
    })
  }
  const handleDragEnd = () => setDraggedWidget(null)

  // Stat cards data
  const statCards = [
    { title: 'Packets/sec', value: stats.currentPacketsPerSec.toLocaleString(), subtitle: `${stats.totalFlows} flows in ${timeRange}`, icon: Activity, color: 'text-primary', bg: 'bg-primary/10' },
    { title: 'Threats Blocked', value: stats.blockedThreats.toString(), subtitle: `in last ${timeRange}`, icon: Shield, color: 'text-danger', bg: 'bg-danger/10' },
    { title: 'Endpoints', value: stats.activeEndpoints.toString(), subtitle: 'devices monitored', icon: Laptop, color: 'text-accent', bg: 'bg-accent/10' },
    { title: 'System Health', value: `${stats.systemHealth}%`, subtitle: 'operational', icon: Heart, color: 'text-safe', bg: 'bg-safe/10' },
  ]

  // Render individual widget content
  const renderWidget = (widget: DashboardWidget) => {
    switch (widget.type) {
      case 'traffic-chart':
        return (
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.trafficTrend}>
                <defs>
                  <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1E1E23" />
                <XAxis dataKey="time" stroke="#71717A" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#71717A" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip {...tooltipStyle} />
                <Area type="monotone" dataKey="packets" stroke="#3B82F6" strokeWidth={1.5} fillOpacity={1} fill="url(#colorPackets)" name="Packets" />
                <Area type="monotone" dataKey="threats" stroke="#EF4444" strokeWidth={1.5} fillOpacity={1} fill="url(#colorThreats)" name="Threats" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )

      case 'threat-distribution':
        return stats.threatDistribution.length > 0 ? (
          <div>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={stats.threatDistribution} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value" animationDuration={600}>
                    {stats.threatDistribution.map((entry, idx) => (
                      <Cell key={idx} fill={entry.color} stroke="transparent" />
                    ))}
                  </Pie>
                  <Tooltip {...tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="grid grid-cols-2 gap-2 mt-3">
              {stats.threatDistribution.map((entry, idx) => (
                <div key={idx} className="flex items-center gap-2 px-2.5 py-1.5 bg-muted rounded-lg">
                  <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: entry.color }} />
                  <span className="text-xs text-muted-foreground flex-1">{entry.name}</span>
                  <span className="text-xs font-semibold text-foreground">{entry.value}</span>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
            No threats in {timeRange}
          </div>
        )

      case 'threat-bar':
        const barData = [
          { name: 'Critical', value: stats.threatBreakdown.critical, fill: '#EF4444' },
          { name: 'High', value: stats.threatBreakdown.high, fill: '#F97316' },
          { name: 'Medium', value: stats.threatBreakdown.medium, fill: '#FBBF24' },
          { name: 'Low', value: stats.threatBreakdown.low, fill: '#3B82F6' },
        ]
        return (
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={barData} barCategoryGap="20%">
                <CartesianGrid strokeDasharray="3 3" stroke="#1E1E23" horizontal vertical={false} />
                <XAxis dataKey="name" stroke="#71717A" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#71717A" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip {...tooltipStyle} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {barData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )

      case 'quick-actions':
        return (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {[
              { href: '/live-traffic', icon: Activity, title: 'Live Traffic', desc: 'Real-time packet analysis', color: 'text-primary' },
              { href: '/threats', icon: Shield, title: 'Security Alerts', desc: 'View detected threats', color: 'text-danger' },
              { href: '/system-health', icon: Heart, title: 'System Health', desc: 'Service status overview', color: 'text-safe' },
            ].map((action) => (
              <a
                key={action.href}
                href={action.href}
                className="flex items-center gap-3 p-3 bg-muted hover:bg-border rounded-lg transition-colors group"
              >
                <div className={`w-9 h-9 rounded-lg flex items-center justify-center bg-background ${action.color}`}>
                  <action.icon className="w-4 h-4" />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-foreground">{action.title}</p>
                  <p className="text-[11px] text-muted-foreground">{action.desc}</p>
                </div>
                <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-foreground transition-colors" />
              </a>
            ))}
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground text-balance">Security Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Real-time network monitoring and threat intelligence</p>
        </div>
        <div className="flex items-center gap-1.5">
          {['1m', '5m', '15m', '1h', '6h', '24h'].map((range) => (
            <button
              key={range}
              onClick={() => setTimeRange(range)}
              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-all ${
                timeRange === range
                  ? 'bg-primary text-primary-foreground'
                  : 'bg-card text-muted-foreground hover:text-foreground border border-border hover:border-border-hover'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        {statCards.map((card) => (
          <div key={card.title} className="card-surface-hover p-5">
            <div className="flex items-start justify-between mb-3">
              <div>
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{card.title}</p>
                <h3 className="text-2xl font-semibold text-foreground mt-1">{card.value}</h3>
                <p className="text-[11px] text-muted-foreground mt-0.5">{card.subtitle}</p>
              </div>
              <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${card.bg}`}>
                <card.icon className={`w-4 h-4 ${card.color}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Customizable Widget Grid */}
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Widgets</h2>
        <button
          onClick={() => setShowAddWidget(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-muted-foreground hover:text-foreground bg-card border border-border hover:border-border-hover rounded-lg transition-all"
        >
          <Plus className="w-3 h-3" />
          Add Widget
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {widgets.map((widget) => (
          <div
            key={widget.id}
            draggable
            onDragStart={() => handleDragStart(widget.id)}
            onDragOver={(e) => handleDragOver(e, widget.id)}
            onDragEnd={handleDragEnd}
            className={`card-surface p-5 ${widget.size === 'full' ? 'lg:col-span-2' : ''} ${
              draggedWidget === widget.id ? 'opacity-50' : ''
            }`}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <GripVertical className="w-3.5 h-3.5 text-muted-foreground cursor-grab active:cursor-grabbing" />
                <h3 className="text-sm font-medium text-foreground">{widget.title}</h3>
              </div>
              <div className="flex items-center gap-1.5">
                {widget.type === 'traffic-chart' && (
                  <div className="flex items-center gap-1.5 mr-2">
                    <div className="w-1.5 h-1.5 rounded-full bg-safe" />
                    <span className="text-[10px] text-muted-foreground">Live</span>
                  </div>
                )}
                <button
                  onClick={() => removeWidget(widget.id)}
                  className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            </div>
            {renderWidget(widget)}
          </div>
        ))}
      </div>

      {/* Add Widget Modal */}
      {showAddWidget && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center" onClick={() => setShowAddWidget(false)}>
          <div className="bg-card border border-border rounded-xl w-full max-w-md p-6 animate-fadeIn" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-semibold text-foreground">Add Widget</h2>
              <button onClick={() => setShowAddWidget(false)} className="p-1.5 rounded-lg hover:bg-muted text-muted-foreground">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-2">
              {AVAILABLE_WIDGETS.map((w) => (
                <button
                  key={w.type}
                  onClick={() => addWidget(w.type, w.title, w.size)}
                  className="w-full flex items-center justify-between p-3 bg-muted hover:bg-border rounded-lg transition-colors text-left"
                >
                  <div>
                    <p className="text-sm font-medium text-foreground">{w.title}</p>
                    <p className="text-[11px] text-muted-foreground">{w.size === 'full' ? 'Full width' : 'Half width'}</p>
                  </div>
                  <Plus className="w-4 h-4 text-muted-foreground" />
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
