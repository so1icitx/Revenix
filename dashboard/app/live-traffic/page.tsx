'use client'

import { API_URL } from '../../lib/api-config'
import { useEffect, useState } from 'react'
import { Activity } from 'lucide-react'
import { formatSofiaTime } from '../../lib/time'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

interface Flow {
  hostname: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  packets: number
  bytes: number
  end_ts: number
}

const tooltipStyle = {
  contentStyle: { backgroundColor: '#0F0F12', border: '1px solid #1E1E23', borderRadius: '8px', fontSize: '12px', color: '#FAFAFA' },
  labelStyle: { color: '#FAFAFA' },
  itemStyle: { color: '#FAFAFA' },
}

export default function LiveTrafficPage() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [currentStats, setCurrentStats] = useState({ packets: 0, bytes: 0 })
  const [chartData, setChartData] = useState<Array<{ time: string; packets: number; bytes: number }>>([])
  const [activeFlowsCount, setActiveFlowsCount] = useState(0)

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const response = await fetch(`${API_URL}/flows/recent`)
        if (!response.ok) throw new Error('Failed to fetch')
        const data = await response.json()
        const now = Date.now() / 1000
        const thirtySecondsAgo = now - 30
        const recentFlows = data.filter((f: any) => f.end_ts >= thirtySecondsAgo)
        const totalPackets = recentFlows.reduce((sum: number, f: any) => sum + (f.packets || 0), 0)
        const totalBytes = recentFlows.reduce((sum: number, f: any) => sum + (f.bytes || 0), 0)
        const packetsPerSec = Math.round(totalPackets / 30)
        const bytesPerSec = Math.round(totalBytes / 30)
        setCurrentStats({ packets: packetsPerSec, bytes: bytesPerSec })
        setActiveFlowsCount(data.length)
        setFlows(data)
        setChartData(prev => {
          const newPoint = { time: formatSofiaTime(Date.now()), packets: packetsPerSec, bytes: Math.round(bytesPerSec / 1024) }
          return [...prev.slice(-59), newPoint]
        })
      } catch (error) {
        console.error('Fetch error:', error)
      }
    }
    fetchFlows()
    const interval = setInterval(fetchFlows, 1000)
    return () => clearInterval(interval)
  }, [])

  const formatBytes = (bytes: number) => {
    if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${bytes} B`
  }

  return (
    <div className="p-6 space-y-5 animate-fadeIn">
      <div>
        <h1 className="text-2xl font-semibold text-foreground">Live Traffic</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Real-time packet analysis and flow data</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 gap-3">
        <div className="card-surface p-4">
          <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Packets/sec</p>
          <p className="text-2xl font-semibold text-primary mt-1">{currentStats.packets.toLocaleString()}</p>
        </div>
        <div className="card-surface p-4">
          <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Throughput</p>
          <p className="text-2xl font-semibold text-accent mt-1">{formatBytes(currentStats.bytes)}/s</p>
        </div>
        <div className="card-surface p-4">
          <p className="text-xs text-muted-foreground font-medium uppercase tracking-wider">Active Flows</p>
          <p className="text-2xl font-semibold text-foreground mt-1">{activeFlowsCount.toLocaleString()}</p>
        </div>
      </div>

      {/* Chart */}
      <div className="card-surface p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-medium text-foreground">Traffic Rate</h3>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-primary" />
              <span className="text-[11px] text-muted-foreground">Packets/sec</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full bg-accent" />
              <span className="text-[11px] text-muted-foreground">KB/sec</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-1.5 h-1.5 rounded-full bg-safe" />
              <span className="text-[10px] text-muted-foreground">Live</span>
            </div>
          </div>
        </div>
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="packetFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.15} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="byteFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.1} />
                  <stop offset="95%" stopColor="#38BDF8" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E1E23" />
              <XAxis dataKey="time" stroke="#71717A" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis stroke="#71717A" fontSize={10} tickLine={false} axisLine={false} />
              <Tooltip {...tooltipStyle} />
              <Area type="monotone" dataKey="packets" stroke="#3B82F6" strokeWidth={1.5} fill="url(#packetFill)" name="Packets/sec" />
              <Area type="monotone" dataKey="bytes" stroke="#38BDF8" strokeWidth={1.5} fill="url(#byteFill)" name="KB/sec" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Flows Table */}
      <div className="card-surface overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border">
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Device</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Source</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Destination</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Protocol</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Packets</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Bytes</th>
                <th className="px-4 py-3 text-left text-[11px] font-medium text-muted-foreground uppercase tracking-wider">Time</th>
              </tr>
            </thead>
            <tbody>
              {flows.map((flow, idx) => (
                <tr key={idx} className="border-b border-border last:border-0 hover:bg-muted/50 transition-colors">
                  <td className="px-4 py-2.5 text-sm text-primary font-medium">{flow.hostname}</td>
                  <td className="px-4 py-2.5 text-sm font-mono text-muted-foreground">{flow.src_ip}:{flow.src_port || 0}</td>
                  <td className="px-4 py-2.5 text-sm font-mono text-muted-foreground">{flow.dst_ip}:{flow.dst_port || 0}</td>
                  <td className="px-4 py-2.5 text-sm">
                    <span className="px-2 py-0.5 bg-muted rounded text-xs text-foreground">{flow.protocol}</span>
                  </td>
                  <td className="px-4 py-2.5 text-sm text-foreground">{flow.packets.toLocaleString()}</td>
                  <td className="px-4 py-2.5 text-sm text-foreground">{formatBytes(flow.bytes)}</td>
                  <td className="px-4 py-2.5 text-sm text-muted-foreground">
                    {formatSofiaTime(flow.end_ts * 1000, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
