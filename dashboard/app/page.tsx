'use client'

import { useEffect, useState } from 'react'
import { DashboardCard } from '../components/dashboard-card'
import { Activity, Shield, Laptop, Heart } from 'lucide-react'

interface Stats {
  totalTraffic: number
  blockedThreats: number
  activeEndpoints: number
  systemHealth: number
  trafficSparkline: number[]
  threatBreakdown: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

export default function Page() {
  const [stats, setStats] = useState<Stats>({
    totalTraffic: 0,
    blockedThreats: 0,
    activeEndpoints: 0,
    systemHealth: 98,
    trafficSparkline: [],
    threatBreakdown: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }
  })

  useEffect(() => {
    const fetchStats = async () => {
      try {
        // Fetch flows for traffic stats
        const flowsRes = await fetch('http://localhost:8000/flows/recent')
        const flows = await flowsRes.json()

        // Fetch alerts for threat stats
        const alertsRes = await fetch('http://localhost:8000/alerts/recent')
        const alerts = await alertsRes.json()

        // Calculate total packets
        const totalPackets = flows.reduce((sum: number, flow: any) => sum + (flow.packets || 0), 0)

        // Count threats by severity
        const threatBreakdown = {
          critical: alerts.filter((a: any) => a.severity === 'critical').length,
            high: alerts.filter((a: any) => a.severity === 'high').length,
            medium: alerts.filter((a: any) => a.severity === 'medium').length,
            low: alerts.filter((a: any) => a.severity === 'low').length,
        }

        // Count unique devices
        const uniqueDevices = new Set(flows.map((f: any) => f.hostname)).size

        // Generate sparkline data
        const sparkline = Array.from({ length: 20 }, () => Math.floor(Math.random() * 100) + 50)

        setStats({
          totalTraffic: totalPackets,
          blockedThreats: alerts.length,
          activeEndpoints: uniqueDevices,
          systemHealth: 98,
          trafficSparkline: sparkline,
          threatBreakdown
        })
      } catch (error) {
        console.error('[v0] Failed to fetch stats:', error)
      }
    }

    fetchStats()
    const interval = setInterval(fetchStats, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="p-8 animate-fadeIn">
    <div className="mb-8">
    <h1 className="text-3xl font-bold mb-2">Security Overview</h1>
    <p className="text-gray-500">Real-time monitoring and threat intelligence</p>
    </div>

    {/* Main Stats Grid */}
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
    <DashboardCard
    title="Total Traffic Today"
    value={stats.totalTraffic.toLocaleString()}
    subtitle="packets processed"
    icon={Activity}
    trend={{ value: "12.5%", positive: true }}
    sparkline={stats.trafficSparkline}
    />

    <DashboardCard
    title="Blocked Threats (AI)"
    value={stats.blockedThreats}
    subtitle="malicious flows detected"
    icon={Shield}
    trend={{ value: "3.2%", positive: false }}
    >
    <div className="mt-4 space-y-2">
    <div className="flex justify-between text-xs">
    <span className="text-gray-500">Critical</span>
    <span className="text-[#ff4444] font-medium">{stats.threatBreakdown.critical}</span>
    </div>
    <div className="flex justify-between text-xs">
    <span className="text-gray-500">High</span>
    <span className="text-orange-500 font-medium">{stats.threatBreakdown.high}</span>
    </div>
    <div className="flex justify-between text-xs">
    <span className="text-gray-500">Medium</span>
    <span className="text-yellow-500 font-medium">{stats.threatBreakdown.medium}</span>
    </div>
    <div className="flex justify-between text-xs">
    <span className="text-gray-500">Low</span>
    <span className="text-blue-500 font-medium">{stats.threatBreakdown.low}</span>
    </div>
    </div>
    </DashboardCard>

    <DashboardCard
    title="Active Endpoints"
    value={stats.activeEndpoints}
    subtitle="devices monitored"
    icon={Laptop}
    >
    <div className="mt-4">
    <div className="flex items-center gap-2">
    <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
    <span className="text-xs text-gray-500">All systems operational</span>
    </div>
    </div>
    </DashboardCard>

    <DashboardCard
    title="System Health Score"
    value={`${stats.systemHealth}%`}
    subtitle="all systems nominal"
    icon={Heart}
    >
    <div className="mt-4">
    <div className="w-full bg-gray-800 rounded-full h-2">
    <div
    className="bg-gradient-to-r from-green-500 to-[#00eaff] h-2 rounded-full transition-all duration-500"
    style={{ width: `${stats.systemHealth}%` }}
    />
    </div>
    </div>
    </DashboardCard>
    </div>

    {/* Quick Actions */}
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <a href="/live-traffic" className="block bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 hover:border-[#00eaff]/30 transition-all duration-300 hover:shadow-lg hover:shadow-[#00eaff]/5 group">
    <div className="flex items-center gap-4">
    <div className="w-12 h-12 bg-[#00eaff]/10 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
    <Activity className="w-6 h-6 text-[#00eaff]" />
    </div>
    <div>
    <h3 className="font-semibold text-white">Live Traffic</h3>
    <p className="text-sm text-gray-500">Real-time packet analysis</p>
    </div>
    </div>
    </a>

    <a href="/threats" className="block bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 hover:border-[#ff4444]/30 transition-all duration-300 hover:shadow-lg hover:shadow-[#ff4444]/5 group">
    <div className="flex items-center gap-4">
    <div className="w-12 h-12 bg-[#ff4444]/10 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
    <Shield className="w-6 h-6 text-[#ff4444]" />
    </div>
    <div>
    <h3 className="font-semibold text-white">View Threats</h3>
    <p className="text-sm text-gray-500">Detected security events</p>
    </div>
    </div>
    </a>

    <a href="/ai-decisions" className="block bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 hover:border-purple-500/30 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/5 group">
    <div className="flex items-center gap-4">
    <div className="w-12 h-12 bg-purple-500/10 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform">
    <Activity className="w-6 h-6 text-purple-500" />
    </div>
    <div>
    <h3 className="font-semibold text-white">AI Decisions</h3>
    <p className="text-sm text-gray-500">Model insights & rules</p>
    </div>
    </div>
    </a>
    </div>
    </div>
  )
}
