'use client'

import { useEffect, useState } from 'react'
import { Activity } from 'lucide-react'

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

const CHART_STORAGE_KEY = 'revenix_live_traffic_chart'

export default function LiveTrafficPage() {
    const [flows, setFlows] = useState<Flow[]>([])
    const [currentStats, setCurrentStats] = useState({ packets: 0, bytes: 0 })
    const [chartData, setChartData] = useState<{ packets: number[], bytes: number[], timestamps: string[] }>(() => {
        if (typeof window !== 'undefined') {
            const stored = sessionStorage.getItem(CHART_STORAGE_KEY)
            if (stored) {
                try {
                    return JSON.parse(stored)
                } catch {}
            }
        }
        return {
            packets: Array(60).fill(0),
                                                                                                             bytes: Array(60).fill(0),
                                                                                                             timestamps: []
        }
    })
    const [activeFlowsCount, setActiveFlowsCount] = useState(0)

    useEffect(() => {
        if (typeof window !== 'undefined') {
            sessionStorage.setItem(CHART_STORAGE_KEY, JSON.stringify(chartData))
        }
    }, [chartData])

    useEffect(() => {
        const fetchFlows = async () => {
            try {
                const response = await fetch('http://localhost:8000/flows/recent')
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

                    setChartData(prev => ({
                        packets: [...prev.packets.slice(-59), packetsPerSec],
                                          bytes: [...prev.bytes.slice(-59), bytesPerSec],
                                          timestamps: [...prev.timestamps.slice(-59), new Date().toLocaleTimeString()]
                    }))
            } catch (error) {
                console.error('Fetch error:', error)
            }
        }

        fetchFlows()
        const interval = setInterval(fetchFlows, 1000)
        return () => clearInterval(interval)
    }, [])

    const maxPackets = Math.max(...chartData.packets, 100)
    const maxBytes = Math.max(...chartData.bytes, 10240)

    const formatBytes = (bytes: number) => {
        if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
            if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
                return `${bytes} B`
    }

    const yAxisLabels = {
        packets: [
            Math.round(maxPackets),
            Math.round(maxPackets * 0.75),
            Math.round(maxPackets * 0.5),
            Math.round(maxPackets * 0.25),
            0
        ],
        bytes: [
            maxBytes,
            Math.round(maxBytes * 0.75),
            Math.round(maxBytes * 0.5),
            Math.round(maxBytes * 0.25),
            0
        ]
    }

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Live Traffic Monitor</h1>
        <p className="text-gray-500">Real-time packet analysis and flow data</p>
        </div>

        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-[#00eaff]/10 rounded-lg flex items-center justify-center">
        <Activity className="w-5 h-5 text-[#00eaff]" />
        </div>
        <div>
        <h3 className="font-semibold">Traffic Rate</h3>
        <p className="text-sm text-gray-500">Real-time network activity</p>
        </div>
        </div>
        <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
        <div className="w-3 h-3 bg-[#00eaff] rounded"></div>
        <span className="text-xs text-gray-500">Packets/sec</span>
        </div>
        <div className="flex items-center gap-2">
        <div className="w-3 h-3 bg-purple-500 rounded"></div>
        <span className="text-xs text-gray-500">Bytes/sec</span>
        </div>
        <div className="flex items-center gap-2">
        <div className="w-2 h-2 bg-[#00eaff] rounded-full animate-pulse"></div>
        <span className="text-sm text-gray-500">Live</span>
        </div>
        </div>
        </div>

        <div className="h-48 relative bg-gray-950/50 rounded-lg p-4 flex">
        {/* Y-axis labels */}
        <div className="flex flex-col justify-between py-1 pr-2 text-xs text-gray-500 w-16">
        <span>{yAxisLabels.bytes[0]}</span>
        <span>{yAxisLabels.bytes[1]}</span>
        <span>{yAxisLabels.bytes[2]}</span>
        <span>{yAxisLabels.bytes[3]}</span>
        <span>{yAxisLabels.bytes[4]}</span>
        </div>

        {/* Chart */}
        <svg className="flex-1 h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        <defs>
        <linearGradient id="packetGradient" x1="0" x2="0" y1="0" y2="1">
        <stop offset="0%" stopColor="#00eaff" stopOpacity="0.3" />
        <stop offset="100%" stopColor="#00eaff" stopOpacity="0" />
        </linearGradient>
        <linearGradient id="byteGradient" x1="0" x2="0" y1="0" y2="1">
        <stop offset="0%" stopColor="#a855f7" stopOpacity="0.2" />
        <stop offset="100%" stopColor="#a855f7" stopOpacity="0" />
        </linearGradient>
        </defs>

        {/* Grid lines */}
        <line x1="0" y1="25" x2="100" y2="25" stroke="#374151" strokeWidth="0.2" opacity="0.5" />
        <line x1="0" y1="50" x2="100" y2="50" stroke="#374151" strokeWidth="0.2" opacity="0.5" />
        <line x1="0" y1="75" x2="100" y2="75" stroke="#374151" strokeWidth="0.2" opacity="0.5" />

        {/* Bytes chart (background) */}
        {chartData.bytes.length > 1 && (
            <>
            <polyline
            points={chartData.bytes.map((val, idx) => {
                const x = (idx / (chartData.bytes.length - 1)) * 100
                const y = 95 - ((val / maxBytes) * 85)
                return `${x},${y}`
            }).join(' ')}
            fill="none"
            stroke="#a855f7"
            strokeWidth="0.5"
            vectorEffect="non-scaling-stroke"
            opacity="0.6"
            />
            <polygon
            points={`0,95 ${chartData.bytes.map((val, idx) => {
                const x = (idx / (chartData.bytes.length - 1)) * 100
                const y = 95 - ((val / maxBytes) * 85)
                return `${x},${y}`
            }).join(' ')} 100,95`}
            fill="url(#byteGradient)"
            />
            </>
        )}

        {/* Packets chart (foreground) */}
        {chartData.packets.length > 1 && (
            <>
            <polyline
            points={chartData.packets.map((val, idx) => {
                const x = (idx / (chartData.packets.length - 1)) * 100
                const y = 95 - ((val / maxPackets) * 85)
                return `${x},${y}`
            }).join(' ')}
            fill="none"
            stroke="#00eaff"
            strokeWidth="0.8"
            vectorEffect="non-scaling-stroke"
            />
            <polygon
            points={`0,95 ${chartData.packets.map((val, idx) => {
                const x = (idx / (chartData.packets.length - 1)) * 100
                const y = 95 - ((val / maxPackets) * 85)
                return `${x},${y}`
            }).join(' ')} 100,95`}
            fill="url(#packetGradient)"
            />
            </>
        )}
        </svg>
        </div>

        <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-gray-800">
        <div>
        <p className="text-xs text-gray-500 mb-1">Current Packets/sec</p>
        <p className="text-xl font-bold text-[#00eaff]">
        {currentStats.packets}
        </p>
        </div>
        <div>
        <p className="text-xs text-gray-500 mb-1">Current Bytes/sec</p>
        <p className="text-xl font-bold text-purple-500">
        {(currentStats.bytes / 1024).toFixed(2)} KB
        </p>
        </div>
        <div>
        <p className="text-xs text-gray-500 mb-1">Active Flows</p>
        <p className="text-xl font-bold text-gray-300">{activeFlowsCount}</p>
        </div>
        </div>
        </div>

        {/* Flows Table */}
        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full">
        <thead className="bg-gray-900 border-b border-gray-800">
        <tr>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Packets</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Bytes</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
        </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
        {flows.slice(0, 50).map((flow, idx) => (
            <tr key={idx} className="hover:bg-gray-900/50 transition-colors">
            <td className="px-4 py-3 text-sm text-[#00eaff] font-medium">{flow.hostname}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-400">{flow.src_ip}:{flow.src_port || 0}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-400">{flow.dst_ip}:{flow.dst_port || 0}</td>
            <td className="px-4 py-3 text-sm">
            <span className="px-2 py-1 bg-gray-800 rounded text-xs">{flow.protocol}</span>
            </td>
            <td className="px-4 py-3 text-sm text-gray-300">{flow.packets.toLocaleString()}</td>
            <td className="px-4 py-3 text-sm text-gray-300">{(flow.bytes / 1024).toFixed(2)} KB</td>
            <td className="px-4 py-3 text-sm text-gray-500">
            {new Date(flow.end_ts * 1000).toLocaleTimeString()}
            </td>
            </tr>
        ))}
        {flows.length > 50 && (
            <tr>
            <td colSpan={7} className="px-4 py-3 text-sm text-center text-gray-500 bg-gray-900/30">
            Showing first 50 of {flows.length} total flows
            </td>
            </tr>
        )}
        </tbody>
        </table>
        </div>
        </div>
        </div>
    )
}
