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

export default function LiveTrafficPage() {
    const [flows, setFlows] = useState<Flow[]>([])
    const [packetsPerSec, setPacketsPerSec] = useState<number[]>([])

    useEffect(() => {
        const fetchFlows = async () => {
            try {
                const response = await fetch('http://localhost:8000/flows/recent')
                if (!response.ok) throw new Error('Failed to fetch')
                    const data = await response.json()
                    setFlows(data)

                    const now = Date.now() / 1000
                    const recentFlows = data.filter((f: any) => now - f.end_ts < 5)
                    const totalPackets = recentFlows.reduce((sum: number, f: any) => sum + f.packets, 0) / 5
                    setPacketsPerSec(prev => [...prev.slice(-59), totalPackets])
            } catch (error) {
                console.error('[v0] Fetch error:', error)
            }
        }

        fetchFlows()
        const interval = setInterval(fetchFlows, 1000)
        return () => clearInterval(interval)
    }, [])

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Live Traffic Monitor</h1>
        <p className="text-gray-500">Real-time packet analysis and flow data</p>
        </div>

        {/* Live Chart */}
        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-[#00eaff]/10 rounded-lg flex items-center justify-center">
        <Activity className="w-5 h-5 text-[#00eaff]" />
        </div>
        <div>
        <h3 className="font-semibold">Traffic Rate</h3>
        <p className="text-sm text-gray-500">Packets per second</p>
        </div>
        </div>
        <div className="flex items-center gap-2">
        <div className="w-2 h-2 bg-[#00eaff] rounded-full animate-pulse"></div>
        <span className="text-sm text-gray-500">Live</span>
        </div>
        </div>

        <div className="h-32 relative">
        <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        {packetsPerSec.length > 1 && (
            <polyline
            points={packetsPerSec.map((val, idx) => {
                const x = (idx / (packetsPerSec.length - 1)) * 100
                const max = Math.max(...packetsPerSec, 1)
                const y = 100 - (val / max) * 80
                return `${x},${y}`
            }).join(' ')}
            fill="none"
            stroke="#00eaff"
            strokeWidth="2"
            vectorEffect="non-scaling-stroke"
            />
        )}
        </svg>
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
        </tbody>
        </table>
        </div>
        </div>
        </div>
    )
}
