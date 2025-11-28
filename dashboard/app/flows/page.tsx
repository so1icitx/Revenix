'use client'

import { useEffect, useState } from 'react'

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
    anomaly_score?: number
}

export default function FlowsPage() {
    const [flows, setFlows] = useState<Flow[]>([])

    useEffect(() => {
        const fetchFlows = async () => {
            try {
                const response = await fetch('http://localhost:8000/flows/recent')
                if (!response.ok) throw new Error('Failed to fetch')
                    const data = await response.json()
                    setFlows(data)
            } catch (error) {
                console.error('[v0] Fetch error:', error)
            }
        }

        fetchFlows()
        const interval = setInterval(fetchFlows, 2000)
        return () => clearInterval(interval)
    }, [])

    const getRowColor = (score?: number) => {
        if (!score) return ''
            if (score >= 0.8) return 'bg-[#ff4444]/10 border-l-4 border-[#ff4444]'
                if (score >= 0.6) return 'bg-yellow-500/10 border-l-4 border-yellow-500'
                    return ''
    }

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Network Flows</h1>
        <p className="text-gray-500">Historical flow data and aggregated traffic</p>
        </div>

        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full">
        <thead className="bg-gray-900 border-b border-gray-800">
        <tr>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Dest</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Src Port</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Dst Port</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Packets</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Bytes</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Anomaly</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
        </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
        {flows.map((flow, idx) => (
            <tr key={idx} className={`hover:bg-gray-900/50 transition-colors ${getRowColor(flow.anomaly_score)}`}>
            <td className="px-4 py-3 text-sm text-[#00eaff] font-medium">{flow.hostname}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-400">{flow.src_ip}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-400">{flow.dst_ip}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-500">{flow.src_port || '-'}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-500">{flow.dst_port || '-'}</td>
            <td className="px-4 py-3 text-sm">
            <span className="px-2 py-1 bg-gray-800 rounded text-xs">{flow.protocol}</span>
            </td>
            <td className="px-4 py-3 text-sm text-gray-300">{flow.packets.toLocaleString()}</td>
            <td className="px-4 py-3 text-sm text-gray-300">{(flow.bytes / 1024).toFixed(2)} KB</td>
            <td className="px-4 py-3">
            {flow.anomaly_score !== undefined ? (
                <div className="flex items-center gap-2">
                <div className="w-16 bg-gray-800 rounded-full h-1.5">
                <div
                className={`h-1.5 rounded-full ${
                    flow.anomaly_score >= 0.8 ? 'bg-[#ff4444]' :
                    flow.anomaly_score >= 0.6 ? 'bg-yellow-500' :
                    'bg-green-500'
                }`}
                style={{ width: `${flow.anomaly_score * 100}%` }}
                />
                </div>
                <span className={`text-xs font-medium ${
                    flow.anomaly_score >= 0.8 ? 'text-[#ff4444]' :
                    flow.anomaly_score >= 0.6 ? 'text-yellow-500' :
                    'text-green-500'
                }`}>
                {(flow.anomaly_score * 100).toFixed(0)}%
                </span>
                </div>
            ) : (
                <span className="text-xs text-gray-600">-</span>
            )}
            </td>
            <td className="px-4 py-3 text-sm text-gray-500">
            {new Date(flow.end_ts * 1000).toLocaleString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            })}
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
