'use client'

import { useEffect, useState } from 'react'
import { Shield, AlertTriangle } from 'lucide-react'

interface Alert {
    id: number
    hostname: string
    risk_score: number
    severity: string
    reason: string
    src_ip: string
    dst_ip: string
    threat_category?: string
    timestamp: string
}

export default function ThreatsPage() {
    const [alerts, setAlerts] = useState<Alert[]>([])
    const [expandedAlert, setExpandedAlert] = useState<number | null>(null)

    useEffect(() => {
        const fetchAlerts = async () => {
            try {
                const response = await fetch('http://localhost:8000/alerts/recent')
                if (!response.ok) throw new Error('Failed to fetch')
                    const data = await response.json()
                    setAlerts(data)
            } catch (error) {
                console.error('[v0] Fetch error:', error)
            }
        }

        fetchAlerts()
        const interval = setInterval(fetchAlerts, 5000)
        return () => clearInterval(interval)
    }, [])

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'bg-[#ff4444]'
            case 'high': return 'bg-orange-500'
            case 'medium': return 'bg-yellow-500'
            case 'low': return 'bg-blue-500'
            default: return 'bg-gray-500'
        }
    }

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
        <div className="w-12 h-12 bg-[#ff4444]/10 rounded-lg flex items-center justify-center">
        <Shield className="w-6 h-6 text-[#ff4444]" />
        </div>
        <div>
        <h1 className="text-3xl font-bold">Threat Detection</h1>
        <p className="text-gray-500">AI-identified security threats and anomalies</p>
        </div>
        </div>
        </div>

        {/* Threat Stats */}
        <div className="grid grid-cols-4 gap-4 mb-6">
        {['critical', 'high', 'medium', 'low'].map(severity => {
            const count = alerts.filter(a => a.severity === severity).length
            return (
                <div key={severity} className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-4">
                <div className="flex items-center justify-between">
                <div>
                <p className="text-sm text-gray-500 capitalize">{severity}</p>
                <p className="text-2xl font-bold">{count}</p>
                </div>
                <div className={`w-3 h-3 rounded-full ${getSeverityColor(severity)}`}></div>
                </div>
                </div>
            )
        })}
        </div>

        {/* Threats Table */}
        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full">
        <thead className="bg-gray-900 border-b border-gray-800">
        <tr>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Category</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AI Analysis</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
        </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
        {alerts.map((alert) => (
            <>
            <tr
            key={alert.id}
            className="hover:bg-gray-900/50 transition-colors cursor-pointer"
            onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}
            >
            <td className="px-4 py-3">
            <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getSeverityColor(alert.severity)} text-white`}>
            {alert.severity}
            </span>
            </td>
            <td className="px-4 py-3 text-sm">
            {alert.threat_category && (
                <span className="px-2 py-1 bg-gray-800 rounded text-xs text-gray-400">
                {alert.threat_category.replace(/_/g, ' ').toUpperCase()}
                </span>
            )}
            </td>
            <td className="px-4 py-3">
            <div className="flex items-center gap-2">
            <div className="w-16 bg-gray-800 rounded-full h-1.5">
            <div
            className="h-1.5 rounded-full bg-gradient-to-r from-yellow-500 to-[#ff4444]"
            style={{ width: `${alert.risk_score * 100}%` }}
            />
            </div>
            <span className="text-xs text-gray-400">{(alert.risk_score * 100).toFixed(0)}%</span>
            </div>
            </td>
            <td className="px-4 py-3 text-sm text-[#00eaff] font-medium">{alert.hostname}</td>
            <td className="px-4 py-3 text-sm font-mono text-gray-400">{alert.src_ip}</td>
            <td className="px-4 py-3 text-sm text-gray-300 max-w-md">
            <div className="flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
            <p className="line-clamp-2">{alert.reason}</p>
            </div>
            </td>
            <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
            {new Date(alert.timestamp).toLocaleString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            })}
            </td>
            </tr>
            {expandedAlert === alert.id && (
                <tr key={`${alert.id}-expanded`} className="bg-gray-900/30">
                <td colSpan={7} className="px-4 py-4">
                <div className="space-y-3">
                <h4 className="text-sm font-semibold text-white">Complete Threat Analysis</h4>
                <p className="text-sm text-gray-400 leading-relaxed">{alert.reason}</p>
                </div>
                </td>
                </tr>
            )}
            </>
        ))}
        </tbody>
        </table>
        </div>
        </div>
        </div>
    )
}
