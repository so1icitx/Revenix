'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { formatSofiaDateTime, formatSofiaTime } from '../../lib/time'
import { API_URL } from '../../lib/api-config'

interface Alert {
    id: number
    flow_id: string
    hostname: string
    risk_score: number
    severity: string
    reason: string
    src_ip: string
    dst_ip: string
    protocol?: string
    threat_category?: string
    timestamp?: number  // Unix timestamp from API
    created_at?: string  // Legacy ISO string format
}

export default function AlertsPage() {
    const [alerts, setAlerts] = useState<Alert[]>([])
    const [error, setError] = useState<string | null>(null)
    const [lastUpdate, setLastUpdate] = useState<Date>(new Date())
    const [expandedAlert, setExpandedAlert] = useState<number | null>(null)  // Track expanded alert for full explanation

    useEffect(() => {
        const fetchAlerts = async () => {
            try {
                const response = await fetch(`${API_URL}/alerts/recent`)
                if (!response.ok) throw new Error('Failed to fetch alerts')
                const data = await response.json()
                setAlerts(data)
                setLastUpdate(new Date())
                setError(null)
            } catch (err) {
                console.error('Fetch error:', err)
                setError(err instanceof Error ? err.message : 'Network error')
            }
        }

        fetchAlerts()
        const interval = setInterval(fetchAlerts, 5000)
        return () => clearInterval(interval)
    }, [])

    const getSeverityColor = (severity: string) => {
        switch (severity.toLowerCase()) {
            case 'critical': return 'bg-red-500 text-white'
            case 'high': return 'bg-orange-500 text-white'
            case 'medium': return 'bg-yellow-500 text-black'
            case 'low': return 'bg-blue-500 text-white'
            default: return 'bg-gray-500 text-white'
        }
    }

    const getThreatCategoryBadge = (category?: string) => {
        if (!category) return null

        const categoryColors: Record<string, string> = {
            'port_scan': 'bg-purple-600',
            'ddos_attack': 'bg-red-600',
            'botnet_c2': 'bg-orange-600',
            'data_exfiltration': 'bg-red-700',
            'brute_force': 'bg-yellow-600',
            'dns_tunneling': 'bg-blue-600',
            'anomalous_behavior': 'bg-gray-600'
        }

        const color = categoryColors[category] || 'bg-gray-600'
        const label = category.replace(/_/g, ' ').toUpperCase()

        return (
            <span className={`${color} text-white px-2 py-1 rounded text-xs font-bold`}>
                {label}
            </span>
        )
    }

    return (
        <div className="min-h-screen bg-gray-950 text-white p-8">
            <div className="max-w-7xl mx-auto">
                <div className="mb-8">
                    <div className="flex items-center justify-between mb-4">
                        <div>
                            <h1 className="text-4xl font-bold mb-2">Security Alerts</h1>
                            <p className="text-gray-400">AI-detected threats with detailed explanations</p>
                        </div>
                        <div className="flex gap-3">
                            <Link
                                href="/"
                                className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
                            >
                                View Flows
                            </Link>
                            <Link
                                href="/rules"
                                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors"
                            >
                                View Rules
                            </Link>
                        </div>
                    </div>
                    <p className="text-sm text-gray-500">
                        Last updated: {formatSofiaTime(lastUpdate)}
                    </p>
                </div>

                {error && (
                    <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-6">
                        <p className="text-red-400">Error: {error}</p>
                    </div>
                )}

                <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead className="bg-gray-800 border-b border-gray-700">
                                <tr>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Threat Type  {/* Added threat type column */}
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Severity
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Risk Score
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Hostname
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Source IP
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Dest IP
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-1/3">
                                        AI Threat Analysis
                                    </th>
                                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                                        Time
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-800">
                                {alerts.length === 0 ? (
                                    <tr>
                                        <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
                                            No alerts detected yet
                                        </td>
                                    </tr>
                                ) : (
                                    alerts.map((alert) => (
                                        <>
                                            <tr
                                                key={alert.id}
                                                className="hover:bg-gray-800/50 transition-colors cursor-pointer"
                                                onClick={() => setExpandedAlert(expandedAlert === alert.id ? null : alert.id)}
                                            >
                                                <td className="px-4 py-3 text-sm">
                                                    {getThreatCategoryBadge(alert.threat_category)}
                                                </td>
                                                <td className="px-4 py-3 text-sm">
                                                    <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase ${getSeverityColor(alert.severity)}`}>
                                                        {alert.severity}
                                                    </span>
                                                </td>
                                                <td className="px-4 py-3 text-sm">
                                                    <div className="flex items-center gap-2">
                                                        <div className="w-20 bg-gray-800 rounded-full h-2">
                                                            <div
                                                                className="h-2 rounded-full bg-gradient-to-r from-yellow-500 to-red-500"
                                                                style={{ width: `${alert.risk_score * 100}%` }}
                                                            />
                                                        </div>
                                                        <span className="text-gray-300 font-medium">
                                                            {(alert.risk_score * 100).toFixed(0)}%
                                                        </span>
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3 text-sm font-medium text-blue-400">
                                                    {alert.hostname}
                                                </td>
                                                <td className="px-4 py-3 text-sm font-mono text-gray-300">
                                                    {alert.src_ip}
                                                </td>
                                                <td className="px-4 py-3 text-sm font-mono text-gray-300">
                                                    {alert.dst_ip}
                                                </td>
                                                <td className="px-4 py-3 text-sm text-gray-300">
                                                    <div className="flex items-start gap-2">
                                                        <span className="text-yellow-500 mt-0.5 flex-shrink-0">⚠</span>
                                                        <div className="flex-1">
                                                            <p className={expandedAlert === alert.id ? "" : "line-clamp-2"}>
                                                                {alert.reason}
                                                            </p>
                                                            <button
                                                                className="text-blue-400 hover:text-blue-300 text-xs mt-1"
                                                                onClick={(e) => {
                                                                    e.stopPropagation()
                                                                    setExpandedAlert(expandedAlert === alert.id ? null : alert.id)
                                                                }}
                                                            >
                                                                {expandedAlert === alert.id ? 'Show less' : 'Read full analysis →'}
                                                            </button>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
                                                    {formatSofiaDateTime(alert.timestamp ?? alert.created_at)}
                                                </td>
                                            </tr>
                                            {expandedAlert === alert.id && (
                                                <tr key={`${alert.id}-expanded`} className="bg-gray-800/30">
                                                    <td colSpan={8} className="px-4 py-4">
                                                        <div className="space-y-3">
                                                            {alert.threat_category && (
                                                                <div className="flex items-center gap-2 pb-2 border-b border-gray-700">
                                                                    <span className="text-xs text-gray-500">Threat Classification:</span>
                                                                    {getThreatCategoryBadge(alert.threat_category)}
                                                                </div>
                                                            )}
                                                            <div>
                                                                <h4 className="text-sm font-semibold text-gray-300 mb-2">Complete Threat Analysis:</h4>
                                                                <p className="text-sm text-gray-400 leading-relaxed">
                                                                    {alert.reason}
                                                                </p>
                                                            </div>
                                                            <div className="grid grid-cols-2 gap-4 pt-3 border-t border-gray-700">
                                                                <div>
                                                                    <p className="text-xs text-gray-500">Protocol</p>
                                                                    <p className="text-sm text-gray-300 font-medium">{alert.protocol || 'TCP'}</p>
                                                                </div>
                                                                <div>
                                                                    <p className="text-xs text-gray-500">Flow ID</p>
                                                                    <p className="text-sm text-gray-300 font-mono">{alert.flow_id.substring(0, 8)}...</p>
                                                                </div>
                                                            </div>
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </>
                                    ))
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="mt-4 text-sm text-gray-500">
                    Showing {alerts.length} alerts
                </div>
            </div>
        </div>
    )
}
