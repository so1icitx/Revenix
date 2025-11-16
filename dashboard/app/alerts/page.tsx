'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'

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
    created_at: string
}

export default function AlertsPage() {
    const [alerts, setAlerts] = useState<Alert[]>([])
    const [error, setError] = useState<string | null>(null)
    const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

    useEffect(() => {
        const fetchAlerts = async () => {
            try {
                const response = await fetch('http://localhost:8000/alerts/recent')
                if (!response.ok) throw new Error('Failed to fetch alerts')
                    const data = await response.json()
                    setAlerts(data)
                    setLastUpdate(new Date())
                    setError(null)
            } catch (err) {
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

    return (
        <div className="min-h-screen bg-gray-950 text-white p-8">
        <div className="max-w-7xl mx-auto">
        <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
        <div>
        <h1 className="text-4xl font-bold mb-2">Security Alerts</h1>
        <p className="text-gray-400">AI-detected threats and anomalies</p>
        </div>
        <Link
        href="/"
        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
        View Flows
        </Link>
        </div>
        <p className="text-sm text-gray-500">
        Last updated: {lastUpdate.toLocaleTimeString()}
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
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        AI Reason
        </th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Time
        </th>
        </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
        {alerts.length === 0 ? (
            <tr>
            <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
            No alerts detected yet
            </td>
            </tr>
        ) : (
            alerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-gray-800/50 transition-colors">
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
                <td className="px-4 py-3 text-sm text-gray-300 max-w-md">
                <div className="flex items-start gap-2">
                <span className="text-yellow-500 mt-0.5">⚠</span>
                <span>{alert.reason}</span>
                </div>
                </td>
                <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
                {new Date(alert.created_at).toLocaleString()}
                </td>
                </tr>
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
