'use client'

import { useEffect, useState } from 'react'

interface Rule {
    id: number
    alert_id: number
    rule_type: string
    action: string
    target: string
    reason: string
    confidence: number
    status: string
    created_at: string
    hostname: string
    src_ip: string
    severity: string
    risk_score: number
}

export default function RulesPage() {
    const [rules, setRules] = useState<Rule[]>([])
    const [lastUpdate, setLastUpdate] = useState<string>('')

    useEffect(() => {
        fetchRules()
        const interval = setInterval(fetchRules, 5000)
        return () => clearInterval(interval)
    }, [])

    const fetchRules = async () => {
        try {
            const response = await fetch('http://localhost:8000/rules/recent')
            if (response.ok) {
                const data = await response.json()
                setRules(data)
                setLastUpdate(new Date().toLocaleTimeString())
            }
        } catch (error) {
            console.error('Failed to fetch rules:', error)
        }
    }

    const getActionBadgeColor = (action: string) => {
        switch (action) {
            case 'BLOCK':
                return 'bg-red-500/20 text-red-400 border-red-500/30'
            case 'RATE_LIMIT':
                return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30'
            case 'ALLOW':
                return 'bg-green-500/20 text-green-400 border-green-500/30'
            default:
                return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
        }
    }

    const getStatusBadgeColor = (status: string) => {
        switch (status) {
            case 'pending':
                return 'bg-blue-500/20 text-blue-400 border-blue-500/30'
            case 'applied':
                return 'bg-green-500/20 text-green-400 border-green-500/30'
            case 'rejected':
                return 'bg-red-500/20 text-red-400 border-red-500/30'
            default:
                return 'bg-gray-500/20 text-gray-400 border-gray-500/30'
        }
    }

    return (
        <div className="min-h-screen bg-black text-white p-8">
        <div className="max-w-7xl mx-auto">
        <div className="flex items-center justify-between mb-8">
        <div>
        <h1 className="text-4xl font-bold mb-2">Revenix Dashboard</h1>
        <p className="text-gray-400">AI-recommended firewall rules</p>
        </div>
        <div className="flex gap-4">
        <a
        href="/"
        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
        View Flows
        </a>
        <a
        href="/alerts"
        className="px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
        >
        View Alerts
        </a>
        </div>
        </div>

        <div className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-lg p-4 mb-6">
        <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
        Last updated: {lastUpdate}
        </p>
        <p className="text-sm text-gray-400">
        Showing {rules.length} rule recommendations
        </p>
        </div>
        </div>

        <div className="bg-gray-900/50 backdrop-blur-sm border border-gray-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full">
        <thead className="bg-gray-800/50">
        <tr>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Action
        </th>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Target
        </th>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Device
        </th>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Reason
        </th>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Confidence
        </th>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Status
        </th>
        <th className="px-6 py-4 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
        Time
        </th>
        </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
        {rules.length === 0 ? (
            <tr>
            <td colSpan={7} className="px-6 py-12 text-center text-gray-500">
            No rule recommendations yet
            </td>
            </tr>
        ) : (
            rules.map((rule) => (
                <tr
                key={rule.id}
                className="hover:bg-gray-800/30 transition-colors"
                >
                <td className="px-6 py-4">
                <span
                className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border ${getActionBadgeColor(
                    rule.action
                )}`}
                >
                {rule.action}
                </span>
                </td>
                <td className="px-6 py-4">
                <code className="text-sm bg-gray-800 px-2 py-1 rounded text-blue-400">
                {rule.target}
                </code>
                </td>
                <td className="px-6 py-4">
                <div className="flex flex-col">
                <span className="text-sm font-medium">{rule.hostname}</span>
                <span className="text-xs text-gray-500">{rule.src_ip}</span>
                </div>
                </td>
                <td className="px-6 py-4">
                <div className="flex items-start gap-2">
                <svg
                className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                >
                <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                />
                </svg>
                <p className="text-sm text-gray-300">{rule.reason}</p>
                </div>
                </td>
                <td className="px-6 py-4">
                <div className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                <div className="w-24 bg-gray-800 rounded-full h-2">
                <div
                className="bg-green-500 h-2 rounded-full"
                style={{ width: `${rule.confidence * 100}%` }}
                />
                </div>
                <span className="text-xs text-gray-400">
                {(rule.confidence * 100).toFixed(0)}%
                </span>
                </div>
                </div>
                </td>
                <td className="px-6 py-4">
                <span
                className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-medium border ${getStatusBadgeColor(
                    rule.status
                )}`}
                >
                {rule.status}
                </span>
                </td>
                <td className="px-6 py-4 text-sm text-gray-400 whitespace-nowrap">
                {new Date(rule.created_at).toLocaleString('en-US', {
                    month: 'short',
                    day: 'numeric',
                    year: 'numeric',
                    hour: 'numeric',
                    minute: '2-digit',
                    second: '2-digit',
                    hour12: true,
                })}
                </td>
                </tr>
            ))
        )}
        </tbody>
        </table>
        </div>
        </div>
        </div>
        </div>
    )
}
