'use client'

import { useEffect, useState } from 'react'
import { Brain } from 'lucide-react'

interface Rule {
    id: number
    action: string
    target: string
    hostname: string
    reason: string
    confidence: number
    status: string
    created_at: string
}

export default function AIDecisionsPage() {
    const [rules, setRules] = useState<Rule[]>([])

    useEffect(() => {
        const fetchRules = async () => {
            try {
                const response = await fetch('http://localhost:8000/rules/recommended')
                if (response.ok) {
                    const data = await response.json()
                    setRules(data || [])
                }
            } catch (error) {
                console.error('[v0] Fetch error:', error)
            }
        }

        fetchRules()
        const interval = setInterval(fetchRules, 5000)
        return () => clearInterval(interval)
    }, [])

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
        <div className="w-12 h-12 bg-purple-500/10 rounded-lg flex items-center justify-center">
        <Brain className="w-6 h-6 text-purple-500" />
        </div>
        <div>
        <h1 className="text-3xl font-bold">AI Decision Log</h1>
        <p className="text-gray-500">ML model decisions and firewall rule recommendations</p>
        </div>
        </div>
        </div>

        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
        <table className="w-full">
        <thead className="bg-gray-900 border-b border-gray-800">
        <tr>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Device</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reasoning</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Confidence</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
        <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
        </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
        {rules.map((rule) => (
            <tr key={rule.id} className="hover:bg-gray-900/50 transition-colors">
            <td className="px-4 py-3">
            <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                rule.action === 'BLOCK' ? 'bg-[#ff4444]/20 text-[#ff4444]' : 'bg-yellow-500/20 text-yellow-500'
            }`}>
            {rule.action}
            </span>
            </td>
            <td className="px-4 py-3 text-sm font-mono text-[#00eaff]">{rule.target}</td>
            <td className="px-4 py-3 text-sm text-gray-300">{rule.hostname}</td>
            <td className="px-4 py-3 text-sm text-gray-400 max-w-md truncate">{rule.reason}</td>
            <td className="px-4 py-3">
            <div className="flex items-center gap-2">
            <div className="w-20 bg-gray-800 rounded-full h-1.5">
            <div
            className="h-1.5 rounded-full bg-gradient-to-r from-[#00eaff] to-green-500"
            style={{ width: `${rule.confidence * 100}%` }}
            />
            </div>
            <span className="text-xs text-gray-400">{(rule.confidence * 100).toFixed(0)}%</span>
            </div>
            </td>
            <td className="px-4 py-3">
            <span className="px-2 py-1 bg-gray-800 rounded text-xs text-gray-400">{rule.status}</span>
            </td>
            <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
            {new Date(rule.created_at).toLocaleString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: true
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
