'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'

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

export default function Page() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [error, setError] = useState<string | null>(null)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())

  useEffect(() => {
    const fetchFlows = async () => {
      try {
        const possibleUrls = [
          'http://localhost:8000/flows/recent',
          'http://127.0.0.1:8000/flows/recent',
          `http://${window.location.hostname}:8000/flows/recent`
        ]

        let response = null
        let lastError = null

        for (const url of possibleUrls) {
          try {
            console.log('[v0] Trying URL:', url)
            response = await fetch(url, {
              mode: 'cors',
              headers: {
                'Accept': 'application/json',
              }
            })

            if (response.ok) {
              console.log('[v0] Success with URL:', url)
              break
            }
          } catch (err) {
            console.log('[v0] Failed with URL:', url, err)
            lastError = err
          }
        }

        if (!response || !response.ok) {
          throw lastError || new Error('Failed to fetch from all URLs')
        }

        const data = await response.json()

        console.log('[v0] Received flows:', data.length, 'flows')
        console.log('[v0] Sample flow:', data[0])

        setFlows(data)
        setLastUpdate(new Date())
        setError(null)
      } catch (err) {
        console.error('[v0] Fetch error:', err)
        setError(err instanceof Error ? err.message : 'Network error - cannot reach API')
      }
    }

    fetchFlows()
    const interval = setInterval(fetchFlows, 2000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="min-h-screen bg-gray-950 text-white p-8">
    <div className="max-w-7xl mx-auto">
    <div className="mb-8">
    <div className="flex items-center justify-between mb-4">
    <div>
    <h1 className="text-4xl font-bold mb-2">Revenix Dashboard</h1>
    <p className="text-gray-400">Real-time network flow monitoring</p>
    </div>
    <Link
    href="/alerts"
    className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors flex items-center gap-2"
    >
    <span>🚨</span>
    View Alerts
    </Link>
    </div>
    <p className="text-sm text-gray-500 mt-2">
    Last updated: {lastUpdate.toLocaleTimeString()}
    </p>
    </div>

    {error && (
      <div className="bg-red-900/20 border border-red-500 rounded-lg p-4 mb-6">
      <p className="text-red-400">Error: {error}</p>
      <p className="text-xs text-red-300 mt-2">
      Check browser console (F12) for details. API should be at http://localhost:8000
      </p>
      </div>
    )}

    <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
    <div className="overflow-x-auto">
    <table className="w-full">
    <thead className="bg-gray-800 border-b border-gray-700">
    <tr>
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
    Ports
    </th>
    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
    Protocol
    </th>
    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
    Packets
    </th>
    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
    Bytes
    </th>
    <th className="px-4 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
    Time
    </th>
    </tr>
    </thead>
    <tbody className="divide-y divide-gray-800">
    {flows.length === 0 ? (
      <tr>
      <td colSpan={8} className="px-4 py-8 text-center text-gray-500">
      No flows captured yet
      </td>
      </tr>
    ) : (
      flows.map((flow, idx) => (
        <tr key={idx} className="hover:bg-gray-800/50 transition-colors">
        <td className="px-4 py-3 text-sm font-medium text-blue-400">
        {flow.hostname}
        </td>
        <td className="px-4 py-3 text-sm font-mono text-gray-300">
        {flow.src_ip}
        </td>
        <td className="px-4 py-3 text-sm font-mono text-gray-300">
        {flow.dst_ip}
        </td>
        <td className="px-4 py-3 text-sm font-mono text-gray-400">
        {flow.src_port} → {flow.dst_port}
        </td>
        <td className="px-4 py-3 text-sm">
        <span className="px-2 py-1 bg-gray-800 rounded text-xs font-medium">
        {flow.protocol}
        </span>
        </td>
        <td className="px-4 py-3 text-sm text-gray-300">
        {flow.packets.toLocaleString()}
        </td>
        <td className="px-4 py-3 text-sm text-gray-300">
        {(flow.bytes / 1024).toFixed(2)} KB
        </td>
        <td className="px-4 py-3 text-sm text-gray-500">
        {new Date(flow.end_ts * 1000).toLocaleTimeString()}
        </td>
        </tr>
      ))
    )}
    </tbody>
    </table>
    </div>
    </div>

    <div className="mt-4 text-sm text-gray-500">
    Showing {flows.length} recent flows
    </div>
    </div>
    </div>
  )
}
