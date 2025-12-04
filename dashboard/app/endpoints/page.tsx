'use client'

import { useEffect, useState } from 'react'
import { Laptop, Activity, Network, Shield, Brain } from 'lucide-react'

interface DeviceProfile {
    hostname: string
    trained: boolean
    flow_count: number
    baseline?: {
        avg_bytes_per_flow: number
        avg_packets_per_flow: number
        common_destinations_count: number
        common_ports_count: number
    }
    autoencoder?: {
        trained: boolean
        threshold: number | null
        encoding_dim: number
    }
}

export default function EndpointsPage() {
    const [devices, setDevices] = useState<DeviceProfile[]>([])

    useEffect(() => {
        const fetchDevices = async () => {
            try {
                const response = await fetch('http://localhost:8001/devices/profiles')
                if (response.ok) {
                    const data = await response.json()
                    console.log('[v0] Devices fetched:', data)
                    setDevices(data.profiles || [])
                }
            } catch (error) {
                console.error('[v0] Fetch error:', error)
            }
        }

        fetchDevices()
        const interval = setInterval(fetchDevices, 5000)
        return () => clearInterval(interval)
    }, [])

    const formatBytes = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`
            if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
                return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    }

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
        <div className="w-12 h-12 bg-[#00eaff]/10 rounded-lg flex items-center justify-center">
        <Laptop className="w-6 h-6 text-[#00eaff]" />
        </div>
        <div>
        <h1 className="text-3xl font-bold">Endpoint Monitoring</h1>
        <p className="text-gray-500">Connected devices with AI-powered behavioral analysis</p>
        </div>
        </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {devices.map((device, idx) => (
            <div key={idx} className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 hover:border-[#00eaff]/30 transition-all">
            <div className="flex items-start justify-between mb-4">
            <div>
            <h3 className="font-semibold text-white mb-1">{device.hostname}</h3>
            <p className="text-xs text-gray-500">
            {device.flow_count} flows analyzed
            </p>
            </div>
            <div className={`w-3 h-3 rounded-full ${device.trained ? 'bg-green-500' : 'bg-yellow-500'} animate-pulse`}></div>
            </div>

            <div className="space-y-3 pt-4 border-t border-gray-800">
            <div className="flex justify-between text-sm">
            <span className="text-gray-500">Isolation Forest</span>
            <span className={device.trained ? 'text-green-500' : 'text-yellow-500'}>
            {device.trained ? 'Trained' : 'Learning...'}
            </span>
            </div>

            {device.autoencoder && (
                <div className="flex justify-between text-sm">
                <span className="text-gray-500 flex items-center gap-1">
                <Brain className="w-3 h-3" />
                Autoencoder
                </span>
                <span className={device.autoencoder.trained ? 'text-green-500' : 'text-yellow-500'}>
                {device.autoencoder.trained ? 'Trained' : 'Learning...'}
                </span>
                </div>
            )}

            {device.baseline && (
                <>
                <div className="flex items-center gap-2 text-sm">
                <Activity className="w-4 h-4 text-[#00eaff]" />
                <span className="text-gray-500">Avg Flow Size</span>
                <span className="ml-auto text-white">
                {formatBytes(device.baseline.avg_bytes_per_flow)}
                </span>
                </div>

                <div className="flex items-center gap-2 text-sm">
                <Network className="w-4 h-4 text-[#00eaff]" />
                <span className="text-gray-500">Avg Packets/Flow</span>
                <span className="ml-auto text-white">
                {device.baseline.avg_packets_per_flow.toFixed(1)}
                </span>
                </div>

                <div className="flex items-center gap-2 text-sm">
                <Shield className="w-4 h-4 text-[#00eaff]" />
                <span className="text-gray-500">Known Destinations</span>
                <span className="ml-auto text-white">
                {device.baseline.common_destinations_count}
                </span>
                </div>
                </>
            )}

            {device.autoencoder?.trained && device.autoencoder.threshold && (
                <div className="mt-3 pt-3 border-t border-gray-800">
                <div className="text-xs text-gray-500 mb-1">AI Detection Models</div>
                <div className="flex gap-2">
                <div className="flex-1 bg-green-500/10 border border-green-500/30 rounded px-2 py-1 text-center">
                <div className="text-[10px] text-green-500">IF Model</div>
                </div>
                <div className="flex-1 bg-green-500/10 border border-green-500/30 rounded px-2 py-1 text-center">
                <div className="text-[10px] text-green-500">Autoencoder</div>
                </div>
                </div>
                </div>
            )}
            </div>
            </div>
        ))}
        </div>

        {devices.length === 0 && (
            <div className="text-center py-12 text-gray-500">
            No devices detected yet. Waiting for network traffic...
            </div>
        )}
        </div>
    )
}
