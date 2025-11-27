'use client'

import { useEffect, useState } from 'react'
import { Laptop } from 'lucide-react'

export default function EndpointsPage() {
    const [devices, setDevices] = useState<any[]>([])

    useEffect(() => {
        const fetchDevices = async () => {
            try {
                const response = await fetch('http://localhost:8001/devices/profiles')
                if (response.ok) {
                    const data = await response.json()
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

    return (
        <div className="p-8 animate-fadeIn">
        <div className="mb-8">
        <div className="flex items-center gap-4 mb-4">
        <div className="w-12 h-12 bg-[#00eaff]/10 rounded-lg flex items-center justify-center">
        <Laptop className="w-6 h-6 text-[#00eaff]" />
        </div>
        <div>
        <h1 className="text-3xl font-bold">Endpoint Monitoring</h1>
        <p className="text-gray-500">Connected devices and behavioral profiles</p>
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

            <div className="space-y-2 pt-4 border-t border-gray-800">
            <div className="flex justify-between text-sm">
            <span className="text-gray-500">Status</span>
            <span className={device.trained ? 'text-green-500' : 'text-yellow-500'}>
            {device.trained ? 'Profile Trained' : 'Learning...'}
            </span>
            </div>
            </div>
            </div>
        ))}
        </div>
        </div>
    )
}
