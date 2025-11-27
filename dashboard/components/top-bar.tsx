'use client'

import { useEffect, useState } from 'react'
import { Bell, User } from 'lucide-react'

export function TopBar() {
    const [lastSync, setLastSync] = useState<Date>(new Date())

    useEffect(() => {
        const interval = setInterval(() => {
            setLastSync(new Date())
        }, 2000)
        return () => clearInterval(interval)
    }, [])

    return (
        <div className="h-16 bg-[#0C0C0C] border-b border-gray-800 flex items-center justify-between px-6 fixed top-0 right-0 left-64 z-10">
        {/* Organization Info */}
        <div>
        <h2 className="text-sm font-semibold text-white">My Organization</h2>
        <p className="text-xs text-gray-500">
        Last sync: {lastSync.toLocaleTimeString()}
        </p>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-4">
        {/* Notifications */}
        <button className="relative p-2 hover:bg-gray-900 rounded-lg transition-colors">
        <Bell className="w-5 h-5 text-gray-400" />
        <span className="absolute top-1 right-1 w-2 h-2 bg-[#ff4444] rounded-full"></span>
        </button>

        {/* User Avatar */}
        <button className="flex items-center gap-2 hover:bg-gray-900 rounded-lg p-2 transition-colors">
        <div className="w-8 h-8 bg-gradient-to-br from-[#00eaff] to-[#0099ff] rounded-full flex items-center justify-center">
        <User className="w-5 h-5 text-black" />
        </div>
        <span className="text-sm text-gray-300">Admin</span>
        </button>
        </div>
        </div>
    )
}
