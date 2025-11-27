'use client'

import { type LucideIcon } from 'lucide-react'
import { ReactNode } from 'react'

interface DashboardCardProps {
    title: string
    value: string | number
    subtitle?: string
    icon: LucideIcon
    trend?: {
        value: string
        positive: boolean
    }
    sparkline?: number[]
    children?: ReactNode
}

export function DashboardCard({
    title,
    value,
    subtitle,
    icon: Icon,
    trend,
    sparkline,
    children
}: DashboardCardProps) {
    return (
        <div className="bg-gradient-to-br from-gray-900/50 to-gray-900/30 border border-gray-800 rounded-xl p-6 hover:border-[#00eaff]/30 transition-all duration-300 hover:shadow-lg hover:shadow-[#00eaff]/5">
        <div className="flex items-start justify-between mb-4">
        <div>
        <p className="text-sm text-gray-500 mb-1">{title}</p>
        <h3 className="text-3xl font-bold text-white">{value}</h3>
        {subtitle && (
            <p className="text-xs text-gray-600 mt-1">{subtitle}</p>
        )}
        </div>
        <div className="w-12 h-12 bg-[#00eaff]/10 rounded-lg flex items-center justify-center">
        <Icon className="w-6 h-6 text-[#00eaff]" />
        </div>
        </div>

        {trend && (
            <div className="flex items-center gap-2">
            <span className={`text-sm font-medium ${trend.positive ? 'text-green-500' : 'text-[#ff4444]'}`}>
            {trend.positive ? '↑' : '↓'} {trend.value}
            </span>
            <span className="text-xs text-gray-600">vs last hour</span>
            </div>
        )}

        {sparkline && sparkline.length > 0 && (
            <div className="mt-4 h-12">
            <Sparkline data={sparkline} />
            </div>
        )}

        {children}
        </div>
    )
}

function Sparkline({ data }: { data: number[] }) {
    const max = Math.max(...data)
    const min = Math.min(...data)
    const range = max - min || 1

    const points = data.map((value, index) => {
        const x = (index / (data.length - 1)) * 100
        const y = 100 - ((value - min) / range) * 100
        return `${x},${y}`
    }).join(' ')

    return (
        <svg className="w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        <polyline
        points={points}
        fill="none"
        stroke="url(#gradient)"
        strokeWidth="2"
        vectorEffect="non-scaling-stroke"
        />
        <defs>
        <linearGradient id="gradient" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stopColor="#00eaff" />
        <stop offset="100%" stopColor="#0099ff" />
        </linearGradient>
        </defs>
        </svg>
    )
}
