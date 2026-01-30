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
    <div className="card-surface-hover p-5">
      <div className="flex items-start justify-between mb-3">
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">{title}</p>
          <h3 className="text-2xl font-semibold text-foreground">{value}</h3>
          {subtitle && (
            <p className="text-[11px] text-muted-foreground mt-0.5">{subtitle}</p>
          )}
        </div>
        <div className="w-9 h-9 bg-primary/10 rounded-lg flex items-center justify-center">
          <Icon className="w-4 h-4 text-primary" />
        </div>
      </div>

      {trend && (
        <div className="flex items-center gap-2">
          <span className={`text-xs font-medium ${trend.positive ? 'text-safe' : 'text-danger'}`}>
            {trend.positive ? '+' : '-'} {trend.value}
          </span>
          <span className="text-[10px] text-muted-foreground">vs last hour</span>
        </div>
      )}

      {sparkline && sparkline.length > 0 && (
        <div className="mt-3 h-10">
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
        stroke="#3B82F6"
        strokeWidth="2"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}
