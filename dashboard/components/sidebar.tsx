'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { LayoutDashboard, Activity, GitBranch, Shield, Brain, FileText, Laptop, Settings, Heart } from 'lucide-react'

const navItems = [
    { href: '/', label: 'Dashboard', icon: LayoutDashboard },
{ href: '/live-traffic', label: 'Live Traffic', icon: Activity },
{ href: '/flows', label: 'Flows', icon: GitBranch },
{ href: '/threats', label: 'Threats', icon: Shield },
{ href: '/ai-decisions', label: 'AI Decisions', icon: Brain },
{ href: '/policies', label: 'Policies', icon: FileText },
{ href: '/endpoints', label: 'Endpoints', icon: Laptop },
{ href: '/system-health', label: 'System Health', icon: Heart },
{ href: '/settings', label: 'Settings', icon: Settings },
]

export function Sidebar() {
    const pathname = usePathname()

    return (
        <div className="h-screen w-64 bg-[#0C0C0C] border-r border-gray-800 flex flex-col fixed left-0 top-0">
        {/* Logo */}
        <div className="p-6 border-b border-gray-800">
        <div className="flex items-center gap-3">
        <div className="w-10 h-10 bg-gradient-to-br from-[#00eaff] to-[#0099ff] rounded-lg flex items-center justify-center">
        <Shield className="w-6 h-6 text-black" />
        </div>
        <div>
        <h1 className="text-xl font-bold text-white">Revenix</h1>
        <p className="text-xs text-gray-500">AI Firewall</p>
        </div>
        </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        {navItems.map((item) => {
            const Icon = item.icon
            const isActive = pathname === item.href

            return (
                <Link
                key={item.href}
                href={item.href}
                className={`
                    flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200
                    ${isActive
                        ? 'bg-[#00eaff]/10 text-[#00eaff] border border-[#00eaff]/20'
                        : 'text-gray-400 hover:bg-gray-900 hover:text-white'
                    }
                    `}
                    >
                    <Icon className="w-5 h-5" />
                    <span className="text-sm font-medium">{item.label}</span>
                    </Link>
            )
        })}
        </nav>

        {/* Footer */}
        <div className="p-4 border-t border-gray-800">
        <div className="text-xs text-gray-600 text-center">
        v1.0.0
        </div>
        </div>
        </div>
    )
}
