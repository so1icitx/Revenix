import type { Metadata } from 'next'
import './globals.css'
import { Sidebar } from '../components/sidebar'
import { TopBar } from '../components/top-bar'

export const metadata: Metadata = {
    title: 'Revenix AI Firewall',
    description: 'Enterprise-grade AI-powered network security',
}

export default function RootLayout({
    children,
}: {
    children: React.ReactNode
}) {
    return (
        <html lang="en">
        <body className="bg-[#0C0C0C] text-white antialiased">
        <Sidebar />
        <TopBar />
        <main className="ml-64 mt-16 min-h-screen">
        {children}
        </main>
        </body>
        </html>
    )
}
