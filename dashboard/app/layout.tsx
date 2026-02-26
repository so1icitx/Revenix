import type React from "react"
import type { Metadata, Viewport } from "next"
import { Inter, JetBrains_Mono } from "next/font/google"
import "./globals.css"
import { AppShell } from "../components/app-shell"

const inter = Inter({ subsets: ["latin"] })
const jetbrainsMono = JetBrains_Mono({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Revenix - AI Firewall Dashboard",
  description: "Enterprise-grade AI-powered network security monitoring and threat intelligence",
  icons: {
    icon: "/icon.png",
  },
}

export const viewport: Viewport = {
  themeColor: "#09090B",
  width: "device-width",
  initialScale: 1,
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${inter.className}`}>
      <body className="bg-background text-foreground antialiased">
        <AppShell>{children}</AppShell>
      </body>
    </html>
  )
}
