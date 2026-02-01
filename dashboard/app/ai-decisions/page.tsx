"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

export default function AIDecisionsPage() {
    const router = useRouter()

    useEffect(() => {
        router.replace("/threats")
    }, [router])

    return (
        <div className="p-6 flex items-center justify-center h-64">
            <p className="text-muted-foreground text-sm">Redirecting to Threats...</p>
        </div>
    )
}
