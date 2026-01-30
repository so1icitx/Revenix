'use client'

import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import { checkAuthRequired } from '../lib/auth'

export default function AuthGuard({ children }: { children: React.ReactNode }) {
    const router = useRouter()
    const pathname = usePathname()
    const [isChecking, setIsChecking] = useState(true)

    useEffect(() => {
        async function check() {
            // Don't check auth on auth pages
            if (pathname?.startsWith('/auth/')) {
                console.log('[AuthGuard] On auth page, skipping check')
                setIsChecking(false)
                return
            }

            console.log('[AuthGuard] Checking auth requirements...')
            const { needsSignup, needsLogin } = await checkAuthRequired()
            console.log('[AuthGuard] Result:', { needsSignup, needsLogin })
            
            if (needsSignup) {
                console.log('[AuthGuard] Redirecting to SIGNUP')
                router.push('/auth/signup')
            } else if (needsLogin) {
                console.log('[AuthGuard] Redirecting to LOGIN')
                router.push('/auth/login')
            } else {
                console.log('[AuthGuard] User authenticated, allowing access')
                setIsChecking(false)
            }
        }

        check()
    }, [pathname, router])

    if (isChecking) {
        return (
            <div className="min-h-screen bg-background flex items-center justify-center">
                <div className="text-muted-foreground text-sm">Loading...</div>
            </div>
        )
    }

    return <>{children}</>
}
