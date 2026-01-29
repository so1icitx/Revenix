/**
 * Auth helper with JWT tokens and bcrypt password hashing
 * Uses sessionStorage to require login on every restart/browser close
 */

import { API_URL } from './api-config'

export async function checkAuthRequired(): Promise<{ needsSignup: boolean; needsLogin: boolean }> {
    try {
        // Check if any users exist in the database
        const response = await fetch(`${API_URL}/auth/check-users`, {
            method: 'GET',
            cache: 'no-store',  // Prevent caching
        })

        console.log('[Auth] check-users response status:', response.status)

        if (response.ok) {
            const data = await response.json()
            console.log('[Auth] check-users response data:', data)
            const hasUsers = (data.user_count || 0) > 0
            console.log('[Auth] hasUsers:', hasUsers)

            // Check if user is logged in (using sessionStorage = clears on restart)
            const isLoggedIn = typeof window !== 'undefined' && sessionStorage.getItem('revenix_token') !== null
            console.log('[Auth] isLoggedIn:', isLoggedIn)

            if (!hasUsers) {
                console.log('[Auth] No users found - redirecting to SIGNUP')
                return { needsSignup: true, needsLogin: false }
            } else if (!isLoggedIn) {
                console.log('[Auth] Users exist but not logged in - redirecting to LOGIN')
                return { needsSignup: false, needsLogin: true }
            } else {
                console.log('[Auth] User logged in - allowing access')
                return { needsSignup: false, needsLogin: false }
            }
        } else {
            const errorText = await response.text()
            console.error('[Auth] check-users failed:', response.status, errorText)
        }

        // Default: assume login required if endpoint fails
        console.warn('[Auth] Defaulting to LOGIN (endpoint failed)')
        return { needsSignup: false, needsLogin: true }
    } catch (error) {
        console.error('[Auth] Check failed with exception:', error)
        // On error, check if we're on an auth page - if so, don't redirect
        if (typeof window !== 'undefined' && window.location.pathname.startsWith('/auth/')) {
            console.log('[Auth] Already on auth page, not redirecting')
            return { needsSignup: false, needsLogin: false }
        }
        return { needsSignup: false, needsLogin: true }
    }
}

export function getAuthToken(): string | null {
    if (typeof window === 'undefined') return null
    return sessionStorage.getItem('revenix_token')
}

export function setAuthToken(token: string) {
    if (typeof window !== 'undefined') {
        sessionStorage.setItem('revenix_token', token)
    }
}

export function getCurrentUser() {
    if (typeof window === 'undefined') return null
    const userData = sessionStorage.getItem('revenix_user')
    return userData ? JSON.parse(userData) : null
}

export function setCurrentUser(user: any, token: string) {
    if (typeof window !== 'undefined') {
        sessionStorage.setItem('revenix_user', JSON.stringify(user))
        sessionStorage.setItem('revenix_token', token)
    }
}

export function logout() {
    if (typeof window !== 'undefined') {
        sessionStorage.removeItem('revenix_user')
        sessionStorage.removeItem('revenix_token')
    }
}
