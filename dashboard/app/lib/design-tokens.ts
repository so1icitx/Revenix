// Revenix Dashboard Design System
// Centralized design tokens for consistent UI across all pages

export const colors = {
    // Backgrounds
    bgMain: '#0A0A0A',
    bgCard: '#0A0A0A',
    bgCardHover: 'rgba(26, 26, 26, 0.5)',
    bgInput: '#111111',

    // Borders
    border: '#1A1A1A',
    borderHover: '#2A2A2A',

    // Accents
    accent: '#00eaff',
    accentHover: '#00d4e6',

    // Status colors (used for text/icons only, not backgrounds)
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    success: '#10b981',

    // Text
    textPrimary: '#ffffff',
    textSecondary: '#9ca3af',
    textTertiary: '#6b7280',
    textMuted: '#4b5563',
}

export const spacing = {
    cardPadding: 'p-6',
    cardGap: 'gap-6',
    sectionMargin: 'mb-8',
}

export const borders = {
    card: 'border border-[#1A1A1A] rounded-xl',
    input: 'border border-[#1A1A1A] rounded-lg',
    button: 'rounded-lg',
}

export const backgrounds = {
    card: 'bg-[#0A0A0A]',
    cardHover: 'hover:bg-[#1A1A1A]/50',
    input: 'bg-[#111111]',
}

export const transitions = {
    default: 'transition-all duration-200',
    fast: 'transition-all duration-150',
}

// Reusable component classes
export const components = {
    // Card with consistent styling
    card: `${backgrounds.card} ${borders.card} ${spacing.cardPadding} ${transitions.default}`,

    // Stat card
    statCard: `${backgrounds.card} ${borders.card} p-4 ${transitions.default} hover:scale-[1.02]`,

    // Primary button (accent color)
    buttonPrimary: `px-4 py-2 bg-[#00eaff] hover:bg-[#00d4e6] text-black font-medium ${borders.button} ${transitions.default}`,

    // Secondary button
    buttonSecondary: `px-4 py-2 bg-[#1A1A1A] hover:bg-[#2A2A2A] text-white ${borders.button} ${transitions.default}`,

    // Danger button
    buttonDanger: `px-4 py-2 bg-red-600 hover:bg-red-500 text-white ${borders.button} ${transitions.default}`,

    // Input field
    input: `px-4 py-2 ${backgrounds.input} ${borders.input} text-white focus:outline-none focus:border-[#00eaff] ${transitions.default}`,

    // Badge/tag
    badge: `px-2 py-1 ${backgrounds.card} ${borders.card} text-xs`,

    // Tab button
    tabActive: `px-4 py-2 bg-[#00eaff]/20 text-[#00eaff] border border-[#00eaff] ${borders.button} font-medium`,
    tabInactive: `px-4 py-2 bg-[#0A0A0A] text-gray-400 border border-[#1A1A1A] ${borders.button} hover:border-[#2A2A2A]`,
}

// Severity helpers (for text color only)
export const getSeverityColor = (severity: string): string => {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'text-red-500'
        case 'high': return 'text-orange-500'
        case 'medium': return 'text-yellow-500'
        case 'low': return 'text-blue-500'
        default: return 'text-gray-500'
    }
}

// Severity border accent (thin colored line, not full background)
export const getSeverityBorder = (severity: string): string => {
    switch (severity?.toLowerCase()) {
        case 'critical': return 'border-l-4 border-l-red-500'
        case 'high': return 'border-l-4 border-l-orange-500'
        case 'medium': return 'border-l-4 border-l-yellow-500'
        case 'low': return 'border-l-4 border-l-blue-500'
        default: return 'border-l-4 border-l-gray-500'
    }
}
