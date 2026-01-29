/**
 * Centralized API configuration for the dashboard
 * Uses environment variables with fallback to localhost for development
 */

export const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
export const BRAIN_URL = process.env.NEXT_PUBLIC_BRAIN_URL || 'http://localhost:8001';
