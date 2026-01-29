/**
 * WebSocket Client for Real-Time Updates
 * Replaces polling with instant push notifications
 */
import { io, Socket } from 'socket.io-client';

let socket: Socket | null = null;
const listeners = new Map<string, Set<Function>>();

/**
 * Initialize WebSocket connection
 */
export function initializeWebSocket(): Socket {
  if (socket) {
    return socket;
  }

  const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
  
  socket = io(API_URL, {
    transports: ['websocket', 'polling'],
    reconnection: true,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 5000,
    reconnectionAttempts: Infinity,
  });

  socket.on('connect', () => {
    console.log('[WebSocket] Connected to real-time updates');
    
    // Subscribe to all relevant channels
    socket?.emit('subscribe', {
      channels: ['alerts', 'flows', 'rules', 'endpoints']
    });
  });

  socket.on('disconnect', () => {
    console.log('[WebSocket] Disconnected');
  });

  socket.on('connected', (data) => {
    console.log('[WebSocket] Server confirmed:', data.message);
  });

  // Handle incoming events
  socket.on('alert', (data) => {
    notifyListeners('alert', data);
  });

  socket.on('flow', (data) => {
    notifyListeners('flow', data);
  });

  socket.on('rule', (data) => {
    notifyListeners('rule', data);
  });

  socket.on('system_health', (data) => {
    notifyListeners('system_health', data);
  });

  socket.on('endpoint_update', (data) => {
    notifyListeners('endpoint_update', data);
  });

  socket.on('threat_blocked', (data) => {
    notifyListeners('threat_blocked', data);
  });

  return socket;
}

/**
 * Subscribe to specific event type
 */
export function subscribeToEvent(eventType: string, callback: Function): () => void {
  if (!listeners.has(eventType)) {
    listeners.set(eventType, new Set());
  }
  
  listeners.get(eventType)!.add(callback);
  
  // Initialize socket if not already
  if (!socket) {
    initializeWebSocket();
  }
  
  // Return unsubscribe function
  return () => {
    listeners.get(eventType)?.delete(callback);
  };
}

/**
 * Notify all listeners for a specific event
 */
function notifyListeners(eventType: string, data: any): void {
  const eventListeners = listeners.get(eventType);
  if (eventListeners) {
    eventListeners.forEach(callback => {
      try {
        callback(data);
      } catch (error) {
        console.error(`[WebSocket] Error in ${eventType} listener:`, error);
      }
    });
  }
}

/**
 * Get socket instance
 */
export function getSocket(): Socket | null {
  return socket;
}

/**
 * Disconnect and cleanup
 */
export function disconnectWebSocket(): void {
  if (socket) {
    socket.disconnect();
    socket = null;
    listeners.clear();
  }
}

/**
 * Check if connected
 */
export function isConnected(): boolean {
  return socket !== null && socket.connected;
}
