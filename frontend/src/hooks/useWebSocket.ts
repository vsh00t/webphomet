import { useEffect, useRef, useState, useCallback } from 'react';
import type { WsEvent } from '../types';

export function useWebSocket(sessionId?: string) {
  const ws = useRef<WebSocket | null>(null);
  const [events, setEvents] = useState<WsEvent[]>([]);
  const [connected, setConnected] = useState(false);

  const connect = useCallback(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host = window.location.host;
    const path = sessionId
      ? `${proto}://${host}/api/v1/ws/${sessionId}`
      : `${proto}://${host}/api/v1/ws`;

    const socket = new WebSocket(path);
    ws.current = socket;

    socket.onopen = () => setConnected(true);
    socket.onclose = () => {
      setConnected(false);
      // Auto-reconnect after 3s
      setTimeout(connect, 3000);
    };
    socket.onerror = () => socket.close();
    socket.onmessage = (e) => {
      try {
        const evt: WsEvent = JSON.parse(e.data);
        setEvents((prev) => [evt, ...prev].slice(0, 200));
      } catch { /* ignore */ }
    };
  }, [sessionId]);

  useEffect(() => {
    connect();
    return () => ws.current?.close();
  }, [connect]);

  const send = useCallback((data: any) => {
    ws.current?.send(JSON.stringify(data));
  }, []);

  return { events, connected, send };
}
