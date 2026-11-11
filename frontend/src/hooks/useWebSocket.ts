'use client';

import { useState, useEffect } from 'react';
import { wsClient } from '@/lib/ws';
import { WsMessage } from '@/types';

export function useWebSocket() {
  const [latestMetric, setLatestMetric] = useState<WsMessage | null>(null);
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<string[]>([]);
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    setConnected(wsClient.connected);

    const unsubscribe = wsClient.subscribe((msg: WsMessage) => {
      setConnected(true);
      if (msg.type === 'metrics') {
        setLatestMetric(msg);
        if (msg.data?.latest_event) {
          setEvents((prev) => [msg.data.latest_event, ...prev].slice(0, 50));
        }
      } else if (msg.type === 'anomaly_alert') {
        setAlerts((prev) => [msg, ...prev].slice(0, 20));
      }
    });

    return () => {
      unsubscribe();
    };
  }, []);

  return { latestMetric, connected, events, alerts };
}
