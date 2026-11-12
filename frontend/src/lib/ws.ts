import { WsMessage } from '@/types';

type MessageHandler = (message: WsMessage) => void;

class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private listeners: Set<MessageHandler> = new Set();
  private reconnectTimeout: NodeJS.Timeout | null = null;
  private isConnected = false;

  constructor() {
    const defaultWs = (process.env.NEXT_PUBLIC_API_URL || 'https://michael-the-guardian-ai.onrender.com')
      .replace(/^http:/, 'ws:')
      .replace(/^https:/, 'wss:')
      .replace(/\/+$/, '');
    const wsBase = process.env.NEXT_PUBLIC_WS_URL || defaultWs;
    this.url = `${wsBase}/ws/monitoring`;
  }

  public connect() {
    if (typeof window === 'undefined') return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    try {
      this.ws = new WebSocket(this.url);

      this.ws.onopen = () => {
        this.isConnected = true;
      };

      this.ws.onmessage = (event) => {
        try {
          const data: WsMessage = JSON.parse(event.data);
          this.listeners.forEach((listener) => listener(data));
        } catch {
          // ignore parse errors
        }
      };

      this.ws.onclose = () => {
        this.isConnected = false;
        this.scheduleReconnect();
      };

      this.ws.onerror = () => {
        this.ws?.close();
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
    this.reconnectTimeout = setTimeout(() => {
      this.connect();
    }, 3000);
  }

  public subscribe(handler: MessageHandler): () => void {
    this.listeners.add(handler);
    if (!this.isConnected) {
      this.connect();
    }
    return () => {
      this.listeners.delete(handler);
      if (this.listeners.size === 0 && this.ws) {
        this.ws.close();
        this.ws = null;
      }
    };
  }

  public get connected() {
    return this.isConnected;
  }
}

export const wsClient = new WebSocketClient();
