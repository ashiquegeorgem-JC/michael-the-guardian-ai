'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Sparkles,
  X,
  Send,
  Loader2,
  Shield,
  HelpCircle,
  AlertTriangle,
  ChevronDown,
} from 'lucide-react';
import { askCopilot, getCopilotSuggestions, getSessions } from '@/lib/api';
import { CopilotResponse, LogSession } from '@/types';

interface Message {
  id: string;
  sender: 'user' | 'michael';
  text: string;
  confidence?: 'low' | 'medium' | 'high';
  evidence?: string[];
  suggestedActions?: string[];
  timestamp: string;
}

export function AskMichaelButton() {
  const [isOpen, setIsOpen] = useState(false);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([
    'Summarize current security posture',
    'Are there any brute force attacks?',
    'What critical IOCs have been detected?',
    'Explain recent anomaly clusters',
  ]);
  const [activeSessionId, setActiveSessionId] = useState<string | undefined>(undefined);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'michael',
      text: 'MICHAEL Cyber Defense Intelligence online. Ask me about active security telemetry, anomalous patterns, incident root causes, or IOC attribution.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Fetch active session and suggestions
    getSessions()
      .then((res) => {
        if (res.sessions && res.sessions.length > 0) {
          setActiveSessionId(res.sessions[res.sessions.length - 1].id);
        }
      })
      .catch(() => {});

    getCopilotSuggestions()
      .then((res) => {
        if (res.suggestions && res.suggestions.length > 0) {
          setSuggestions(res.suggestions.slice(0, 4));
        }
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isOpen]);

  const handleSend = async (queryToSend?: string) => {
    const q = (queryToSend || input).trim();
    if (!q || isLoading) return;

    const userMsg: Message = {
      id: `u-${Date.now()}`,
      sender: 'user',
      text: q,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const resp = await askCopilot(q, activeSessionId);
      const aiMsg: Message = {
        id: `m-${Date.now()}`,
        sender: 'michael',
        text: resp.answer || 'Analysis complete. No critical security deviations identified.',
        confidence: resp.confidence,
        evidence: resp.evidence,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, aiMsg]);
    } catch (err: any) {
      const errMsg: Message = {
        id: `err-${Date.now()}`,
        sender: 'michael',
        text: 'Telemetry query error: Unable to reach intelligence reasoning backend.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };
      setMessages((prev) => [...prev, errMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <>
      {/* ── Floating Ask Michael Button (Fixed Bottom-Right) ───────────────── */}
      <div className="fixed bottom-6 right-6 z-50">
        {!isOpen && (
          <button
            onClick={() => setIsOpen(true)}
            aria-label="Ask Michael Security Assistant"
            style={{
              backgroundColor: '#10151E',
              border: '1px solid rgba(56, 189, 248, 0.35)',
              boxShadow: '0 8px 30px rgba(0, 0, 0, 0.7)',
            }}
            className="flex items-center gap-2.5 px-4 py-2.5 rounded-full text-white text-xs font-medium hover:border-[#38BDF8] hover:bg-[#151C28] transition-all cursor-pointer group"
          >
            <span className="w-2 h-2 rounded-full bg-[#38BDF8] animate-pulse" />
            <Sparkles size={14} className="text-[#38BDF8] group-hover:rotate-12 transition-transform" />
            <span className="font-heading tracking-wide" style={{ fontFamily: "'Times New Roman', Times, serif" }}>
              Ask Michael
            </span>
          </button>
        )}
      </div>

      {/* ── Compact Floating Assistant Window ─────────────────────────────── */}
      {isOpen && (
        <div
          role="dialog"
          aria-labelledby="assistant-title"
          style={{
            backgroundColor: '#0C1017',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: 16,
            boxShadow: '0 16px 48px rgba(0, 0, 0, 0.85)',
          }}
          className="fixed bottom-6 right-6 z-50 w-[380px] sm:w-[420px] h-[520px] flex flex-col overflow-hidden font-sans text-slate-200 animate-in fade-in slide-in-from-bottom-4 duration-200"
        >
          {/* Header */}
          <div className="p-3.5 px-4 border-b border-white/[0.07] bg-[#0F141D] flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2.5">
              <span className="w-2 h-2 rounded-full bg-[#10B981]" />
              <div>
                <h3
                  id="assistant-title"
                  className="text-sm font-heading text-white font-normal leading-none"
                  style={{ fontFamily: "'Times New Roman', Times, serif" }}
                >
                  MICHAEL AI
                </h3>
                <span className="text-[10px] text-[#64748B] font-mono">
                  Autonomous Security Reasoning
                </span>
              </div>
            </div>

            <button
              onClick={() => setIsOpen(false)}
              className="text-[#94A3B8] hover:text-white p-1 rounded-md hover:bg-white/[0.06] transition-colors cursor-pointer"
              title="Close Assistant"
            >
              <X size={16} />
            </button>
          </div>

          {/* Conversation History */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3.5 text-xs">
            {messages.map((m) => (
              <div
                key={m.id}
                className={`flex flex-col ${
                  m.sender === 'user' ? 'items-end' : 'items-start'
                }`}
              >
                <div
                  style={{
                    backgroundColor:
                      m.sender === 'user' ? '#162030' : '#0F141D',
                    border: `1px solid ${
                      m.sender === 'user'
                        ? 'rgba(56, 189, 248, 0.3)'
                        : 'rgba(255, 255, 255, 0.06)'
                    }`,
                    borderRadius: 10,
                  }}
                  className="p-3 max-w-[88%] space-y-2 leading-relaxed"
                >
                  <p className="whitespace-pre-wrap">{m.text}</p>

                  {m.confidence && (
                    <div className="flex items-center gap-2 pt-1 border-t border-white/[0.06] text-[10px] text-[#94A3B8] font-mono">
                      <span>Confidence: {m.confidence.toUpperCase()}</span>
                      {m.evidence && m.evidence.length > 0 && (
                        <span>• Evidence: {m.evidence.length} logs</span>
                      )}
                    </div>
                  )}

                  {m.suggestedActions && m.suggestedActions.length > 0 && (
                    <div className="pt-1.5 space-y-1">
                      <span className="text-[10px] uppercase font-mono text-[#64748B] block">
                        Recommended Actions:
                      </span>
                      {m.suggestedActions.map((action, idx) => (
                        <div
                          key={idx}
                          className="text-[11px] text-[#38BDF8] bg-sky-500/10 px-2 py-1 rounded border border-sky-500/20"
                        >
                          • {action}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                <span className="text-[9px] text-[#64748B] font-mono px-1 mt-0.5">
                  {m.timestamp}
                </span>
              </div>
            ))}

            {isLoading && (
              <div className="flex items-center gap-2 text-xs text-[#94A3B8] p-2 bg-[#0F141D] rounded-lg border border-white/[0.05] w-fit">
                <Loader2 size={13} className="animate-spin text-[#38BDF8]" />
                <span className="font-mono text-[11px]">Evaluating telemetry signals...</span>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Quick Suggestions (if conversation is short) */}
          {messages.length <= 2 && !isLoading && (
            <div className="px-3 pb-2 pt-1 border-t border-white/[0.04] bg-[#0A0D13]">
              <div className="text-[10px] font-mono text-[#64748B] mb-1.5 uppercase tracking-wider">
                Quick Queries
              </div>
              <div className="flex flex-wrap gap-1.5">
                {suggestions.map((s, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSend(s)}
                    className="text-[10px] text-[#94A3B8] hover:text-white bg-white/[0.03] hover:bg-white/[0.08] px-2 py-1 rounded border border-white/[0.06] transition-colors truncate max-w-full cursor-pointer text-left"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Input Bar */}
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend();
            }}
            className="p-3 border-t border-white/[0.07] bg-[#0F141D] flex items-center gap-2 shrink-0"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask Michael about threats, logs, IOCs..."
              className="flex-1 bg-[#080B0F] border border-white/10 rounded-lg px-3 py-1.5 text-xs text-white placeholder-[#64748B] focus:outline-none focus:border-[#38BDF8] transition-colors"
            />
            <button
              type="submit"
              disabled={!input.trim() || isLoading}
              className="p-2 bg-[#162030] hover:bg-[#1E2C42] text-[#38BDF8] disabled:opacity-40 disabled:cursor-not-allowed rounded-lg border border-sky-500/30 transition-colors cursor-pointer"
              title="Send Query"
            >
              <Send size={13} />
            </button>
          </form>
        </div>
      )}
    </>
  );
}
