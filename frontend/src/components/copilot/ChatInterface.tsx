'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Send,
  Sparkles,
  Bot,
  User,
  Copy,
  Check,
  ChevronDown,
  ChevronRight,
  Terminal,
} from 'lucide-react';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { askCopilot, getCopilotSuggestions } from '@/lib/api';
import { useSearchParams } from 'next/navigation';

interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  content: string;
  evidence?: string[];
  confidence?: 'low' | 'medium' | 'high';
  timestamp: string;
}

interface ChatInterfaceProps {
  sessionId?: string;
}

export function ChatInterface({ sessionId }: ChatInterfaceProps) {
  const searchParams = useSearchParams();
  const initialPrompt = searchParams.get('prompt') || '';

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      content:
        'Greetings, Security Analyst. I am MICHAEL – The Guardian AI Copilot. I analyze ingested log telemetry, evaluate multivariate anomaly clusters, investigate security incidents, and assist you with root-cause attribution and incident response playbooks. How may I assist your investigation today?',
      confidence: 'high',
      timestamp: new Date().toISOString(),
    },
  ]);
  const [input, setInput] = useState(initialPrompt);
  const [isLoading, setIsLoading] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [expandedEvidence, setExpandedEvidence] = useState<Record<string, boolean>>({});
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getCopilotSuggestions()
      .then((res) => {
        if (res.suggestions && res.suggestions.length > 0) {
          setSuggestions(res.suggestions);
        }
      })
      .catch(() => {
        setSuggestions([
          'What are the most critical anomalies detected?',
          'Explain the root cause of the latest incident.',
          'Which IP addresses performed unauthorized authentication attempts?',
          'What remediation steps should we execute right now?',
        ]);
      });
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  useEffect(() => {
    if (initialPrompt && messages.length === 1) {
      handleSend(initialPrompt);
    }
  }, [initialPrompt]);

  const handleSend = async (textToSend?: string) => {
    const query = (textToSend || input).trim();
    if (!query || isLoading) return;

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      sender: 'user',
      content: query,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const resp = await askCopilot(query, sessionId);

      const assistantMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        content: resp.answer,
        evidence: resp.evidence,
        confidence: resp.confidence,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch {
      const errorMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        content:
          'Unable to reach AI reasoning backend. Ensure the backend daemon is operational or retry your prompt.',
        confidence: 'low',
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const toggleEvidence = (id: string) => {
    setExpandedEvidence((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div
      style={{
        backgroundColor: '#0C1119',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: '12px',
        boxShadow: '0 4px 16px rgba(0, 0, 0, 0.35)',
      }}
      className="flex flex-col h-[700px] overflow-hidden font-sans"
    >
      {/* 1. Header */}
      <div className="p-4 border-b border-white/[0.06] flex items-center justify-between bg-[#080C12]">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-[#3B82F6]">
            <Sparkles size={16} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-[#F5F7FA]">
              Forensic Reasoning Workspace
            </h3>
            <p className="text-xs text-[#A7B1C0]">
              Autonomous investigation assistant
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Badge variant="cyan" size="sm">
            LLM Core Active
          </Badge>
        </div>
      </div>

      {/* 2. Chat Message Stream */}
      <div className="flex-1 overflow-y-auto p-5 space-y-4">
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          const isExp = expandedEvidence[msg.id];

          return (
            <div
              key={msg.id}
              className={`flex gap-3 max-w-3xl ${
                isUser ? 'ml-auto flex-row-reverse' : ''
              }`}
            >
              {/* Avatar */}
              <div
                className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 text-xs font-semibold ${
                  isUser
                    ? 'bg-[#3B82F6] text-white'
                    : 'bg-[#111823] border border-white/10 text-[#3B82F6]'
                }`}
              >
                {isUser ? <User size={13} /> : <Bot size={14} />}
              </div>

              {/* Message Bubble */}
              <div className="space-y-2 max-w-[85%]">
                <div
                  className={`p-4 rounded-xl text-xs leading-relaxed ${
                    isUser
                      ? 'bg-[#3B82F6] text-white'
                      : 'bg-[#111823] border border-white/[0.06] text-[#F5F7FA]'
                  }`}
                >
                  <div className="whitespace-pre-wrap">{msg.content}</div>

                  {!isUser && (
                    <div className="flex items-center justify-between pt-3 mt-3 border-t border-white/[0.06] text-[10px] text-[#A7B1C0]">
                      <div className="flex items-center gap-2">
                        {msg.confidence && (
                          <Badge
                            variant={
                              msg.confidence === 'high'
                                ? 'success'
                                : msg.confidence === 'medium'
                                ? 'warning'
                                : 'default'
                            }
                            size="sm"
                          >
                            {msg.confidence.toUpperCase()} CONFIDENCE
                          </Badge>
                        )}
                      </div>
                      <button
                        onClick={() => handleCopy(msg.id, msg.content)}
                        className="p-1 rounded hover:text-white transition-colors"
                      >
                        {copiedId === msg.id ? (
                          <Check size={11} className="text-[#22C55E]" />
                        ) : (
                          <Copy size={11} />
                        )}
                      </button>
                    </div>
                  )}
                </div>

                {/* Evidence Accordion (Assistant only) */}
                {msg.evidence && msg.evidence.length > 0 && (
                  <div className="rounded-lg bg-[#080C12] border border-white/[0.06] overflow-hidden text-xs">
                    <button
                      onClick={() => toggleEvidence(msg.id)}
                      className="w-full px-3 py-2 flex items-center justify-between text-[#A7B1C0] hover:text-[#F5F7FA] text-left transition-colors"
                    >
                      <span className="flex items-center gap-1.5 font-medium text-[11px]">
                        <Terminal size={12} className="text-[#3B82F6]" />
                        Supporting Telemetry Evidence ({msg.evidence.length} events)
                      </span>
                      {isExp ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                    </button>

                    {isExp && (
                      <div className="px-3 pb-3 space-y-1.5 font-mono text-[10px] text-slate-300 border-t border-white/[0.04] pt-2">
                        {msg.evidence.map((ev, i) => (
                          <div
                            key={i}
                            className="p-2 rounded bg-[#05070B] border border-white/[0.03] break-all select-all"
                          >
                            {ev}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {isLoading && (
          <div className="flex gap-3 max-w-xl">
            <div className="w-7 h-7 rounded-lg bg-[#111823] border border-white/10 flex items-center justify-center text-[#3B82F6] shrink-0">
              <Bot size={14} />
            </div>
            <div className="p-3.5 rounded-xl bg-[#111823] border border-white/[0.06] flex items-center gap-2 text-xs text-[#A7B1C0]">
              <span className="w-2 h-2 rounded-full bg-[#3B82F6] animate-ping" />
              <span>Analyzing telemetry graph and synthesizing forensic hypothesis...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* 3. Suggestions Strip */}
      {suggestions.length > 0 && (
        <div className="px-4 py-2.5 border-t border-white/[0.06] bg-[#080C12] flex items-center gap-2 overflow-x-auto">
          <span className="text-[11px] text-[#687589] shrink-0 font-medium">
            Suggested:
          </span>
          {suggestions.map((s, idx) => (
            <button
              key={idx}
              onClick={() => handleSend(s)}
              className="px-2.5 py-1 rounded-full text-[11px] text-[#A7B1C0] hover:text-[#F5F7FA] bg-white/[0.03] hover:bg-white/[0.06] border border-white/[0.06] transition-all whitespace-nowrap shrink-0"
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* 4. Prompt Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        className="p-4 border-t border-white/[0.06] bg-[#0C1119] flex items-center gap-2"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask MICHAEL Copilot about anomalies, incidents, remediation steps..."
          className="flex-1 bg-[#080C12] border border-white/[0.08] text-xs text-[#F5F7FA] placeholder-[#687589] rounded-lg px-4 py-2.5 focus:outline-none focus:border-[#3B82F6] transition-colors"
        />
        <Button
          type="submit"
          variant="primary"
          size="sm"
          disabled={!input.trim() || isLoading}
          leftIcon={<Send size={13} />}
        >
          Send
        </Button>
      </form>
    </div>
  );
}
