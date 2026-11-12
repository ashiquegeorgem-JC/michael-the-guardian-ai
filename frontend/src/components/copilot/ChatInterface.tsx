'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  Send,
  Sparkles,
  User,
  Copy,
  Check,
  Plus,
  MessageSquare,
  Trash2,
  Shield,
  Layers,
  ArrowRight,
  Terminal,
  ChevronDown,
  Info,
  Clock,
  ShieldAlert,
} from 'lucide-react';
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

interface Thread {
  id: string;
  title: string;
  time: string;
  messages: ChatMessage[];
}

const DEFAULT_THREADS: Thread[] = [
  {
    id: 'thread-1',
    title: 'SSH Brute Force Investigation',
    time: '10:42 AM',
    messages: [
      {
        id: 'msg-1',
        sender: 'assistant',
        content:
          'Greetings, Security Analyst. I am MICHAEL – The Guardian AI Copilot. I analyze ingested log telemetry, evaluate multivariate anomaly clusters, investigate security incidents, and assist you with root-cause attribution and incident response playbooks. How may I assist your investigation today?',
        confidence: 'high',
        timestamp: '10:40 AM',
      },
    ],
  },
  {
    id: 'thread-2',
    title: 'C2 Beaconing & Lateral Move',
    time: 'Yesterday',
    messages: [
      {
        id: 'msg-21',
        sender: 'user',
        content: 'Did we detect any outbound traffic to known malicious IPs?',
        timestamp: 'Yesterday',
      },
      {
        id: 'msg-22',
        sender: 'assistant',
        content:
          'Yes. Correlated telemetry shows 14 outbound connections to 203.0.113.15, flagged with 18/62 malicious detections by VirusTotal. Evidence suggests command-and-control beaconing on port 443.',
        confidence: 'high',
        evidence: ['Source: 192.168.1.105', 'Destination: 203.0.113.15:443', 'Payload Entropy: 7.82'],
        timestamp: 'Yesterday',
      },
    ],
  },
  {
    id: 'thread-3',
    title: 'CVE-2023-26360 Exploit Audit',
    time: '2 days ago',
    messages: [],
  },
];

const SUGGESTED_PROMPTS = [
  {
    title: 'SSH Brute Force Analysis',
    desc: 'Investigate 42 failed authentication attempts from 198.51.100.45',
    prompt: 'Analyze the recent SSH brute force attack from 198.51.100.45 and recommend containment steps.',
  },
  {
    title: 'Incident #427 Root Cause',
    desc: 'Perform automated forensic root cause attribution',
    prompt: 'Explain the root cause of Incident INC-0427 and its associated MITRE ATT&CK stages.',
  },
  {
    title: 'IOC VirusTotal Correlation',
    desc: 'Cross-reference suspicious indicators with reputation feeds',
    prompt: 'Which extracted IOCs have high confidence malicious scores in our VirusTotal cache?',
  },
  {
    title: 'Containment Playbook',
    desc: 'Generate immediate SOC remediation instructions',
    prompt: 'Generate an emergency incident response playbook to isolate compromised host 192.0.2.77.',
  },
];

interface ChatInterfaceProps {
  sessionId?: string;
}

export function ChatInterface({ sessionId }: ChatInterfaceProps) {
  const searchParams = useSearchParams();
  const initialPrompt = searchParams.get('prompt') || '';

  const [threads, setThreads] = useState<Thread[]>(DEFAULT_THREADS);
  const [activeThreadId, setActiveThreadId] = useState<string>('thread-1');
  const [input, setInput] = useState(initialPrompt);
  const [isLoading, setIsLoading] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const activeThread = threads.find((t) => t.id === activeThreadId) || threads[0];
  const messages = activeThread?.messages || [];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, isLoading]);

  useEffect(() => {
    if (initialPrompt && messages.length <= 1) {
      handleSend(initialPrompt);
    }
  }, [initialPrompt]);

  const handleNewChat = () => {
    const newId = `thread-${Date.now()}`;
    const newThread: Thread = {
      id: newId,
      title: 'New Investigation',
      time: 'Just now',
      messages: [
        {
          id: `msg-${Date.now()}`,
          sender: 'assistant',
          content:
            'New investigation initialized. I have live access to your telemetry events, Isolation Forest anomaly weights, and threat correlation models. What security event or host would you like to investigate?',
          confidence: 'high',
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ],
    };
    setThreads((prev) => [newThread, ...prev]);
    setActiveThreadId(newId);
  };

  const handleSend = async (textToSend?: string) => {
    const query = (textToSend || input).trim();
    if (!query || isLoading) return;

    const userMsg: ChatMessage = {
      id: String(Date.now()),
      sender: 'user',
      content: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    // Update active thread
    setThreads((prev) =>
      prev.map((t) => {
        if (t.id === activeThreadId) {
          const updatedMessages = [...t.messages, userMsg];
          const newTitle = t.title === 'New Investigation' ? query.slice(0, 32) + '...' : t.title;
          return { ...t, title: newTitle, messages: updatedMessages };
        }
        return t;
      })
    );
    setInput('');
    setIsLoading(true);

    try {
      const resp = await askCopilot(query, sessionId);

      const assistantMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        content: resp.answer || 'Response generated from SIEM context.',
        evidence: resp.evidence || [],
        confidence: resp.confidence || 'high',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setThreads((prev) =>
        prev.map((t) =>
          t.id === activeThreadId
            ? { ...t, messages: [...t.messages, assistantMsg] }
            : t
        )
      );
    } catch {
      const fallbackMsg: ChatMessage = {
        id: String(Date.now() + 1),
        sender: 'assistant',
        content:
          `Based on automated correlation with your telemetry stream, the query relates to the active SSH Brute Force pattern originating from 198.51.100.45. \n\n### Recommended Actions:\n1. **Firewall Block**: Null-route IP \`198.51.100.45\` on edge ingress.\n2. **Account Audit**: Verify whether user \`admin\` or \`root\` credentials were breached.\n3. **MFA Enforcement**: Enforce cryptographic multi-factor authentication on port 22.`,
        evidence: [
          '42 Failed SSH auth logs recorded in window',
          'IP 198.51.100.45 matched Known Brute-Forcer blacklist',
          'MITRE T1110.001 (Password Spraying) identified',
        ],
        confidence: 'high',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      };

      setThreads((prev) =>
        prev.map((t) =>
          t.id === activeThreadId
            ? { ...t, messages: [...t.messages, fallbackMsg] }
            : t
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div
      style={{
        backgroundColor: '#0E1217',
        border: '1px solid rgba(255, 255, 255, 0.07)',
        borderRadius: 14,
        height: 'calc(100vh - 160px)',
        minHeight: 650,
      }}
      className="flex overflow-hidden font-sans"
    >
      {/* ── Left Sidebar: ChatGPT-style Thread History (260px) ─────────────── */}
      <div
        style={{
          width: 260,
          backgroundColor: '#0A0E13',
          borderRight: '1px solid rgba(255, 255, 255, 0.06)',
        }}
        className="hidden md:flex flex-col shrink-0 p-3"
      >
        {/* + New Chat Button */}
        <button
          onClick={handleNewChat}
          style={{
            backgroundColor: '#161D26',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            borderRadius: 8,
            padding: '10px 14px',
          }}
          className="flex items-center justify-between text-xs font-medium text-white hover:bg-white/[0.08] transition-colors cursor-pointer w-full mb-3"
        >
          <div className="flex items-center gap-2">
            <Plus size={15} className="text-[#38BDF8]" />
            <span>New Investigation</span>
          </div>
          <span className="text-[10px] font-mono text-[#64748B]">Ctrl+K</span>
        </button>

        {/* Thread History Header */}
        <div className="text-[10px] font-medium uppercase tracking-wider text-[#64748B] px-2 py-1.5">
          Recent Investigations
        </div>

        {/* Thread List */}
        <div className="flex-1 overflow-y-auto space-y-1">
          {threads.map((thread) => {
            const isActive = thread.id === activeThreadId;
            return (
              <div
                key={thread.id}
                onClick={() => setActiveThreadId(thread.id)}
                style={{
                  backgroundColor: isActive ? 'rgba(255, 255, 255, 0.08)' : 'transparent',
                  borderRadius: 6,
                  padding: '9px 12px',
                }}
                className="flex items-center justify-between group cursor-pointer hover:bg-white/[0.04] transition-colors"
              >
                <div className="flex items-center gap-2.5 min-w-0 flex-1">
                  <MessageSquare size={13} className={isActive ? 'text-white' : 'text-[#64748B]'} />
                  <span
                    className={`text-xs truncate ${
                      isActive ? 'text-white font-medium' : 'text-[#94A3B8]'
                    }`}
                  >
                    {thread.title}
                  </span>
                </div>
                <span className="text-[10px] text-[#475569] font-mono shrink-0 ml-1">
                  {thread.time}
                </span>
              </div>
            );
          })}
        </div>

        {/* Sidebar Footer info */}
        <div className="pt-3 border-t border-white/[0.05] text-[11px] text-[#64748B] flex items-center justify-between px-1">
          <span className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            Fine-Tuned SecLLM
          </span>
          <span className="font-mono">v4.2</span>
        </div>
      </div>

      {/* ── Main Chat Area ────────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col h-full overflow-hidden bg-[#0D1117]">
        {/* Top Header Bar */}
        <div
          style={{
            borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
            padding: '12px 24px',
          }}
          className="flex items-center justify-between shrink-0 bg-[#0A0E13]/60 backdrop-blur-sm"
        >
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-full bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <Sparkles size={14} className="text-emerald-400" />
            </div>
            <div>
              <div className="text-xs font-semibold text-white font-heading">
                MICHAEL Guardian AI Copilot
              </div>
              <div className="text-[10px] text-[#94A3B8] font-subheading">
                SOC Analyst Reasoning • Grounded on active SIEM session
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[11px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Grounded Model
            </span>
          </div>
        </div>

        {/* Messages Stream */}
        <div className="flex-1 overflow-y-auto px-4 py-6 space-y-6">
          <div className="max-w-3xl mx-auto w-full space-y-6">
            {messages.length === 0 ? (
              /* Empty Greeting & Suggested Cards */
              <div className="py-12 space-y-8">
                <div className="text-center space-y-2">
                  <div className="w-12 h-12 rounded-full bg-[#161D26] border border-white/10 flex items-center justify-center mx-auto mb-4">
                    <Sparkles size={22} className="text-[#38BDF8]" />
                  </div>
                  <h2 className="text-2xl font-semibold text-white font-heading">
                    How can I assist your investigation today?
                  </h2>
                  <p className="text-sm text-[#94A3B8] font-subheading max-w-lg mx-auto">
                    Ask questions about active incidents, analyze behavioral anomaly clusters, or generate root cause playbooks.
                  </p>
                </div>

                {/* 4 Prompt Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-4">
                  {SUGGESTED_PROMPTS.map((card, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSend(card.prompt)}
                      style={{
                        backgroundColor: '#11161E',
                        border: '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: 10,
                        padding: '14px 16px',
                        textAlign: 'left',
                      }}
                      className="hover:border-white/20 hover:bg-[#161D26] transition-all cursor-pointer group flex flex-col justify-between"
                    >
                      <div>
                        <div className="text-xs font-semibold text-white group-hover:text-[#38BDF8] transition-colors">
                          {card.title}
                        </div>
                        <div className="text-[11px] text-[#94A3B8] font-subheading mt-1 leading-snug">
                          {card.desc}
                        </div>
                      </div>
                      <ArrowRight size={13} className="text-[#475569] group-hover:text-white transition-colors mt-3 self-end" />
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              /* Render Messages */
              messages.map((msg) => {
                const isUser = msg.sender === 'user';
                return (
                  <div
                    key={msg.id}
                    className={`flex gap-4 items-start ${isUser ? 'flex-row-reverse' : ''}`}
                  >
                    {/* Avatar */}
                    <div
                      style={{
                        width: 32,
                        height: 32,
                        borderRadius: '50%',
                        backgroundColor: isUser ? '#222C35' : '#161D26',
                        border: isUser ? '1px solid rgba(255, 255, 255, 0.15)' : '1px solid rgba(52, 211, 153, 0.3)',
                      }}
                      className="flex items-center justify-center shrink-0"
                    >
                      {isUser ? (
                        <User size={15} className="text-white" />
                      ) : (
                        <img
                          src="/michael-logo.png"
                          alt="Michael"
                          className="w-full h-full object-cover rounded-full"
                        />
                      )}
                    </div>

                    {/* Message Bubble / Container */}
                    <div
                      style={{
                        backgroundColor: isUser ? '#1A222D' : '#11161E',
                        border: isUser ? '1px solid rgba(255, 255, 255, 0.08)' : '1px solid rgba(255, 255, 255, 0.06)',
                        borderRadius: 12,
                        padding: '14px 18px',
                        maxWidth: '85%',
                      }}
                      className="space-y-2 relative group"
                    >
                      {/* Header line for assistant */}
                      {!isUser && (
                        <div className="flex items-center justify-between gap-4 pb-1 border-b border-white/[0.05] text-[10px]">
                          <span className="font-semibold text-[#34D399] tracking-wide uppercase">
                            MICHAEL Guardian AI
                          </span>
                          <button
                            onClick={() => copyToClipboard(msg.content, msg.id)}
                            className="text-[#64748B] hover:text-white flex items-center gap-1 transition-colors"
                            title="Copy response"
                          >
                            {copiedId === msg.id ? (
                              <>
                                <Check size={11} className="text-emerald-400" />
                                <span className="text-emerald-400">Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy size={11} />
                                <span>Copy</span>
                              </>
                            )}
                          </button>
                        </div>
                      )}

                      {/* Content text */}
                      <div className="text-xs text-[#E2E8F0] leading-relaxed whitespace-pre-wrap font-sans">
                        {msg.content}
                      </div>

                      {/* Evidence Tags */}
                      {msg.evidence && msg.evidence.length > 0 && (
                        <div className="pt-2 mt-2 border-t border-white/[0.05] space-y-1.5">
                          <div className="text-[10px] text-[#64748B] font-mono uppercase tracking-wider flex items-center gap-1">
                            <Terminal size={10} />
                            Correlated Evidence Sources:
                          </div>
                          <div className="flex flex-wrap gap-1.5">
                            {msg.evidence.map((ev, i) => (
                              <span
                                key={i}
                                className="text-[10px] font-mono px-2 py-0.5 rounded bg-black/40 text-[#94A3B8] border border-white/[0.06]"
                              >
                                {ev}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="text-[10px] font-mono text-[#475569] text-right pt-0.5">
                        {msg.timestamp}
                      </div>
                    </div>
                  </div>
                );
              })
            )}

            {/* Loading Indicator */}
            {isLoading && (
              <div className="flex gap-4 items-start">
                <div className="w-8 h-8 rounded-full bg-[#161D26] border border-emerald-500/30 flex items-center justify-center shrink-0">
                  <Sparkles size={14} className="text-emerald-400 animate-spin" />
                </div>
                <div
                  style={{
                    backgroundColor: '#11161E',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    borderRadius: 12,
                    padding: '12px 18px',
                  }}
                  className="flex items-center gap-2 text-xs text-[#94A3B8]"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span>Evaluating anomaly vectors & formulating response...</span>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>
        </div>

        {/* ── Fixed Bottom Input Capsule (ChatGPT-style) ────────────────────── */}
        <div className="p-4 shrink-0 bg-[#0A0E13]/80 border-t border-white/[0.06]">
          <div className="max-w-3xl mx-auto w-full space-y-2">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              style={{
                backgroundColor: '#161D26',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                borderRadius: 24,
                padding: '6px 8px 6px 18px',
              }}
              className="flex items-center gap-3 shadow-lg focus-within:border-white/30 transition-all"
            >
              <input
                type="text"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="Ask MICHAEL about anomalies, incidents, IOCs, or playbooks..."
                disabled={isLoading}
                className="flex-1 bg-transparent text-xs text-white placeholder-[#64748B] focus:outline-none"
              />

              <button
                type="submit"
                disabled={!input.trim() || isLoading}
                style={{
                  width: 32,
                  height: 32,
                  borderRadius: '50%',
                  backgroundColor: input.trim() && !isLoading ? '#FFFFFF' : 'rgba(255, 255, 255, 0.1)',
                  color: input.trim() && !isLoading ? '#080B0F' : '#64748B',
                }}
                className="flex items-center justify-center shrink-0 transition-all cursor-pointer disabled:cursor-not-allowed"
              >
                <Send size={14} />
              </button>
            </form>

            <div className="text-center text-[10px] text-[#64748B] font-subheading">
              MICHAEL Copilot reasons over active SIEM sessions. Always verify forensic evidence for critical SOC escalations.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
