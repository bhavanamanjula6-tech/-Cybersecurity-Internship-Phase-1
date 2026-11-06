/**
 * CyberOps SOC — AI Security Copilot Drawer
 *
 * Slide-over right drawer providing authenticated conversational AI advisory.
 * Backed authoritatively by POST /api/copilot/chat and GET /api/copilot/status.
 *
 * Security Invariants:
 * 1. Read-only advisory UI: never exposes buttons for autonomous containment or mutation.
 * 2. Mandatory human-in-the-loop verification badge on every AI response turn.
 * 3. Authoritative backend role boundaries: never fakes permissions or bypasses errors.
 * 4. Zero secret leakage: no client-side API keys or @google/genai imports.
 */

import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  X,
  Send,
  AlertTriangle,
  Shield,
  Sparkles,
  RefreshCw,
  Trash2,
  ChevronDown,
  Info,
  Clock,
  CheckCircle2,
  AlertCircle,
  FileText,
  Target,
  Wrench,
  Activity,
  Layers,
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { UserRole, ROLE_METADATA } from '../../types/auth';
import { CopilotContextType } from '../../server/ai/types';
import { useCopilot, CopilotMessage } from '../../hooks/useCopilot';

interface CopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  defaultContextType?: CopilotContextType;
  defaultEntityId?: string;
}

const CONTEXT_LABELS: Record<CopilotContextType, { label: string; icon: React.FC<{ className?: string }> }> = {
  alert_triage: { label: 'Alert Triage', icon: Target },
  mitre_analysis: { label: 'MITRE Analysis', icon: Layers },
  remediation_task: { label: 'Remediation Task', icon: Wrench },
  platform_health: { label: 'Platform Health', icon: Activity },
  general_soc: { label: 'General SOC Advisory', icon: Shield },
};

const ROLE_PROMPT_SUGGESTIONS: Record<UserRole, { title: string; prompt: string; contextType: CopilotContextType }[]> = {
  soc_analyst: [
    {
      title: 'Analyze command line artifacts',
      prompt: 'Analyze the process execution and command line artifacts in this alert to determine intent.',
      contextType: 'alert_triage',
    },
    {
      title: 'Recommend priority escalation',
      prompt: 'Based on the observed evidence and affected asset criticality, what priority should this alert be?',
      contextType: 'alert_triage',
    },
    {
      title: 'Triage checklist for PowerShell',
      prompt: 'Provide a structured triage checklist for investigating suspicious encoded PowerShell activity.',
      contextType: 'general_soc',
    },
  ],
  security_engineer: [
    {
      title: 'Analyze MITRE ATT&CK coverage',
      prompt: 'Analyze detection coverage and mitigation recommendations for technique T1059.001 (PowerShell).',
      contextType: 'mitre_analysis',
    },
    {
      title: 'Draft Sigma detection rule',
      prompt: 'Provide detection engineering guidance and Sigma rule logic for detecting base64 encoded command arguments.',
      contextType: 'mitre_analysis',
    },
    {
      title: 'Defense-in-depth gaps',
      prompt: 'Identify common defensive gaps across execution and persistence tactics in enterprise environments.',
      contextType: 'mitre_analysis',
    },
  ],
  it_operations: [
    {
      title: 'Host containment verification',
      prompt: 'What verification steps should IT Operations execute before re-enabling network connectivity on an isolated endpoint?',
      contextType: 'remediation_task',
    },
    {
      title: 'Remediation task checklist',
      prompt: 'What are the recommended recovery and patching steps for the assigned containment task?',
      contextType: 'remediation_task',
    },
    {
      title: 'Credential reset guidance',
      prompt: 'Best practices for securing service accounts after suspicious authentication anomalies.',
      contextType: 'general_soc',
    },
  ],
  super_admin: [
    {
      title: 'Platform diagnostics summary',
      prompt: 'Summarize system diagnostics, platform operational health, and administrative governance policies.',
      contextType: 'platform_health',
    },
    {
      title: 'Audit log governance review',
      prompt: 'What tamper-evident audit logging controls are enforced for SOC operational actions?',
      contextType: 'platform_health',
    },
    {
      title: 'Role-based access boundaries',
      prompt: 'Explain the platform isolation boundaries between Super Admin and operational SOC telemetry.',
      contextType: 'platform_health',
    },
  ],
};

export const CopilotDrawer: React.FC<CopilotDrawerProps> = ({
  isOpen,
  onClose,
  defaultContextType = 'general_soc',
  defaultEntityId,
}) => {
  const { currentUser } = useAuth();
  const [inputText, setInputText] = useState('');
  const [contextDropdownOpen, setContextDropdownOpen] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const {
    messages,
    isLoading,
    status,
    statusError,
    contextType,
    setContextType,
    entityId,
    setEntityId,
    sendMessage,
    clearMessages,
    refreshStatus,
  } = useCopilot({
    initialContextType: defaultContextType,
    initialEntityId: defaultEntityId,
  });

  // Sync incoming props when drawer opens
  useEffect(() => {
    if (isOpen) {
      if (defaultContextType) setContextType(defaultContextType);
      if (defaultEntityId !== undefined) setEntityId(defaultEntityId);
    }
  }, [isOpen, defaultContextType, defaultEntityId, setContextType, setEntityId]);

  // Focus textarea when drawer opens
  useEffect(() => {
    if (isOpen) {
      const timer = setTimeout(() => textareaRef.current?.focus(), 150);
      return () => clearTimeout(timer);
    }
  }, [isOpen]);

  // Scroll to bottom when messages update
  useEffect(() => {
    if (isOpen) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isLoading, isOpen]);

  // ESC key closes drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        if (contextDropdownOpen) {
          setContextDropdownOpen(false);
        } else {
          onClose();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, contextDropdownOpen, onClose]);

  // Click outside context dropdown to close
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setContextDropdownOpen(false);
      }
    };
    if (contextDropdownOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [contextDropdownOpen]);

  const handleSend = async () => {
    const text = inputText.trim();
    if (!text || isLoading) return;
    setInputText('');
    await sendMessage(text);
  };

  const handleKeyDownTextarea = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const roleMeta = currentUser ? ROLE_METADATA[currentUser.role] : null;
  const suggestions = currentUser ? ROLE_PROMPT_SUGGESTIONS[currentUser.role] || [] : [];
  const currentContextMeta = CONTEXT_LABELS[contextType] || CONTEXT_LABELS.general_soc;
  const ContextIcon = currentContextMeta.icon;

  if (!isOpen) return null;

  return (
    <>
      {/* Backdrop overlay on small screens */}
      <div
        className="fixed inset-0 bg-slate-900/60 backdrop-blur-xs z-50 sm:bg-slate-900/40 transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Container */}
      <aside
        className="fixed inset-y-0 right-0 z-50 w-full sm:w-[500px] md:w-[560px] max-w-full bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-800 shadow-2xl flex flex-col font-sans transition-all duration-300 ease-in-out"
        role="dialog"
        aria-modal="true"
        aria-label="AI Security Copilot Chat Drawer"
      >
        {/* Top Header */}
        <div className="px-4 py-3 bg-slate-50 dark:bg-slate-950/80 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-3 select-none">
          <div className="flex items-center gap-2.5 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-cyan-50 dark:bg-cyan-950 border border-cyan-200 dark:border-cyan-800/80 flex items-center justify-center text-cyan-600 dark:text-cyan-400 shrink-0">
              <Bot className="w-4 h-4" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-heading font-bold text-sm tracking-wide text-slate-900 dark:text-slate-100 truncate">
                  AI SECURITY COPILOT
                </span>
                <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-100 dark:bg-cyan-950 text-cyan-800 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-800">
                  GEMINI 3.8 FLASH
                </span>
              </div>
              <div className="flex items-center gap-2 text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                <span>Advisory System</span>
                <span>•</span>
                <span className="text-cyan-700 dark:text-cyan-400 font-semibold">{roleMeta?.label || 'Operator'}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-1 shrink-0">
            {messages.length > 0 && (
              <button
                type="button"
                onClick={clearMessages}
                className="p-1.5 rounded-md text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 transition cursor-pointer"
                title="Clear conversation history"
                aria-label="Clear chat history"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            )}
            <button
              type="button"
              onClick={refreshStatus}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 transition cursor-pointer"
              title="Refresh service status"
              aria-label="Refresh Copilot status"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={onClose}
              className="p-1.5 rounded-md text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 transition cursor-pointer"
              title="Close Copilot drawer (Esc)"
              aria-label="Close Copilot drawer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Operational Context Bar */}
        <div className="px-4 py-2 bg-slate-100/70 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-slate-500 dark:text-slate-400 shrink-0">Threat Context:</span>
            <div className="relative" ref={dropdownRef}>
              <button
                type="button"
                onClick={() => setContextDropdownOpen(!contextDropdownOpen)}
                className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 text-slate-800 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-700/80 cursor-pointer transition text-[11px]"
              >
                <ContextIcon className="w-3 h-3 text-cyan-600 dark:text-cyan-400" />
                <span className="font-semibold">{currentContextMeta.label}</span>
                {entityId && (
                  <span className="px-1 py-0.2 rounded bg-cyan-100 dark:bg-cyan-900/50 text-cyan-800 dark:text-cyan-300 text-[10px]">
                    {entityId}
                  </span>
                )}
                <ChevronDown className="w-3 h-3 text-slate-400" />
              </button>

              {/* Context Picker Dropdown */}
              {contextDropdownOpen && (
                <div className="absolute left-0 mt-1 w-56 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg shadow-xl py-1 z-30 font-sans text-xs">
                  <div className="px-3 py-1 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                    Select Context Scope
                  </div>
                  {(Object.keys(CONTEXT_LABELS) as CopilotContextType[]).map((type) => {
                    const item = CONTEXT_LABELS[type];
                    const Icon = item.icon;
                    const isSelected = type === contextType;
                    return (
                      <button
                        key={type}
                        type="button"
                        onClick={() => {
                          setContextType(type);
                          setContextDropdownOpen(false);
                        }}
                        className={`w-full px-3 py-1.5 text-left flex items-center gap-2 cursor-pointer transition ${
                          isSelected
                            ? 'bg-cyan-50 dark:bg-cyan-950/60 text-cyan-700 dark:text-cyan-300 font-medium'
                            : 'text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800'
                        }`}
                      >
                        <Icon className="w-3.5 h-3.5 text-slate-400" />
                        <span>{item.label}</span>
                      </button>
                    );
                  })}
                  {entityId && (
                    <div className="border-t border-slate-200 dark:border-slate-800 mt-1 pt-1 px-3 py-1">
                      <button
                        type="button"
                        onClick={() => {
                          setEntityId(undefined);
                          setContextDropdownOpen(false);
                        }}
                        className="text-[11px] text-red-600 dark:text-red-400 hover:underline cursor-pointer"
                      >
                        Clear Active Entity ({entityId})
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Operational Status Dot */}
          <div className="flex items-center gap-1.5 shrink-0">
            <span
              className={`w-2 h-2 rounded-full ${
                statusError ? 'bg-amber-500' : status?.status === 'online' ? 'bg-emerald-500' : 'bg-slate-400'
              }`}
            />
            <span className="text-[10px] text-slate-500 dark:text-slate-400">
              {statusError ? 'Limited' : status?.status === 'online' ? 'Online' : 'Checking'}
            </span>
          </div>
        </div>

        {/* Global Status Warning if offline/unconfigured */}
        {statusError && (
          <div className="px-4 py-2 bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-900/60 flex items-start gap-2 text-xs text-amber-800 dark:text-amber-300">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
            <div className="leading-snug">
              <span className="font-semibold block font-mono text-[11px]">Notice: {statusError.code}</span>
              <p className="text-[11px] text-amber-700 dark:text-amber-400">{statusError.message}</p>
            </div>
          </div>
        )}

        {/* Conversation Stream */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {/* Empty State */}
          {messages.length === 0 && (
            <div className="h-full flex flex-col justify-between py-2">
              <div className="space-y-4">
                <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2.5">
                  <div className="flex items-center gap-2 text-cyan-700 dark:text-cyan-400 font-heading font-semibold text-sm">
                    <Sparkles className="w-4 h-4" />
                    <span>CyberOps Threat Advisory Assistant</span>
                  </div>
                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
                    Welcome to the AI Security Copilot. Grounded in Google Gemini 3.8 Flash, this assistant provides
                    real-time analytical guidance tailored to your authoritative clearance as a{' '}
                    <strong className="text-slate-800 dark:text-slate-200">{roleMeta?.label}</strong>.
                  </p>
                  <div className="p-2.5 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/50 flex items-start gap-2 text-[11px] text-amber-800 dark:text-amber-300 font-mono">
                    <Info className="w-4 h-4 shrink-0 mt-0.5 text-amber-600 dark:text-amber-400" />
                    <span>
                      AI Copilot is strictly read-only advisory. All containment actions (host isolation, account lock)
                      require human operator confirmation.
                    </span>
                  </div>
                </div>

                {/* Role Prompt Suggestions */}
                <div className="space-y-2">
                  <span className="text-xs font-mono font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Suggested Analysis Inquiries
                  </span>
                  <div className="space-y-2">
                    {suggestions.map((s, idx) => (
                      <button
                        key={idx}
                        type="button"
                        onClick={() => {
                          setContextType(s.contextType);
                          sendMessage(s.prompt, { contextType: s.contextType, entityId });
                        }}
                        className="w-full text-left p-3 rounded-lg bg-white dark:bg-slate-800/80 hover:bg-slate-50 dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700/60 shadow-xs hover:border-cyan-400 dark:hover:border-cyan-500 transition cursor-pointer group"
                      >
                        <div className="flex items-center justify-between text-xs font-medium text-slate-800 dark:text-slate-200 group-hover:text-cyan-600 dark:group-hover:text-cyan-400">
                          <span>{s.title}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-400">
                            {CONTEXT_LABELS[s.contextType]?.label || s.contextType}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 line-clamp-1 mt-1">
                          "{s.prompt}"
                        </p>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="text-center text-[10px] text-slate-400 dark:text-slate-500 font-mono pt-4">
                Strict delimiter enclosure and prompt sanitization enforced server-side.
              </div>
            </div>
          )}

          {/* Conversation Messages */}
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex flex-col ${msg.sender === 'user' ? 'items-end' : 'items-start'} space-y-1`}
            >
              <div
                className={`max-w-[92%] rounded-xl px-4 py-3 text-xs leading-relaxed shadow-xs ${
                  msg.sender === 'user'
                    ? 'bg-blue-600 text-white rounded-br-xs dark:bg-cyan-600'
                    : 'bg-slate-100 dark:bg-slate-800/90 text-slate-800 dark:text-slate-100 rounded-bl-xs border border-slate-200 dark:border-slate-700/60'
                }`}
              >
                {/* Header for assistant message */}
                {msg.sender === 'assistant' && (
                  <div className="mb-2 pb-2 border-b border-slate-200 dark:border-slate-700/60 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-amber-100 dark:bg-amber-950/60 text-amber-900 dark:text-amber-300 border border-amber-300 dark:border-amber-800 text-[10px] font-mono font-bold tracking-wider">
                        <AlertTriangle className="w-3 h-3 text-amber-600 dark:text-amber-400" />
                        <span>AI ADVISORY — VERIFY BEFORE ACTION</span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>

                    {msg.contextType && (
                      <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-500 dark:text-slate-400">
                        <span className="px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300">
                          {CONTEXT_LABELS[msg.contextType]?.label || msg.contextType}
                        </span>
                        {msg.entityId && (
                          <span className="text-cyan-600 dark:text-cyan-400 font-semibold">
                            ID: {msg.entityId}
                          </span>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Message Body or Error */}
                {msg.error ? (
                  <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900/60 text-red-900 dark:text-red-300 space-y-1.5 font-sans">
                    <div className="flex items-center gap-1.5 font-mono font-bold text-xs text-red-700 dark:text-red-400">
                      <AlertCircle className="w-4 h-4 shrink-0" />
                      <span>Request Error: {msg.error.code} (HTTP {msg.error.status})</span>
                    </div>
                    <p className="text-[11px] leading-normal">{msg.error.message}</p>
                    {msg.error.retryAfterSeconds && (
                      <p className="text-[10px] font-mono text-amber-700 dark:text-amber-400">
                        Retry After: {msg.error.retryAfterSeconds} seconds
                      </p>
                    )}
                    {msg.error.code === 'DEMO_MODE_AUTHENTICATION_UNAVAILABLE' ? (
                      <div className="mt-2 pt-2 border-t border-red-200 dark:border-red-900/40 text-[10px] text-slate-600 dark:text-slate-400 font-mono">
                        Security Notice: Server cannot authenticate client localStorage demo personas. Connect live Supabase credentials to activate Gemini advisory.
                      </div>
                    ) : (
                      <div className="pt-1.5 flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => {
                            const msgIndex = messages.findIndex((m) => m.id === msg.id);
                            const userMsg = msgIndex > 0 ? messages[msgIndex - 1] : null;
                            if (userMsg && userMsg.text) {
                              sendMessage(userMsg.text, {
                                contextType: msg.contextType || contextType,
                                entityId: msg.entityId || entityId,
                              });
                            }
                          }}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded-md bg-red-100 hover:bg-red-200 dark:bg-red-900/50 dark:hover:bg-red-900/80 text-red-800 dark:text-red-200 border border-red-300 dark:border-red-800/60 transition cursor-pointer"
                        >
                          <RefreshCw className="w-3 h-3" />
                          <span>Retry Query</span>
                        </button>
                      </div>
                    )}
                  </div>
                ) : msg.text && msg.text.trim().length > 0 ? (
                  <div className="space-y-2 whitespace-pre-wrap break-words font-sans">
                    {msg.text}
                  </div>
                ) : (
                  <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900/60 text-amber-900 dark:text-amber-300 space-y-1.5 font-sans">
                    <div className="flex items-center gap-1.5 font-mono font-bold text-xs text-amber-700 dark:text-amber-400">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>Advisory Unavailable</span>
                    </div>
                    <p className="text-[11px] leading-normal">
                      No advisory text was returned for this query. Please retry your request.
                    </p>
                    <div className="pt-1 flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          const msgIndex = messages.findIndex((m) => m.id === msg.id);
                          const userMsg = msgIndex > 0 ? messages[msgIndex - 1] : null;
                          if (userMsg && userMsg.text) {
                            sendMessage(userMsg.text, {
                              contextType: msg.contextType || contextType,
                              entityId: msg.entityId || entityId,
                            });
                          }
                        }}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded-md bg-amber-100 hover:bg-amber-200 dark:bg-amber-900/50 dark:hover:bg-amber-900/80 text-amber-900 dark:text-amber-200 border border-amber-300 dark:border-amber-800/60 transition cursor-pointer"
                      >
                        <RefreshCw className="w-3 h-3" />
                        <span>Retry Query</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Disclaimer footer for assistant turn */}
                {msg.disclaimer && (
                  <div className="mt-3 pt-2 border-t border-slate-200 dark:border-slate-700/60 text-[10px] font-mono text-slate-500 dark:text-slate-400 leading-tight">
                    {msg.disclaimer}
                  </div>
                )}
              </div>

              {/* Timestamp for user turn */}
              {msg.sender === 'user' && (
                <span className="text-[10px] font-mono text-slate-400 px-1">
                  {new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                </span>
              )}
            </div>
          ))}

          {/* Loading Indicator */}
          {isLoading && (
            <div className="flex items-start space-y-1">
              <div className="rounded-xl px-4 py-3 bg-slate-100 dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700/60 text-xs text-slate-600 dark:text-slate-300 space-y-2 shadow-xs">
                <div className="flex items-center gap-2 text-cyan-600 dark:text-cyan-400 font-mono text-[11px] font-semibold">
                  <div className="w-2 h-2 rounded-full bg-cyan-500 animate-ping" />
                  <span>Synthesizing Gemini 3.8 Flash Advisory...</span>
                </div>
                <div className="flex items-center gap-1.5 text-[10px] text-slate-400 font-mono">
                  <span>Assembling role-scoped evidence boundary</span>
                  <span className="animate-pulse">...</span>
                </div>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {/* Input & Advisory Controls Area */}
        <div className="p-4 bg-slate-50 dark:bg-slate-950 border-t border-slate-200 dark:border-slate-800 space-y-2 select-none">
          <div className="relative">
            <textarea
              ref={textareaRef}
              value={inputText}
              onChange={(e) => setInputText(e.target.value.slice(0, 2000))}
              onKeyDown={handleKeyDownTextarea}
              disabled={isLoading}
              rows={2}
              placeholder={`Ask Copilot about ${currentContextMeta.label.toLowerCase()}... (Shift+Enter for newline)`}
              className="w-full px-3 py-2 pr-12 text-xs rounded-lg bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-hidden focus:ring-2 focus:ring-cyan-500 dark:focus:ring-cyan-400 resize-none transition disabled:opacity-50"
            />
            <div className="absolute right-2 bottom-2.5 flex items-center gap-1">
              <button
                type="button"
                onClick={handleSend}
                disabled={isLoading || inputText.trim().length === 0}
                aria-label="Send message to Copilot"
                className="p-1.5 rounded-md bg-blue-600 hover:bg-blue-700 dark:bg-cyan-600 dark:hover:bg-cyan-500 text-white disabled:opacity-40 disabled:hover:bg-blue-600 dark:disabled:hover:bg-cyan-600 transition cursor-pointer"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-1 truncate max-w-[70%]">
              <Shield className="w-3 h-3 text-cyan-600 dark:text-cyan-400 shrink-0" />
              <span className="truncate">Human verification required for all incident actions</span>
            </div>
            <span className={inputText.length > 1800 ? 'text-amber-500 font-bold' : ''}>
              {inputText.length} / 2000
            </span>
          </div>
        </div>
      </aside>
    </>
  );
};
