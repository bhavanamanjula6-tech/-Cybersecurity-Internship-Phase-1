import React, { useState, useEffect } from 'react';
import { Cpu, Layers, ShieldAlert, Activity, ArrowRight, CheckCircle2, Clock } from 'lucide-react';

export interface ServiceCardData {
  id: string;
  title: string;
  category: string;
  status: 'implemented' | 'prototype';
  statusLabel: string;
  icon: React.ElementType;
  description: string;
  bulletPoints: string[];
  operationalNotice?: string;
}

export const SERVICE_CARDS: ServiceCardData[] = [
  {
    id: 'triage',
    title: 'Deterministic Alert Triage',
    category: 'RULES ENGINE',
    status: 'implemented',
    statusLabel: 'Implemented In-Memory Engine',
    icon: Cpu,
    description:
      'Evaluates security telemetry using explainable rule logic with explicit confidence scores, avoiding unpredictable black-box AI inferences.',
    bulletPoints: [
      'LSASS memory access detection (Rule DET-001, 94% conf)',
      'Obfuscated PowerShell cradles (Rule DET-002, 88% conf)',
      'Malicious macro process trees (Rule DET-003, 85% conf)',
    ],
  },
  {
    id: 'mitre',
    title: 'MITRE ATT&CK Alignment',
    category: 'THREAT KNOWLEDGE',
    status: 'implemented',
    statusLabel: 'Implemented Enterprise v14.1 Mapping',
    icon: Layers,
    description:
      'Curated matrix navigation mapping synthetic alerts to authentic adversary tactics, detection analytics, and structured mitigation defenses.',
    bulletPoints: [
      'Credential Access (T1003.001) & Execution (T1059.001)',
      'Phishing Spearphishing Attachment (T1566.001)',
      'Detection rule coverage gap analysis across matrix',
    ],
  },
  {
    id: 'containment',
    title: 'Proposed Containment Actions',
    category: 'INCIDENT RESPONSE',
    status: 'prototype',
    statusLabel: 'Simulated Prototype (Zero Live Network Impact)',
    icon: ShieldAlert,
    description:
      'Simulates host isolation workflows, process termination approvals, and operator justification requirements within an in-memory containment sandbox.',
    bulletPoints: [
      'Mandatory operator justification & peer authorization',
      'Simulated host isolation & token revocation proposals',
      'Audit log recorded (no real external network disruption)',
    ],
    operationalNotice: 'Prototype only: containment proposals do not execute live firewall or network commands.',
  },
  {
    id: 'telemetry',
    title: 'Network Telemetry & Audit',
    category: 'FLOW TELEMETRY',
    status: 'implemented',
    statusLabel: 'Implemented Synthetic Flow Parser',
    icon: Activity,
    description:
      'Inspects synthetic network flows modeled on the CIC-IDS2017 schema, analyzing socket pairs, packet volume anomalies, and TCP flag patterns.',
    bulletPoints: [
      'Synthetic socket pair mapping (IP, Port, Protocol)',
      'Forward/backward packet inter-arrival distributions',
      'Tamper-evident in-memory operational audit trail',
    ],
  },
];

interface CyberServiceCardsProps {
  onCardFocusChange?: (cardId: string) => void;
  onExploreAction?: (cardId: string) => void;
}

export const CyberServiceCards: React.FC<CyberServiceCardsProps> = ({
  onCardFocusChange,
  onExploreAction,
}) => {
  // Persistent selected card state - defaults to first card (0)
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  // Hovered card index - for independent preview emphasis without losing persistent selection
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [prefersReducedMotion, setPrefersReducedMotion] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
    setPrefersReducedMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setPrefersReducedMotion(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);

  // Card selection handler: updates persistent state and informs parent
  const handleSelectCard = (index: number) => {
    setSelectedIndex(index);
    onCardFocusChange?.(SERVICE_CARDS[index].id);
  };

  // Keyboard navigation for accessible card interaction
  const handleKeyDown = (e: React.KeyboardEvent, index: number) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleSelectCard(index);
    } else if (e.key === 'ArrowRight') {
      e.preventDefault();
      const nextIndex = (index + 1) % SERVICE_CARDS.length;
      handleSelectCard(nextIndex);
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault();
      const prevIndex = (index - 1 + SERVICE_CARDS.length) % SERVICE_CARDS.length;
      handleSelectCard(prevIndex);
    }
  };

  // Fluid CSS custom property tilt tracking without triggering React component re-renders
  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (prefersReducedMotion) return;
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5; // -0.5 to 0.5
    const y = (e.clientY - rect.top) / rect.height - 0.5; // -0.5 to 0.5
    e.currentTarget.style.setProperty('--tilt-x', `${(-y * 8).toFixed(2)}deg`);
    e.currentTarget.style.setProperty('--tilt-y', `${(x * 8).toFixed(2)}deg`);
  };

  const handleMouseEnter = (index: number, e: React.MouseEvent<HTMLDivElement>) => {
    setHoveredIndex(index);
    if (!prefersReducedMotion) {
      e.currentTarget.style.setProperty('--tilt-x', '0deg');
      e.currentTarget.style.setProperty('--tilt-y', '0deg');
    }
  };

  const handleCardMouseLeave = (e: React.MouseEvent<HTMLDivElement>) => {
    setHoveredIndex(null);
    if (!prefersReducedMotion) {
      e.currentTarget.style.setProperty('--tilt-x', '0deg');
      e.currentTarget.style.setProperty('--tilt-y', '0deg');
    }
  };

  // Receding arrangement angles for resting 4-card perspective row (subtle angles)
  const baseRotates = [4, 1.5, -1.5, -4];

  return (
    <div className="w-full space-y-6">
      {/* Header Context with Anti-Slop Typography */}
      <div className="flex flex-col sm:flex-row items-start sm:items-end justify-between gap-4">
        <div>
          <span className="text-xs font-mono uppercase text-purple-600 dark:text-purple-400 font-bold tracking-wider">
            OPERATIONAL ARCHITECTURE
          </span>
          <h3 className="text-2xl sm:text-3xl font-bold font-heading text-slate-900 dark:text-white mt-1">
            Perspective-Grounded SOC Capabilities
          </h3>
          <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400 mt-1 max-w-2xl">
            Click any card body or use the numbered controls below to bring a capability forward into focus. All cards distinguish implemented in-memory engines from simulated prototypes.
          </p>
        </div>

        {/* Circular Number Selector Controls (1, 2, 3, 4) - Synchronized with card focus */}
        <div
          className="flex items-center gap-2 self-end sm:self-auto bg-slate-200/60 dark:bg-slate-900/50 p-1.5 rounded-full border border-slate-300/80 dark:border-slate-800"
          role="tablist"
          aria-label="Service capability selector"
        >
          {SERVICE_CARDS.map((card, idx) => {
            const isControlActive = selectedIndex === idx;
            return (
              <button
                key={card.id}
                type="button"
                role="tab"
                id={`tab-control-${card.id}`}
                aria-selected={isControlActive}
                aria-controls={`capability-card-${card.id}`}
                onClick={(e) => {
                  e.stopPropagation();
                  handleSelectCard(idx);
                }}
                className={`w-9 h-9 rounded-full flex items-center justify-center transition-all duration-300 cursor-pointer border ${
                  isControlActive
                    ? 'border-purple-600 bg-purple-100/90 dark:border-purple-500 dark:bg-purple-950/70 text-purple-800 dark:text-purple-300 shadow-[0_0_15px_rgba(124,58,237,0.35)] dark:shadow-[0_0_15px_rgba(168,85,247,0.4)] scale-110 font-bold'
                    : 'border-slate-300 dark:border-slate-700/80 bg-white dark:bg-slate-900/60 text-slate-600 dark:text-slate-400 hover:border-purple-400 hover:text-purple-700 hover:scale-105'
                }`}
                title={`Select card ${idx + 1}: ${card.title}`}
                aria-label={`Select card ${idx + 1}: ${card.title}`}
              >
                <span className="text-xs font-mono font-bold">{idx + 1}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* 3D Perspective Grid Row */}
      <div
        className="perspective-1200 py-4 px-1"
        onMouseLeave={() => setHoveredIndex(null)}
      >
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
          {SERVICE_CARDS.map((card, index) => {
            const Icon = card.icon;
            const isSelected = selectedIndex === index;
            const isHovered = hoveredIndex === index;

            // Perspective transform calculation - guarantees translateZ >= 0 for flawless browser hit testing
            let rotateY = 0;
            let translateY = 0;
            let translateZ = 0;
            let scale = 1;

            if (prefersReducedMotion) {
              scale = isSelected ? 1.02 : isHovered ? 1.01 : 1;
            } else {
              if (isSelected) {
                // Persistent selected card moves forward, facing front
                translateY = -8;
                translateZ = 28;
                scale = 1.035;
                rotateY = 0;
              } else if (isHovered) {
                // Hovered unselected card lifts gently forward without displacing persistent selected card
                translateY = -6;
                translateZ = 16;
                scale = 1.02;
                rotateY = baseRotates[index] * 0.25;
              } else {
                // Resting receding arrangement: angled inward towards center
                translateY = 0;
                translateZ = 0;
                scale = 0.99;
                rotateY = baseRotates[index];
              }
            }

            return (
              <div
                key={card.id}
                id={`capability-card-${card.id}`}
                role="button"
                tabIndex={0}
                aria-pressed={isSelected}
                aria-label={`Capability ${index + 1}: ${card.title}. Click to select.`}
                onClick={() => handleSelectCard(index)}
                onMouseEnter={(e) => handleMouseEnter(index, e)}
                onMouseMove={handleMouseMove}
                onMouseLeave={handleCardMouseLeave}
                onKeyDown={(e) => handleKeyDown(e, index)}
                style={{
                  transform: `perspective(1000px) translateY(${translateY}px) translateZ(${translateZ}px) rotateY(${rotateY}deg) rotateX(var(--tilt-x, 0deg)) rotateY(var(--tilt-y, 0deg)) scale(${scale})`,
                  transition: 'transform 0.2s cubic-bezier(0.2, 0.8, 0.2, 1), box-shadow 0.3s ease, border-color 0.3s ease, background-color 0.3s ease',
                  willChange: 'transform',
                }}
                className={`relative rounded-2xl p-6 cursor-pointer flex flex-col justify-between select-none group transition-all duration-300 pointer-events-auto ${
                  isSelected
                    ? 'bg-white dark:bg-[#0c1026] border-2 border-purple-600 dark:border-purple-500 shadow-[0_16px_36px_-6px_rgba(109,40,217,0.25),0_6px_16px_rgba(15,23,42,0.06)] dark:shadow-[0_0_35px_rgba(168,85,247,0.35)] z-20'
                    : isHovered
                    ? 'bg-white dark:bg-slate-900/90 border-2 border-purple-400/90 dark:border-purple-400/70 shadow-[0_12px_28px_-4px_rgba(109,40,217,0.18),0_4px_12px_rgba(15,23,42,0.05)] dark:shadow-[0_0_25px_rgba(168,85,247,0.25)] z-20'
                    : 'bg-[#F8FAFD] dark:bg-slate-900/70 border border-slate-200/90 dark:border-slate-800/80 shadow-xs opacity-95 dark:opacity-90 z-10'
                }`}
              >
                {/* Ambient Top Glow on Selected Card */}
                {isSelected && (
                  <div className="absolute inset-x-0 -top-px h-1 bg-gradient-to-r from-transparent via-purple-600 to-transparent rounded-t-2xl pointer-events-none" />
                )}

                <div className="space-y-4">
                  {/* Top Bar: Category & Status Indicator */}
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono tracking-widest text-purple-700 dark:text-purple-400 font-bold uppercase">
                      {card.category}
                    </span>

                    <span
                      className={`inline-flex items-center gap-1 text-[10px] font-mono font-medium ${
                        card.status === 'implemented'
                          ? 'text-emerald-700 dark:text-emerald-400'
                          : 'text-amber-700 dark:text-amber-400'
                      }`}
                    >
                      {card.status === 'implemented' ? (
                        <CheckCircle2 className="w-3 h-3" />
                      ) : (
                        <Clock className="w-3 h-3" />
                      )}
                      <span>{card.status === 'implemented' ? 'Implemented' : 'Simulated'}</span>
                    </span>
                  </div>

                  {/* Icon with Dynamic Neon Illumination */}
                  <div
                    className={`w-12 h-12 rounded-xl flex items-center justify-center transition-all duration-300 ${
                      isSelected
                        ? 'bg-gradient-to-br from-purple-500/15 to-indigo-500/20 text-purple-700 dark:text-fuchsia-300 border border-purple-400/70 dark:border-purple-400/60 shadow-[0_0_18px_rgba(124,58,237,0.3)] dark:shadow-[0_0_18px_rgba(168,85,247,0.45)]'
                        : isHovered
                        ? 'bg-purple-50 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300 border border-purple-300/80 dark:border-purple-500/60 shadow-[0_0_14px_rgba(124,58,237,0.2)] dark:shadow-[0_0_14px_rgba(168,85,247,0.3)]'
                        : 'bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-400 border border-slate-200/90 dark:border-slate-700/60'
                    }`}
                  >
                    <Icon className="w-6 h-6 transition-transform duration-300 group-hover:scale-110" />
                  </div>

                  {/* Title & Prose Description */}
                  <div>
                    <h4 className="text-base font-bold font-heading text-slate-900 dark:text-white">
                      {card.title}
                    </h4>
                    <p className="text-xs text-slate-600 dark:text-slate-300 mt-2 leading-relaxed">
                      {card.description}
                    </p>
                  </div>

                  {/* Key Implementation Points */}
                  <ul className="space-y-1.5 pt-1 text-[11px] text-slate-600 dark:text-slate-400 font-mono">
                    {card.bulletPoints.map((point, i) => (
                      <li key={i} className="flex items-start gap-1.5">
                        <span className="text-purple-600 dark:text-purple-400 font-bold mt-0.5">&bull;</span>
                        <span className="leading-tight">{point}</span>
                      </li>
                    ))}
                  </ul>

                  {/* Notice for Simulated Prototype */}
                  {card.operationalNotice && (
                    <div className="p-2.5 rounded-lg bg-amber-50/80 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/60 text-[10px] text-amber-900 dark:text-amber-300/90 leading-tight">
                      <strong>Note:</strong> {card.operationalNotice}
                    </div>
                  )}
                </div>

                {/* Footer Selection / Action Bar */}
                <div className="pt-4 mt-4 border-t border-slate-200/80 dark:border-slate-800/60 flex items-center justify-between text-xs font-mono">
                  {isSelected ? (
                    <div className="flex items-center justify-between w-full gap-2">
                      <span className="text-purple-700 dark:text-purple-400 font-bold text-[11px] flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-600 dark:bg-purple-500 animate-pulse" />
                        Card {index + 1} Selected
                      </span>
                      {onExploreAction && (
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            onExploreAction(card.id);
                          }}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-[11px] font-semibold font-sans shadow-[0_2px_10px_rgba(124,58,237,0.3)] hover:shadow-[0_4px_16px_rgba(124,58,237,0.45)] transition-all cursor-pointer focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-purple-400"
                          aria-label={`Explore details for ${card.title}`}
                        >
                          <span>Explore Details</span>
                          <ArrowRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  ) : (
                    <div className="flex items-center justify-between w-full">
                      <span className={`text-[11px] transition-colors ${
                        isHovered ? 'text-purple-700 dark:text-purple-300 font-semibold' : 'text-slate-500 dark:text-slate-400'
                      }`}>
                        {isHovered ? 'Click to bring forward' : 'Click card to select'}
                      </span>
                      <div className={`w-6 h-6 rounded-full flex items-center justify-center transition-all ${
                        isHovered
                          ? 'bg-purple-100 text-purple-700 dark:bg-purple-950/80 dark:text-purple-300 shadow-[0_0_8px_rgba(124,58,237,0.25)]'
                          : 'bg-slate-200/70 dark:bg-slate-800 text-slate-500 dark:text-slate-400'
                      }`}>
                        <ArrowRight className="w-3 h-3" />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
