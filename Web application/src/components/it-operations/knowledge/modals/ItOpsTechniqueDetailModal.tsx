import React from 'react';
import { X, ShieldCheck, Server, Layers, ShieldAlert, ExternalLink, Filter } from 'lucide-react';
import { AggregatedItOpsTechnique } from '../types';

interface ItOpsTechniqueDetailModalProps {
  technique: AggregatedItOpsTechnique | null;
  isOpen: boolean;
  onClose: () => void;
  onFilterByPlatform?: (platform: string) => void;
  onFilterByTactic?: (tactic: string) => void;
  onSelectMitigation?: (mitigationId: string) => void;
}

export const ItOpsTechniqueDetailModal: React.FC<ItOpsTechniqueDetailModalProps> = ({
  technique,
  isOpen,
  onClose,
  onFilterByPlatform,
  onFilterByTactic,
  onSelectMitigation,
}) => {
  if (!isOpen || !technique) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-xs animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-labelledby="technique-detail-title"
    >
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-900/90">
          <div className="space-y-1">
            <div className="flex items-center gap-2.5">
              <span className="px-2.5 py-1 text-xs font-mono font-bold rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                {technique.id}
              </span>
              <h2 id="technique-detail-title" className="text-base font-bold text-slate-100 font-heading">
                {technique.name}
              </h2>
            </div>
            <p className="text-xs text-slate-400">
              MITRE ATT&CK Enterprise Technique Reference Mapping
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-xs text-slate-300">
          {/* Target Platforms */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              Target Computing Platforms ({technique.platforms.length})
            </h3>
            {technique.platforms.length === 0 ? (
              <p className="text-slate-500 italic">No specific platforms recorded.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {technique.platforms.map((p) => (
                  <span
                    key={p}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 text-slate-200 border border-slate-700 text-xs font-mono"
                  >
                    {p}
                    {onFilterByPlatform && (
                      <button
                        type="button"
                        onClick={() => {
                          onFilterByPlatform(p);
                          onClose();
                        }}
                        className="text-cyan-400 hover:text-cyan-300 ml-1"
                        title={`Filter workspace by platform ${p}`}
                      >
                        <Filter className="w-3 h-3" />
                      </button>
                    )}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Enterprise Tactics */}
          <div className="space-y-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-indigo-400" />
              Covered Attack Tactics ({technique.tactics.length})
            </h3>
            {technique.tactics.length === 0 ? (
              <p className="text-slate-500 italic">Unclassified tactic</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {technique.tactics.map((t) => (
                  <span
                    key={t}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-indigo-950/60 text-indigo-300 border border-indigo-800 text-xs"
                  >
                    {t}
                    {onFilterByTactic && (
                      <button
                        type="button"
                        onClick={() => {
                          onFilterByTactic(t);
                          onClose();
                        }}
                        className="text-indigo-400 hover:text-indigo-300 ml-1"
                        title={`Filter workspace by tactic ${t}`}
                      >
                        <Filter className="w-3 h-3" />
                      </button>
                    )}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Cataloged Preventative Mitigations */}
          <div className="space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              Associated Mitigations ({technique.mitigations.length})
            </h3>
            {technique.mitigations.length === 0 ? (
              <div className="p-3 bg-slate-950/50 rounded-lg border border-slate-800 text-slate-500 italic">
                No preventative mitigations currently cataloged for this technique in public.it_operations_knowledge.
              </div>
            ) : (
              <div className="space-y-2.5">
                {technique.mitigations.map((m) => (
                  <div
                    key={m.id}
                    className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg space-y-1.5"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                          {m.id}
                        </span>
                        <span className="font-semibold text-slate-200">{m.name}</span>
                      </div>
                      {onSelectMitigation && (
                        <button
                          type="button"
                          onClick={() => {
                            onSelectMitigation(m.id);
                            onClose();
                          }}
                          className="text-emerald-400 hover:text-emerald-300 flex items-center gap-1 text-[11px]"
                        >
                          View Mitigation <ExternalLink className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">
                      {m.description}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex justify-end">
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
          >
            Close Detail
          </button>
        </div>
      </div>
    </div>
  );
};
